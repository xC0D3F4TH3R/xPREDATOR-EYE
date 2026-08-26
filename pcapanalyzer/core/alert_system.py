"""
alert_system.py - Real-time alerting engine with dedup, rate-limiting, escalation.

Receives alerts from all detection engines, deduplicates, correlates into
incident groups, manages escalation, and persists to disk.
"""

from __future__ import annotations

import json
import threading
import time
from collections import defaultdict
from datetime import datetime
from pathlib import Path
from typing import Callable, Optional

from .. import config
from ..models import (
    Alert, AlertGroup, AlertPriority, Severity,
    BehaviorPattern, BehavioralProfile, IntelMatch,
    KillChainPhase, ResponseAction,
)
from ..utils import get_logger, ensure_directory

logger = get_logger("alert_system")


class AlertSystem:
    """Manages alert lifecycle: creation, dedup, correlation, escalation.

    Usage::

        alert_sys = AlertSystem()
        alert_sys.register_callback(my_handler)
        alert_sys.raise_alert(alert)
        groups = alert_sys.correlate()
    """

    def __init__(self, output_dir: Optional[Path] = None) -> None:
        self._alerts: list[Alert] = []
        self._groups: list[AlertGroup] = []
        self._callbacks: list[Callable[[Alert], None]] = []
        self._dedup_cache: dict[str, float] = {}
        self._rate_limiter: list[float] = []
        self._lock = threading.Lock()
        self._alert_log = output_dir / "alerts.jsonl" if output_dir else None
        if self._alert_log:
            ensure_directory(self._alert_log.parent)

    def register_callback(self, callback: Callable[[Alert], None]) -> None:
        """Register a function to be called for every new alert."""
        self._callbacks.append(callback)

    def raise_alert(self, alert: Alert) -> Optional[Alert]:
        """Process and dispatch a new alert.

        Returns the alert if dispatched, or None if suppressed (dedup/rate-limit).
        """
        with self._lock:
            # Rate limiting
            now = time.monotonic()
            self._rate_limiter = [t for t in self._rate_limiter if now - t < 60.0]
            if len(self._rate_limiter) >= config.ALERT_MAX_PER_MINUTE:
                logger.warning("Alert rate limit hit - suppressing alert: %s", alert.title)
                return None
            self._rate_limiter.append(now)

            # Deduplication
            dedup_key = f"{alert.title}:{alert.src_ip}:{alert.dst_ip}"
            if dedup_key in self._dedup_cache:
                elapsed = now - self._dedup_cache[dedup_key]
                if elapsed < config.ALERT_DEDUP_WINDOW:
                    logger.debug("Dedup suppressed: %s (%.1fs since last)", dedup_key, elapsed)
                    return None
            self._dedup_cache[dedup_key] = now

            # Set timestamp if missing
            if alert.timestamp is None:
                alert.timestamp = datetime.now()

            self._alerts.append(alert)

            # Persist to disk
            self._persist_alert(alert)

            # Notify callbacks
            for cb in self._callbacks:
                try:
                    cb(alert)
                except Exception as exc:
                    logger.error("Alert callback error: %s", exc)

            logger.warning(
                "ALERT [%s] %s: %s",
                alert.priority.name, alert.title, alert.description,
            )
            return alert

    def _persist_alert(self, alert: Alert) -> None:
        """Write alert to JSONL log file."""
        if not self._alert_log:
            return
        try:
            record = {
                "alert_id": alert.alert_id,
                "timestamp": alert.timestamp.isoformat() if alert.timestamp else None,
                "priority": alert.priority.name,
                "severity": alert.severity.value,
                "title": alert.title,
                "description": alert.description,
                "source": alert.source,
                "host": alert.host,
                "src_ip": alert.src_ip,
                "dst_ip": alert.dst_ip,
                "process": alert.process_name,
                "mitre_tactic": alert.mitre_tactic.value if alert.mitre_tactic else None,
                "mitre_technique": alert.mitre_technique,
                "iocs": alert.iocs,
            }
            with open(self._alert_log, "a", encoding="utf-8") as fh:
                fh.write(json.dumps(record) + "\n")
        except OSError as exc:
            logger.error("Failed to persist alert: %s", exc)

    def alert_from_pattern(self, pattern: BehaviorPattern, host: str = "") -> Alert:
        """Create an Alert from a detected behavioral pattern."""
        priority_map = {
            Severity.CRITICAL: AlertPriority.CRITICAL,
            Severity.HIGH: AlertPriority.ERROR,
            Severity.MEDIUM: AlertPriority.WARNING,
            Severity.LOW: AlertPriority.NOTICE,
            Severity.INFO: AlertPriority.INFO,
        }
        priority = priority_map.get(pattern.severity, AlertPriority.INFO)

        actions = []
        if pattern.severity.numeric >= Severity.HIGH.numeric:
            actions = [ResponseAction.GENERATE_REPORT, ResponseAction.CAPTURE_FORENSICS]
        if pattern.severity == Severity.CRITICAL:
            actions.append(ResponseAction.NOTIFY_ADMIN)

        return Alert(
            timestamp=pattern.last_seen or datetime.now(),
            priority=priority,
            severity=pattern.severity,
            title=pattern.name,
            description=pattern.description,
            source="behavior_engine",
            category="behavioral_pattern",
            host=host,
            kill_chain_phases=pattern.kill_chain_phases,
            mitre_technique=", ".join(pattern.techniques),
            iocs=[],
            recommended_actions=actions,
        )

    def alert_from_intel_match(self, match: IntelMatch) -> Alert:
        """Create an Alert from an intelligence match."""
        return Alert(
            timestamp=datetime.now(),
            priority=AlertPriority.WARNING if match.ioc.severity.numeric >= Severity.MEDIUM.numeric else AlertPriority.NOTICE,
            severity=match.ioc.severity,
            title=f"Intel Match: {match.ioc.ioc_type.value}",
            description=f"{match.threat_name} - {match.details}",
            source="intelligence",
            category="ioc_match",
            iocs=[match.ioc.value],
            recommended_actions=[ResponseAction.BLOCK_IP, ResponseAction.GENERATE_REPORT],
        )

    def correlate(self) -> list[AlertGroup]:
        """Group related alerts into incident clusters based on shared IOCs,
        IPs, and temporal proximity."""
        groups: list[AlertGroup] = []
        ip_alerts: dict[str, list[Alert]] = defaultdict(list)

        for alert in self._alerts:
            if alert.src_ip:
                ip_alerts[alert.src_ip].append(alert)
            if alert.dst_ip:
                ip_alerts[alert.dst_ip].append(alert)

        seen_alert_ids: set[str] = set()
        for ip, alerts in ip_alerts.items():
            if len(alerts) >= 2:
                unique = [a for a in alerts if a.alert_id not in seen_alert_ids]
                if not unique:
                    continue

                for a in unique:
                    seen_alert_ids.add(a.alert_id)

                severities = [a.severity for a in unique]
                max_sev = max(severities, key=lambda s: s.numeric)
                phases = []
                for a in unique:
                    if a.kill_chain_phases:
                        phases.extend(a.kill_chain_phases)
                phases = list(set(phases))

                group = AlertGroup(
                    name=f"Incident cluster: {ip}",
                    alerts=unique,
                    first_seen=min(a.timestamp for a in unique if a.timestamp),
                    last_seen=max(a.timestamp for a in unique if a.timestamp),
                    severity=max_sev,
                    confidence=min(len(unique) / 5.0, 1.0),
                    kill_chain_phases=phases,
                    affected_hosts=[ip],
                )
                groups.append(group)
                logger.warning(
                    "Alert group formed: %s (%d alerts, severity=%s)",
                    group.name, len(unique), max_sev.value,
                )

        self._groups = groups
        return groups

    def get_alerts(self, min_priority: AlertPriority = AlertPriority.INFO) -> list[Alert]:
        """Return alerts at or above the specified priority level."""
        return [a for a in self._alerts if a.priority.value >= min_priority.value]

    def get_groups(self) -> list[AlertGroup]:
        return list(self._groups)

    @property
    def alert_count(self) -> int:
        return len(self._alerts)

    @property
    def critical_count(self) -> int:
        return sum(1 for a in self._alerts if a.severity == Severity.CRITICAL)

    @property
    def high_count(self) -> int:
        return sum(1 for a in self._alerts if a.severity == Severity.HIGH)
