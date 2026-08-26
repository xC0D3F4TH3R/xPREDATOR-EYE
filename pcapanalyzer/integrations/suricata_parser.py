"""
suricata_parser.py - Suricata EVE JSON parser for IDS alert integration.

Parses Suricata's EVE.json output for alerts, DNS, HTTP, and TLS events,
mapping them to xPREDATOR-EYE models for unified analysis.
"""

from __future__ import annotations

import json
from datetime import datetime
from pathlib import Path
from typing import Generator, Optional

from ..utils import get_logger

logger = get_logger("suricata_parser")


class SuricataEVEParser:
    """Parse Suricata EVE.json for IDS alerts and protocol events."""

    def __init__(self, eve_path: str | Path) -> None:
        self.eve_path = Path(eve_path)

    def stream_events(self, event_type: Optional[str] = None) -> Generator[dict, None, None]:
        """Memory-efficient streaming parser for large EVE.json files."""
        if not self.eve_path.exists():
            logger.warning("EVE.json not found: %s", self.eve_path)
            return

        try:
            with open(self.eve_path, "r", encoding="utf-8", errors="replace") as f:
                for line in f:
                    line = line.strip()
                    if not line:
                        continue
                    try:
                        event = json.loads(line)
                        if event_type and event.get("event_type") != event_type:
                            continue
                        yield event
                    except json.JSONDecodeError:
                        continue
        except Exception as exc:
            logger.error("Failed to read EVE.json: %s", exc)

    def get_alerts(self, min_severity: int = 1) -> list[dict]:
        """Extract IDS alerts from EVE JSON."""
        alerts = []
        for event in self.stream_events("alert"):
            alert_info = event.get("alert", {})
            if alert_info.get("severity", 3) <= min_severity:
                alerts.append({
                    "timestamp": event.get("timestamp", ""),
                    "src_ip": event.get("src_ip", ""),
                    "src_port": event.get("src_port", 0),
                    "dest_ip": event.get("dest_ip", ""),
                    "dest_port": event.get("dest_port", 0),
                    "proto": event.get("proto", ""),
                    "alert_signature": alert_info.get("signature", ""),
                    "alert_category": alert_info.get("category", ""),
                    "alert_severity": alert_info.get("severity", 3),
                    "alert_gid": alert_info.get("gid", 0),
                    "alert_signature_id": alert_info.get("signature_id", 0),
                    "flow_id": event.get("flow_id", 0),
                })
        logger.info("Extracted %d Suricata alerts", len(alerts))
        return alerts

    def get_dns_events(self) -> list[dict]:
        dns_events = []
        for event in self.stream_events("dns"):
            dns_info = event.get("dns", {})
            dns_events.append({
                "timestamp": event.get("timestamp", ""),
                "src_ip": event.get("src_ip", ""),
                "dest_ip": event.get("dest_ip", ""),
                "query": dns_info.get("rrname", ""),
                "query_type": dns_info.get("type", ""),
                "rcode": dns_info.get("rcode", ""),
                "answers": dns_info.get("answers", []),
            })
        return dns_events

    def get_http_events(self) -> list[dict]:
        http_events = []
        for event in self.stream_events("http"):
            http_info = event.get("http", {})
            http_events.append({
                "timestamp": event.get("timestamp", ""),
                "src_ip": event.get("src_ip", ""),
                "dest_ip": event.get("dest_ip", ""),
                "method": http_info.get("method", ""),
                "host": http_info.get("hostname", ""),
                "uri": http_info.get("url", ""),
                "user_agent": http_info.get("http_user_agent", ""),
                "status": http_info.get("status", 0),
                "content_type": http_info.get("http_content_type", ""),
            })
        return http_events

    def get_tls_events(self) -> list[dict]:
        tls_events = []
        for event in self.stream_events("tls"):
            tls_info = event.get("tls", {})
            tls_events.append({
                "timestamp": event.get("timestamp", ""),
                "src_ip": event.get("src_ip", ""),
                "dest_ip": event.get("dest_ip", ""),
                "sni": tls_info.get("sni", ""),
                "version": tls_info.get("version", ""),
                "subject": tls_info.get("subject", ""),
                "issuer": tls_info.get("issuerdn", ""),
                "ja3": tls_info.get("ja3", {}),
                "ja3s": tls_info.get("ja3s", {}),
            })
        return tls_events

    def to_behavior_events(self) -> list:
        """Convert all Suricata events to BehaviorEvent objects."""
        from ..models import BehaviorEvent
        events = []

        for alert in self.get_alerts():
            ts = None
            try:
                ts = datetime.fromisoformat(alert["timestamp"].replace("Z", "+00:00"))
            except (ValueError, KeyError):
                pass
            events.append(BehaviorEvent(
                timestamp=ts, event_type="ids_alert",
                src_ip=alert["src_ip"], dst_ip=alert["dest_ip"],
                dst_port=alert["dest_port"],
                severity_name=alert["alert_severity"],
                raw_data={"signature": alert["alert_signature"], "category": alert["alert_category"]},
            ))

        for dns in self.get_dns_events():
            ts = None
            try:
                ts = datetime.fromisoformat(dns["timestamp"].replace("Z", "+00:00"))
            except (ValueError, KeyError):
                pass
            events.append(BehaviorEvent(
                timestamp=ts, event_type="dns_query",
                src_ip=dns["src_ip"], dst_ip=dns["dest_ip"],
                target=dns["query"],
            ))

        for http in self.get_http_events():
            ts = None
            try:
                ts = datetime.fromisoformat(http["timestamp"].replace("Z", "+00:00"))
            except (ValueError, KeyError):
                pass
            events.append(BehaviorEvent(
                timestamp=ts, event_type="http_request",
                src_ip=http["src_ip"], dst_ip=http["dest_ip"],
                target=http["host"],
                raw_data={"method": http["method"], "uri": http["uri"], "ua": http["user_agent"]},
            ))

        return events
