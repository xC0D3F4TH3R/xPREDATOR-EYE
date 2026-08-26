"""
behavior_engine.py - Behavioral analysis engine.

Correlates events from all monitoring sources (network, process, file)
into behavioral patterns, maps them to MITRE ATT&CK techniques and
Cyber Kill Chain phases, computes behavioral scores, and detects
attack sequences.
"""

from __future__ import annotations

import math
from collections import Counter, defaultdict
from datetime import datetime, timedelta
from typing import Optional

from .. import config
from ..models import (
    BehaviorEvent, BehaviorPattern, BehavioralProfile,
    KillChainPhase, MITRETactic, Severity,
    ProcessSnapshot, FileChange, SystemEvent, LivePacket,
)
from ..utils import get_logger

logger = get_logger("behavior_engine")

MAX_EVENTS = 10000
MAX_WINDOW_EVENTS = 5000

# ═══════════════════════════════════════════════════════════════════════════
# Detection Rules: event-type sequences mapped to TTPs
# ═══════════════════════════════════════════════════════════════════════════

SEQUENCE_RULES: list[dict] = [
    {
        "name": "Suspicious Process + Network Connection",
        "sequence": ["process_start", "network_connect"],
        "severity": Severity.MEDIUM,
        "kill_chain": [KillChainPhase.INSTALLATION, KillChainPhase.COMMAND_AND_CONTROL],
        "mitre": [MITRETactic.EXECUTION, MITRETactic.C2],
        "techniques": ["T1059", "T1071"],
        "description": "New process immediately made network connection",
    },
    {
        "name": "Credential Access + Lateral Movement",
        "sequence": ["credential_access", "network_connect"],
        "severity": Severity.HIGH,
        "kill_chain": [KillChainPhase.EXPLOITATION, KillChainPhase.ACTIONS_ON_OBJECTIVES],
        "mitre": [MITRETactic.CREDENTIAL_ACCESS, MITRETactic.LATERAL_MOVEMENT],
        "techniques": ["T1003", "T1021"],
        "description": "Credential harvesting followed by network connection",
    },
    {
        "name": "File Write + Process Creation",
        "sequence": ["file_created", "process_start"],
        "severity": Severity.MEDIUM,
        "kill_chain": [KillChainPhase.INSTALLATION],
        "mitre": [MITRETactic.PERSISTENCE, MITRETactic.EXECUTION],
        "techniques": ["T1547", "T1059"],
        "description": "New file created then executed as process",
    },
    {
        "name": "DNS Tunneling Pattern",
        "sequence": ["dns_query", "dns_query", "dns_query", "dns_query"],
        "min_count": 4,
        "severity": Severity.HIGH,
        "kill_chain": [KillChainPhase.COMMAND_AND_CONTROL],
        "mitre": [MITRETactic.C2],
        "techniques": ["T1071.004", "T1048.003"],
        "description": "Rapid high-entropy DNS queries suggesting tunneling",
    },
    {
        "name": "Data Staging + Exfiltration",
        "sequence": ["file_created", "file_modified", "network_connect"],
        "severity": Severity.CRITICAL,
        "kill_chain": [KillChainPhase.ACTIONS_ON_OBJECTIVES],
        "mitre": [MITRETactic.COLLECTION, MITRETactic.EXFILTRATION],
        "techniques": ["T1074", "T1041"],
        "description": "File staging followed by outbound network activity",
    },
    {
        "name": "Reconnaissance Activity",
        "sequence": ["network_connect", "network_connect", "network_connect"],
        "min_count": 3,
        "severity": Severity.LOW,
        "kill_chain": [KillChainPhase.RECONNAISSANCE],
        "mitre": [MITRETactic.DISCOVERY],
        "techniques": ["T1046", "T1018"],
        "description": "Multiple rapid connections to different destinations",
    },
    {
        "name": "Defense Evasion - Binary Masquerading",
        "sequence": ["process_start", "file_created"],
        "severity": Severity.HIGH,
        "kill_chain": [KillChainPhase.INSTALLATION],
        "mitre": [MITRETactic.DEFENSE_EVASION],
        "techniques": ["T1036", "T1218"],
        "description": "Process started from unusual location or with masquerading name",
    },
    {
        "name": "Privilege Escalation Pattern",
        "sequence": ["process_start", "process_start"],
        "severity": Severity.HIGH,
        "kill_chain": [KillChainPhase.EXPLOITATION],
        "mitre": [MITRETactic.PRIV_ESCALATION],
        "techniques": ["T1068", "T1055"],
        "description": "Suspicious process spawned with elevated privileges",
    },
    {
        "name": "PowerShell Encoded Command",
        "sequence": ["process_start"],
        "severity": Severity.HIGH,
        "kill_chain": [KillChainPhase.EXPLOITATION, KillChainPhase.INSTALLATION],
        "mitre": [MITRETactic.EXECUTION, MITRETactic.DEFENSE_EVASION],
        "techniques": ["T1059.001", "T1027"],
        "description": "PowerShell with encoded command (possible fileless malware)",
    },
    {
        "name": "Scheduled Task Persistence",
        "sequence": ["process_start", "file_created", "process_start"],
        "severity": Severity.HIGH,
        "kill_chain": [KillChainPhase.INSTALLATION],
        "mitre": [MITRETactic.PERSISTENCE, MITRETactic.EXECUTION],
        "techniques": ["T1053.005", "T1059.001"],
        "description": "File creation followed by scheduled task registration",
    },
    {
        "name": "WMI Lateral Movement",
        "sequence": ["process_start", "network_connect"],
        "min_count": 2,
        "severity": Severity.HIGH,
        "kill_chain": [KillChainPhase.EXPLOITATION, KillChainPhase.ACTIONS_ON_OBJECTIVES],
        "mitre": [MITRETactic.LATERAL_MOVEMENT, MITRETactic.EXECUTION],
        "techniques": ["T1047", "T1021.006"],
        "description": "WMI-based remote execution detected",
    },
    {
        "name": "Registry Persistence Mechanism",
        "sequence": ["file_created", "process_start"],
        "severity": Severity.HIGH,
        "kill_chain": [KillChainPhase.INSTALLATION],
        "mitre": [MITRETactic.PERSISTENCE, MITRETactic.DEFENSE_EVASION],
        "techniques": ["T1547.001", "T1112"],
        "description": "Registry modification followed by process execution",
    },
    {
        "name": "DLL Side-Loading Attack",
        "sequence": ["file_created", "process_start"],
        "severity": Severity.HIGH,
        "kill_chain": [KillChainPhase.INSTALLATION],
        "mitre": [MITRETactic.DEFENSE_EVASION, MITRETactic.PERSISTENCE],
        "techniques": ["T1574.002", "T1218"],
        "description": "DLL loaded from non-standard location",
    },
    {
        "name": "Process Injection Detection",
        "sequence": ["process_start", "process_start"],
        "severity": Severity.CRITICAL,
        "kill_chain": [KillChainPhase.EXPLOITATION, KillChainPhase.INSTALLATION],
        "mitre": [MITRETactic.DEFENSE_EVASION, MITRETactic.PRIV_ESCALATION],
        "techniques": ["T1055", "T1620"],
        "description": "Process injection into legitimate process detected",
    },
    {
        "name": "Encrypted C2 Channel",
        "sequence": ["tls_connection", "network_connect"],
        "severity": Severity.HIGH,
        "kill_chain": [KillChainPhase.COMMAND_AND_CONTROL],
        "mitre": [MITRETactic.C2, MITRETactic.EXECUTION],
        "techniques": ["T1573", "T1071"],
        "description": "Encrypted channel to known C2 infrastructure",
    },
    {
        "name": "DNS over HTTPS Tunneling",
        "sequence": ["dns_query", "tls_connection"],
        "severity": Severity.HIGH,
        "kill_chain": [KillChainPhase.COMMAND_AND_CONTROL, KillChainPhase.ACTIONS_ON_OBJECTIVES],
        "mitre": [MITRETactic.C2, MITRETactic.EXFILTRATION],
        "techniques": ["T1071.004", "T1573.002"],
        "description": "DNS queries tunneled over HTTPS to evade detection",
    },
    {
        "name": "LOLBin Abuse Detection",
        "sequence": ["process_start"],
        "severity": Severity.HIGH,
        "kill_chain": [KillChainPhase.INSTALLATION, KillChainPhase.INSTALLATION],
        "mitre": [MITRETactic.DEFENSE_EVASION, MITRETactic.EXECUTION],
        "techniques": ["T1218", "T1059"],
        "description": "Living-off-the-land binary used for execution",
    },
    {
        "name": "Fileless Malware Pattern",
        "sequence": ["process_start", "network_connect"],
        "severity": Severity.CRITICAL,
        "kill_chain": [KillChainPhase.EXPLOITATION, KillChainPhase.COMMAND_AND_CONTROL],
        "mitre": [MITRETactic.EXECUTION, MITRETactic.DEFENSE_EVASION],
        "techniques": ["T1059.001", "T1620"],
        "description": "Memory-only execution with no file drop detected",
    },
    {
        "name": "Ransomware Encryption Behavior",
        "sequence": ["file_created", "file_modified", "file_modified", "file_modified"],
        "min_count": 4,
        "severity": Severity.CRITICAL,
        "kill_chain": [KillChainPhase.ACTIONS_ON_OBJECTIVES],
        "mitre": [MITRETactic.IMPACT],
        "techniques": ["T1486", "T1490"],
        "description": "Mass file modification/encryption pattern consistent with ransomware",
    },
    {
        "name": "Crypto Mining Activity",
        "sequence": ["process_start", "network_connect"],
        "severity": Severity.MEDIUM,
        "kill_chain": [KillChainPhase.INSTALLATION, KillChainPhase.ACTIONS_ON_OBJECTIVES],
        "mitre": [MITRETactic.IMPACT, MITRETactic.C2],
        "techniques": ["T1496", "T1071"],
        "description": "High CPU process with mining pool connections",
    },
    {
        "name": "Data Staging in Temp Directory",
        "sequence": ["file_created", "file_created", "network_connect"],
        "min_count": 3,
        "severity": Severity.HIGH,
        "kill_chain": [KillChainPhase.ACTIONS_ON_OBJECTIVES],
        "mitre": [MITRETactic.COLLECTION, MITRETactic.EXFILTRATION],
        "techniques": ["T1074.001", "T1560"],
        "description": "Multiple files created in temp directory before exfiltration",
    },
    {
        "name": "Web Shell Deployment",
        "sequence": ["file_created", "network_connect"],
        "severity": Severity.CRITICAL,
        "kill_chain": [KillChainPhase.INSTALLATION, KillChainPhase.COMMAND_AND_CONTROL],
        "mitre": [MITRETactic.PERSISTENCE, MITRETactic.C2],
        "techniques": ["T1505.003", "T1071.001"],
        "description": "Web-accessible file creation with subsequent network activity",
    },
    {
        "name": "Supply Chain Compromise Indicator",
        "sequence": ["process_start", "network_connect", "file_created"],
        "severity": Severity.CRITICAL,
        "kill_chain": [KillChainPhase.WEAPONIZATION, KillChainPhase.INSTALLATION],
        "mitre": [MITRETactic.INITIAL_ACCESS, MITRETactic.PERSISTENCE],
        "techniques": ["T1195.002", "T1554"],
        "description": "Legitimate process connecting to update infrastructure and writing files",
    },
    {
        "name": "Brute Force Detection",
        "sequence": ["network_connect", "network_connect", "network_connect", "network_connect"],
        "min_count": 10,
        "severity": Severity.MEDIUM,
        "kill_chain": [KillChainPhase.EXPLOITATION],
        "mitre": [MITRETactic.CREDENTIAL_ACCESS],
        "techniques": ["T1110", "T1046"],
        "description": "Multiple rapid authentication attempts to same service",
    },
    {
        "name": "Kerberoasting Attack",
        "sequence": ["process_start", "network_connect"],
        "severity": Severity.HIGH,
        "kill_chain": [KillChainPhase.EXPLOITATION],
        "mitre": [MITRETactic.CREDENTIAL_ACCESS],
        "techniques": ["T1558.003", "T1087.002"],
        "description": "Kerberos TGS request followed by offline cracking attempt",
    },
    {
        "name": "Pass-the-Hash Detection",
        "sequence": ["network_connect", "network_connect"],
        "severity": Severity.CRITICAL,
        "kill_chain": [KillChainPhase.EXPLOITATION, KillChainPhase.ACTIONS_ON_OBJECTIVES],
        "mitre": [MITRETactic.LATERAL_MOVEMENT, MITRETactic.CREDENTIAL_ACCESS],
        "techniques": ["T1550.002", "T1021.002"],
        "description": "SMB lateral movement with reused NTLM hashes",
    },
    {
        "name": "Data Exfiltration Over DNS",
        "sequence": ["dns_query", "dns_query", "dns_query"],
        "min_count": 3,
        "severity": Severity.CRITICAL,
        "kill_chain": [KillChainPhase.ACTIONS_ON_OBJECTIVES],
        "mitre": [MITRETactic.EXFILTRATION, MITRETactic.C2],
        "techniques": ["T1048.003", "T1071.004"],
        "description": "High-volume DNS queries suggesting data exfiltration via DNS",
    },
    {
        "name": "Suspicious TLS Certificate",
        "sequence": ["tls_connection"],
        "severity": Severity.MEDIUM,
        "kill_chain": [KillChainPhase.COMMAND_AND_CONTROL],
        "mitre": [MITRETactic.C2, MITRETactic.DEFENSE_EVASION],
        "techniques": ["T1573.002", "T1001"],
        "description": "Self-signed or short-lived TLS certificate detected",
    },
    {
        "name": "Credential Dumping via LSASS",
        "sequence": ["process_start", "credential_access"],
        "severity": Severity.CRITICAL,
        "kill_chain": [KillChainPhase.EXPLOITATION],
        "mitre": [MITRETactic.CREDENTIAL_ACCESS, MITRETactic.DEFENSE_EVASION],
        "techniques": ["T1003.001", "T1003.002"],
        "description": "LSASS memory access followed by credential harvesting",
    },
    {
        "name": "Defense Evasion via Timestomping",
        "sequence": ["file_modified", "process_start"],
        "severity": Severity.HIGH,
        "kill_chain": [KillChainPhase.INSTALLATION],
        "mitre": [MITRETactic.DEFENSE_EVASION],
        "techniques": ["T1070.006", "T1036"],
        "description": "File timestamp modification to evade forensic detection",
    },
    {
        "name": "C2 Beaconing Pattern",
        "sequence": ["network_connect", "network_connect", "network_connect"],
        "min_count": 5,
        "severity": Severity.HIGH,
        "kill_chain": [KillChainPhase.COMMAND_AND_CONTROL],
        "mitre": [MITRETactic.C2],
        "techniques": ["T1071", "T1573"],
        "description": "Periodic connections to same destination suggesting C2 beaconing",
    },
    {
        "name": "Hidden Window Execution",
        "sequence": ["process_start"],
        "severity": Severity.HIGH,
        "kill_chain": [KillChainPhase.EXPLOITATION],
        "mitre": [MITRETactic.DEFENSE_EVASION, MITRETactic.EXECUTION],
        "techniques": ["T1059.001", "T1564"],
        "description": "Process launched with hidden window to avoid detection",
    },
]


class BehaviorEngine:
    """Correlates monitoring events into behavioral patterns and profiles.

    Usage::

        engine = BehaviorEngine()
        engine.ingest_event(event)
        profile = engine.analyze()
    """

    def __init__(self) -> None:
        self._events: list[BehaviorEvent] = []
        self._patterns: list[BehaviorPattern] = []
        self._event_window: list[BehaviorEvent] = []

    def ingest_event(self, event: BehaviorEvent) -> None:
        """Add a single behavioral event for analysis."""
        self._events.append(event)
        if len(self._events) > MAX_EVENTS:
            self._events = self._events[-MAX_EVENTS:]
        self._event_window.append(event)
        self._prune_window()

    def ingest_system_event(self, sev: SystemEvent) -> None:
        """Convert and ingest a SystemEvent."""
        be = BehaviorEvent(
            timestamp=sev.timestamp,
            event_type=sev.event_type,
            source_pid=sev.related_pid,
            description=str(sev.details),
            src_ip=sev.details.get("src_ip", "") if isinstance(sev.details, dict) else "",
            dst_ip=sev.details.get("dst_ip", "") if isinstance(sev.details, dict) else "",
            dst_port=sev.details.get("dst_port", 0) if isinstance(sev.details, dict) else 0,
            raw_data=sev.details if isinstance(sev.details, dict) else {},
        )
        self._map_event_to_ttp(be)
        self.ingest_event(be)

    def ingest_packet(self, pkt: LivePacket) -> None:
        """Convert a live packet to a behavioral event."""
        be = BehaviorEvent(
            timestamp=datetime.fromtimestamp(pkt.timestamp) if pkt.timestamp else None,
            event_type="network_packet",
            category="network",
            src_ip=pkt.src_ip, dst_ip=pkt.dst_ip, dst_port=pkt.dst_port,
            raw_data={"length": pkt.length, "flags": pkt.flags, "proto": pkt.protocol},
        )
        if pkt.dns_query:
            be.event_type = "dns_query"
            be.target = pkt.dns_query
        elif pkt.tls_sni:
            be.event_type = "tls_connection"
            be.target = pkt.tls_sni
        elif pkt.http_host:
            be.event_type = "http_request"
            be.target = pkt.http_host

        self._map_event_to_ttp(be)
        self.ingest_event(be)

    def ingest_file_change(self, fc: FileChange) -> None:
        """Convert a file change to a behavioral event."""
        be = BehaviorEvent(
            timestamp=fc.timestamp,
            event_type=f"file_{fc.change_type}",
            category="filesystem",
            description=f"{fc.change_type}: {fc.path}",
            target=fc.path,
            raw_data={"path": fc.path, "size": fc.size, "md5": fc.md5},
        )
        self._map_event_to_ttp(be)
        self.ingest_event(be)

    def ingest_process_snapshot(self, ps: ProcessSnapshot) -> None:
        """Convert a process snapshot to a behavioral event."""
        be = BehaviorEvent(
            timestamp=ps.timestamp,
            event_type="process_snapshot",
            category="process",
            description=f"Process {ps.name} (pid={ps.pid})",
            source_pid=ps.pid,
            source_process=ps.name,
            raw_data={
                "exe": ps.exe_path, "cmdline": ps.cmdline,
                "score": ps.suspicious_score, "flags": ps.anomaly_flags,
            },
        )
        if ps.suspicious_score > 0.5:
            be.severity = Severity.HIGH if ps.suspicious_score > 0.7 else Severity.MEDIUM
        self._map_event_to_ttp(be)
        self.ingest_event(be)

    def _map_event_to_ttp(self, event: BehaviorEvent) -> None:
        """Map an event type to its corresponding MITRE/Kill Chain mapping."""
        mapping = {
            "process_start": (MITRETactic.EXECUTION, KillChainPhase.DELIVERY),
            "network_connect": (MITRETactic.C2, KillChainPhase.COMMAND_AND_CONTROL),
            "dns_query": (MITRETactic.C2, KillChainPhase.COMMAND_AND_CONTROL),
            "tls_connection": (MITRETactic.C2, KillChainPhase.COMMAND_AND_CONTROL),
            "http_request": (MITRETactic.C2, KillChainPhase.COMMAND_AND_CONTROL),
            "file_created": (MITRETactic.PERSISTENCE, KillChainPhase.INSTALLATION),
            "file_deleted": (MITRETactic.DEFENSE_EVASION, KillChainPhase.INSTALLATION),
            "file_modified": (MITRETactic.COLLECTION, KillChainPhase.ACTIONS_ON_OBJECTIVES),
            "credential_access": (MITRETactic.CREDENTIAL_ACCESS, KillChainPhase.EXPLOITATION),
            "network_packet": (MITRETactic.C2, KillChainPhase.COMMAND_AND_CONTROL),
        }
        tactic, phase = mapping.get(event.event_type, (MITRETactic.C2, KillChainPhase.COMMAND_AND_CONTROL))
        event.mitre_tactic = tactic
        event.kill_chain_phase = phase

    def _prune_window(self) -> None:
        """Remove events outside the analysis time window."""
        cutoff = datetime.now() - timedelta(seconds=config.BEHAVIOR_SEQUENCE_WINDOW)
        self._event_window = [e for e in self._event_window
                              if e.timestamp and e.timestamp >= cutoff]
        if len(self._event_window) > MAX_WINDOW_EVENTS:
            self._event_window = self._event_window[-MAX_WINDOW_EVENTS:]

    def detect_patterns(self) -> list[BehaviorPattern]:
        """Scan the event window for matching detection rules."""
        detected: list[BehaviorPattern] = []

        for rule in SEQUENCE_RULES:
            pattern_events = self._match_sequence(rule)
            if pattern_events:
                bp = BehaviorPattern(
                    name=rule["name"],
                    description=rule["description"],
                    events=pattern_events,
                    severity=rule["severity"],
                    confidence=min(len(pattern_events) / max(rule.get("min_count", len(rule["sequence"])), 1), 1.0),
                    kill_chain_phases=rule["kill_chain"],
                    mitre_tactics=rule["mitre"],
                    techniques=rule["techniques"],
                    first_seen=min(e.timestamp for e in pattern_events if e.timestamp),
                    last_seen=max(e.timestamp for e in pattern_events if e.timestamp),
                )
                detected.append(bp)
                logger.warning("Behavioral pattern detected: %s (severity=%s, confidence=%.2f)",
                               bp.name, bp.severity.value, bp.confidence)

        self._patterns = detected
        return detected

    def _match_sequence(self, rule: dict) -> list[BehaviorEvent]:
        """Check if a rule's event sequence matches the current window."""
        required = rule["sequence"]
        min_count = rule.get("min_count", len(required))

        type_counts = Counter(e.event_type for e in self._event_window)
        matched_count = sum(1 for t in required if type_counts.get(t, 0) > 0)

        if matched_count >= min(min_count, len(required)):
            return [e for e in self._event_window if e.event_type in set(required)]
        return []

    def analyze(self, host: str = "this_host") -> BehavioralProfile:
        """Run full behavioral analysis and produce a profile."""
        patterns = self.detect_patterns()

        total_kill_chain = []
        total_mitre = []
        total_ttps = []
        for p in patterns:
            total_kill_chain.extend(p.kill_chain_phases)
            total_mitre.extend(p.mitre_tactics)
            total_ttps.extend(p.techniques)

        # Deduplicate while preserving order
        seen_kc = set()
        unique_kc = []
        for kc in total_kill_chain:
            if kc not in seen_kc:
                seen_kc.add(kc)
                unique_kc.append(kc)

        seen_mt = set()
        unique_mt = []
        for mt in total_mitre:
            if mt not in seen_mt:
                seen_mt.add(mt)
                unique_mt.append(mt)

        # Compute aggregate scores
        severity_weights = {Severity.CRITICAL: 1.0, Severity.HIGH: 0.75,
                            Severity.MEDIUM: 0.5, Severity.LOW: 0.25, Severity.INFO: 0.1}
        pattern_score = sum(severity_weights.get(p.severity, 0) * p.confidence for p in patterns)
        behavioral_score = min(pattern_score / max(len(patterns), 1), 1.0)
        anomaly_score = self._compute_anomaly_score()

        summary = self._generate_summary(patterns, unique_kc, unique_mt, behavioral_score)

        profile = BehavioralProfile(
            host=host,
            total_events=len(self._events),
            patterns=patterns,
            kill_chain_progression=unique_kc,
            mitre_coverage=unique_mt,
            behavioral_score=behavioral_score,
            anomaly_score=anomaly_score,
            ttps=list(set(total_ttps)),
            summary=summary,
        )

        logger.info(
            "Behavioral analysis complete: score=%.2f, patterns=%d, TTPs=%d",
            behavioral_score, len(patterns), len(profile.ttps),
        )
        return profile

    def _compute_anomaly_score(self) -> float:
        """Simple anomaly score based on event volume and diversity."""
        if not self._event_window:
            return 0.0
        type_count = len(set(e.event_type for e in self._event_window))
        volume = len(self._event_window)
        volume_score = min(volume / 100.0, 1.0)
        diversity_score = min(type_count / 8.0, 1.0)
        return (volume_score * 0.6 + diversity_score * 0.4)

    def _generate_summary(
        self, patterns: list[BehaviorPattern],
        kill_chain: list[KillChainPhase], mitre: list[MITRETactic],
        score: float,
    ) -> str:
        """Generate a human-readable behavioral summary."""
        threat_level = "LOW"
        if score > 0.8:
            threat_level = "CRITICAL"
        elif score > 0.6:
            threat_level = "HIGH"
        elif score > 0.3:
            threat_level = "MEDIUM"

        parts = [f"Threat Level: {threat_level} (score={score:.2f})"]
        parts.append(f"Detected {len(patterns)} behavioral pattern(s)")

        if kill_chain:
            phases = ", ".join(p.value for p in kill_chain[:5])
            parts.append(f"Kill Chain Progression: {phases}")
        if mitre:
            tactics = ", ".join(t.value for t in mitre[:6])
            parts.append(f"MITRE Tactics: {tactics}")

        return " | ".join(parts)

    @property
    def event_count(self) -> int:
        return len(self._events)

    @property
    def window_count(self) -> int:
        return len(self._event_window)
