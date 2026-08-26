"""
models.py - Complete domain model for the PcapMalAnalyzer Threat Intelligence Suite.

Defines every data structure used across the live monitoring, behavioral analysis,
threat actor profiling, damage assessment, alerting, and response pipelines.
This module is the single source of truth for all inter-module data contracts.
"""

from __future__ import annotations

import enum
import uuid
from dataclasses import dataclass, field
from datetime import datetime
from typing import Any, Optional


# ═══════════════════════════════════════════════════════════════════════════
# Custom Exceptions
# ═══════════════════════════════════════════════════════════════════════════

class SuiteError(Exception):
    """Base exception for the entire suite."""

class IngestionError(SuiteError):
    """PCAP file cannot be ingested or validated."""

class ParseError(SuiteError):
    """A packet or protocol layer cannot be parsed."""

class ExtractionError(SuiteError):
    """File carving or stream reassembly fails."""

class IntelligenceError(SuiteError):
    """IOC lookup or enrichment fails."""

class CaptureError(SuiteError):
    """Live capture engine failure."""

class MonitorError(SuiteError):
    """Process or file monitor failure."""

class ResponseError(SuiteError):
    """Automated response execution failure."""


# ═══════════════════════════════════════════════════════════════════════════
# Core Enums
# ═══════════════════════════════════════════════════════════════════════════

class Severity(enum.Enum):
    INFO = "info"
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"

    @property
    def numeric(self) -> int:
        return {"info": 0, "low": 1, "medium": 2, "high": 3, "critical": 4}[self.value]

    def __ge__(self, other: Severity) -> bool:
        return self.numeric >= other.numeric

    def __gt__(self, other: Severity) -> bool:
        return self.numeric > other.numeric


class Protocol(enum.Enum):
    HTTP = "http"
    HTTPS = "https"
    DNS = "dns"
    TLS = "tls"
    SSH = "ssh"
    SMTP = "smtp"
    FTP = "ftp"
    SMB = "smb"
    RDP = "rdp"
    ICMP = "icmp"
    DHCP = "dhcp"
    NTP = "ntp"
    TFTP = "tftp"
    KERBEROS = "kerberos"
    LDAP = "ldap"
    UNKNOWN = "unknown"


class FileType(enum.Enum):
    EXECUTABLE = "executable"
    DLL = "dll"
    SCRIPT = "script"
    DOCUMENT = "document"
    ARCHIVE = "archive"
    IMAGE = "image"
    CONFIG = "config"
    LOG = "log"
    ENCRYPTED = "encrypted"
    UNKNOWN = "unknown"


class IOCType(enum.Enum):
    IP = "ip"
    DOMAIN = "domain"
    HASH_MD5 = "hash_md5"
    HASH_SHA1 = "hash_sha1"
    HASH_SHA256 = "hash_sha256"
    URL = "url"
    JA3 = "ja3"
    JA3S = "ja3s"
    USER_AGENT = "user_agent"
    FILE_PATH = "file_path"
    REGISTRY_KEY = "registry_key"
    MUTEX = "mutex"
    PIPE = "pipe"
    EMAIL = "email"


class KillChainPhase(enum.Enum):
    """Lockheed Martin Cyber Kill Chain phases."""
    RECONNAISSANCE = "reconnaissance"
    WEAPONIZATION = "weaponization"
    DELIVERY = "delivery"
    EXPLOITATION = "exploitation"
    INSTALLATION = "installation"
    COMMAND_AND_CONTROL = "command_and_control"
    ACTIONS_ON_OBJECTIVES = "actions_on_objectives"


class MITRETactic(enum.Enum):
    """MITRE ATT&CK tactics."""
    RECON = "TA0043"
    RESOURCE_DEV = "TA0042"
    INITIAL_ACCESS = "TA0001"
    EXECUTION = "TA0002"
    PERSISTENCE = "TA0003"
    PRIV_ESCALATION = "TA0004"
    DEFENSE_EVASION = "TA0005"
    CREDENTIAL_ACCESS = "TA0006"
    DISCOVERY = "TA0007"
    LATERAL_MOVEMENT = "TA0008"
    COLLECTION = "TA0009"
    C2 = "TA0011"
    EXFILTRATION = "TA0010"
    IMPACT = "TA0040"


class AlertPriority(enum.Enum):
    DEBUG = 0
    INFO = 1
    NOTICE = 2
    WARNING = 3
    ERROR = 4
    CRITICAL = 5
    EMERGENCY = 6


class ResponseAction(enum.Enum):
    BLOCK_IP = "block_ip"
    BLOCK_DOMAIN = "block_domain"
    KILL_PROCESS = "kill_process"
    QUARANTINE_FILE = "quarantine_file"
    ISOLATE_HOST = "isolate_host"
    DISABLE_ACCOUNT = "disable_account"
    RESET_CREDENTIALS = "reset_credentials"
    NOTIFY_ADMIN = "notify_admin"
    CAPTURE_FORENSICS = "capture_forensics"
    GENERATE_REPORT = "generate_report"
    ENABLE_LOGGING = "enable_logging"
    BLOCK_PORT = "block_port"
    FLUSH_DNS = "flush_dns"
    REVOKE_SESSION = "revoke_session"


class Platform(enum.Enum):
    WINDOWS = "windows"
    LINUX = "linux"
    MACOS = "macos"
    ANY = "any"


# ═══════════════════════════════════════════════════════════════════════════
# Network Flow Models
# ═══════════════════════════════════════════════════════════════════════════

@dataclass(frozen=True, slots=True)
class FlowTuple:
    """Immutable 5-tuple identifying a unidirectional network flow."""
    src_ip: str
    dst_ip: str
    src_port: int
    dst_port: int
    protocol: int

    def __str__(self) -> str:
        return f"{self.src_ip}:{self.src_port} -> {self.dst_ip}:{self.dst_port} (proto={self.protocol})"

    def reverse(self) -> FlowTuple:
        return FlowTuple(self.dst_ip, self.src_ip, self.dst_port, self.src_port, self.protocol)


@dataclass(slots=True)
class FlowMetadata:
    """Aggregated metadata for a single network flow."""
    flow: FlowTuple
    packet_count: int = 0
    byte_count: int = 0
    first_seen: Optional[datetime] = None
    last_seen: Optional[datetime] = None
    app_protocol: Protocol = Protocol.UNKNOWN
    flags: list[str] = field(default_factory=list)
    suspicious_score: float = 0.0


@dataclass(slots=True)
class LivePacket:
    """A single packet captured from a live interface."""
    timestamp: float
    src_ip: str
    dst_ip: str
    src_port: int
    dst_port: int
    protocol: int
    length: int
    flags: str = ""
    raw_summary: str = ""
    app_protocol: str = ""
    dns_query: str = ""
    http_host: str = ""
    http_uri: str = ""
    tls_sni: str = ""
    payload_preview: str = ""


# ═══════════════════════════════════════════════════════════════════════════
# Protocol Parsed Artifacts
# ═══════════════════════════════════════════════════════════════════════════

@dataclass(slots=True)
class DNSQuery:
    """A single DNS query/response pair."""
    query_name: str
    query_type: str
    response_codes: list[str] = field(default_factory=list)
    resolved_ips: list[str] = field(default_factory=list)
    timestamp: Optional[datetime] = None
    src_ip: Optional[str] = None
    high_entropy: bool = False
    possible_dga: bool = False
    ttl: Optional[int] = None
    suspicious: bool = False


@dataclass(slots=True)
class HTTPRequest:
    """Parsed HTTP request metadata."""
    method: str
    uri: str
    host: str
    user_agent: str = ""
    content_type: str = ""
    content_length: int = 0
    headers: dict[str, str] = field(default_factory=dict)
    timestamp: Optional[datetime] = None
    src_ip: Optional[str] = None
    dst_ip: Optional[str] = None
    src_port: Optional[int] = None
    dst_port: Optional[int] = None
    suspicious: bool = False


@dataclass(slots=True)
class TLSMetadata:
    """Parsed TLS handshake metadata."""
    sni: str = ""
    ja3: str = ""
    ja3s: str = ""
    version: str = ""
    cipher_suite: str = ""
    certificate_issuer: str = ""
    certificate_subject: str = ""
    certificate_not_before: Optional[str] = None
    certificate_not_after: Optional[str] = None
    src_ip: Optional[str] = None
    dst_ip: Optional[str] = None
    src_port: Optional[int] = None
    dst_port: Optional[int] = None
    timestamp: Optional[datetime] = None
    self_signed: bool = False
    suspicious: bool = False


@dataclass(slots=True)
class CredentialArtifact:
    """Detected cleartext credential or authentication data."""
    protocol: Protocol
    username: str = ""
    password: str = ""
    auth_type: str = ""
    src_ip: Optional[str] = None
    dst_ip: Optional[str] = None
    timestamp: Optional[datetime] = None
    raw_match: str = ""


# ═══════════════════════════════════════════════════════════════════════════
# Process & System Monitoring
# ═══════════════════════════════════════════════════════════════════════════

@dataclass(slots=True)
class ProcessSnapshot:
    """Point-in-time state of a monitored process."""
    pid: int
    name: str
    exe_path: str = ""
    cmdline: list[str] = field(default_factory=list)
    username: str = ""
    cpu_percent: float = 0.0
    memory_rss: int = 0
    memory_vms: int = 0
    status: str = "running"
    create_time: Optional[float] = None
    connections: list[dict[str, Any]] = field(default_factory=list)
    open_files: list[str] = field(default_factory=list)
    threads: int = 0
    parent_pid: int = 0
    parent_name: str = ""
    md5: str = ""
    sha256: str = ""
    signed: Optional[bool] = None
    suspicious_score: float = 0.0
    anomaly_flags: list[str] = field(default_factory=list)
    timestamp: Optional[datetime] = None


@dataclass(slots=True)
class ProcessDiff:
    """Delta between two process snapshots - detects new/modified/removed."""
    new_processes: list[ProcessSnapshot] = field(default_factory=list)
    terminated_processes: list[ProcessSnapshot] = field(default_factory=list)
    modified_processes: list[tuple[ProcessSnapshot, ProcessSnapshot]] = field(default_factory=list)
    new_connections: list[dict[str, Any]] = field(default_factory=list)
    new_files: list[dict[str, Any]] = field(default_factory=list)


@dataclass(slots=True)
class FileChange:
    """A detected change to a monitored file path."""
    path: str
    change_type: str  # created, modified, deleted, renamed
    old_path: str = ""
    size: int = 0
    md5: str = ""
    sha256: str = ""
    process_name: str = ""
    process_pid: int = 0
    timestamp: Optional[datetime] = None


@dataclass(slots=True)
class SystemEvent:
    """A general system-level event from monitoring."""
    event_type: str  # process_start, process_exit, network_connect, file_write, etc.
    severity: Severity = Severity.INFO
    source: str = ""
    details: dict[str, Any] = field(default_factory=dict)
    timestamp: Optional[datetime] = None
    related_pid: Optional[int] = None
    related_iocs: list[str] = field(default_factory=list)


# ═══════════════════════════════════════════════════════════════════════════
# Behavioral Analysis Models
# ═══════════════════════════════════════════════════════════════════════════

@dataclass(slots=True)
class BehaviorEvent:
    """A normalized behavioral event emitted by any monitoring source."""
    event_id: str = field(default_factory=lambda: uuid.uuid4().hex[:12])
    timestamp: Optional[datetime] = None
    event_type: str = ""
    category: str = ""
    description: str = ""
    source_pid: Optional[int] = None
    source_process: str = ""
    src_ip: str = ""
    dst_ip: str = ""
    dst_port: int = 0
    target: str = ""
    raw_data: dict[str, Any] = field(default_factory=dict)
    mitre_tactic: Optional[MITRETactic] = None
    mitre_technique: str = ""
    kill_chain_phase: Optional[KillChainPhase] = None


@dataclass(slots=True)
class BehaviorPattern:
    """A detected pattern of correlated behavioral events."""
    pattern_id: str = field(default_factory=lambda: uuid.uuid4().hex[:12])
    name: str = ""
    description: str = ""
    events: list[BehaviorEvent] = field(default_factory=list)
    severity: Severity = Severity.LOW
    confidence: float = 0.0
    kill_chain_phases: list[KillChainPhase] = field(default_factory=list)
    mitre_tactics: list[MITRETactic] = field(default_factory=list)
    techniques: list[str] = field(default_factory=list)
    first_seen: Optional[datetime] = None
    last_seen: Optional[datetime] = None


@dataclass(slots=True)
class BehavioralProfile:
    """Complete behavioral analysis result for a session or host."""
    host: str = ""
    total_events: int = 0
    patterns: list[BehaviorPattern] = field(default_factory=list)
    kill_chain_progression: list[KillChainPhase] = field(default_factory=list)
    mitre_coverage: list[MITRETactic] = field(default_factory=list)
    behavioral_score: float = 0.0  # 0.0 = benign, 1.0 = definitely malicious
    anomaly_score: float = 0.0
    ttps: list[str] = field(default_factory=list)
    summary: str = ""


# ═══════════════════════════════════════════════════════════════════════════
# Threat Actor Profiling
# ═══════════════════════════════════════════════════════════════════════════

@dataclass(slots=True)
class ThreatActor:
    """A profiled threat actor based on observed TTPs and IOCs."""
    actor_id: str = field(default_factory=lambda: uuid.uuid4().hex[:12])
    aliases: list[str] = field(default_factory=list)
    attribution_confidence: float = 0.0
    associated_groups: list[str] = field(default_factory=list)
    ttps: list[str] = field(default_factory=list)
    mitre_tactics: list[MITRETactic] = field(default_factory=list)
    kill_chain_phases: list[KillChainPhase] = field(default_factory=list)
    iocs: list[str] = field(default_factory=list)
    campaigns: list[str] = field(default_factory=list)
    motivation: str = ""  # financial, espionage, hacktivism, destructive
    sophistication: str = ""  # novice, intermediate, advanced, expert, innovator
    infrastructure: list[str] = field(default_factory=list)  # C2 servers, domains
    first_seen: Optional[datetime] = None
    last_seen: Optional[datetime] = None
    activity_log: list[BehaviorEvent] = field(default_factory=list)


@dataclass(slots=True)
class CampaignProfile:
    """A broader campaign tying multiple events/actors together."""
    campaign_id: str = field(default_factory=lambda: uuid.uuid4().hex[:12])
    name: str = ""
    actors: list[str] = field(default_factory=list)
    target_sectors: list[str] = field(default_factory=list)
    target_countries: list[str] = field(default_factory=list)
    objectives: list[str] = field(default_factory=list)
    ttps: list[str] = field(default_factory=list)
    infrastructure: list[str] = field(default_factory=list)
    timeline: list[BehaviorEvent] = field(default_factory=list)
    severity: Severity = Severity.MEDIUM
    description: str = ""


# ═══════════════════════════════════════════════════════════════════════════
# Damage Assessment
# ═══════════════════════════════════════════════════════════════════════════

@dataclass(slots=True)
class DamageVector:
    """A single dimension of assessed damage."""
    vector_name: str  # confidentiality, integrity, availability, financial
    score: float = 0.0  # 0-10
    description: str = ""
    evidence: list[str] = field(default_factory=list)
    estimated_impact: str = ""


@dataclass(slots=True)
class LateralMovement:
    """A detected lateral movement step."""
    source_host: str = ""
    destination_host: str = ""
    method: str = ""  # smb, rdp, ssh, wmi, psexec, etc.
    account_used: str = ""
    timestamp: Optional[datetime] = None
    success: bool = False
    privilege_escalated: bool = False


@dataclass(slots=True)
class DataExfiltration:
    """A detected or suspected data exfiltration event."""
    source_ip: str = ""
    destination_ip: str = ""
    destination_domain: str = ""
    protocol: str = ""
    bytes_sent: int = 0
    file_paths: list[str] = field(default_factory=list)
    timestamp: Optional[datetime] = None
    confidence: float = 0.0
    staging_areas: list[str] = field(default_factory=list)


@dataclass(slots=True)
class DamageAssessment:
    """Complete damage assessment for an incident."""
    assessment_id: str = field(default_factory=lambda: uuid.uuid4().hex[:12])
    overall_score: float = 0.0  # 0-100
    severity: Severity = Severity.INFO
    vectors: list[DamageVector] = field(default_factory=list)
    lateral_movements: list[LateralMovement] = field(default_factory=list)
    data_exfiltrations: list[DataExfiltration] = field(default_factory=list)
    compromised_hosts: list[str] = field(default_factory=list)
    compromised_accounts: list[str] = field(default_factory=list)
    blast_radius: int = 0  # number of affected hosts
    downtime_estimate: str = ""
    data_at_risk: str = ""
    financial_impact: str = ""
    recovery_time: str = ""
    summary: str = ""


# ═══════════════════════════════════════════════════════════════════════════
# IOC & Intelligence
# ═══════════════════════════════════════════════════════════════════════════

@dataclass(slots=True)
class IOC:
    """A single Indicator of Compromise."""
    value: str
    ioc_type: IOCType
    severity: Severity = Severity.LOW
    source: str = ""
    description: str = ""
    first_seen: Optional[datetime] = None
    last_seen: Optional[datetime] = None
    confidence: float = 0.0
    related_processes: list[int] = field(default_factory=list)


@dataclass(slots=True)
class IntelMatch:
    """Result of cross-referencing an IOC against threat intelligence."""
    ioc: IOC
    matched: bool = False
    threat_name: str = ""
    threat_category: str = ""
    confidence: float = 0.0
    details: str = ""
    source: str = ""
    references: list[str] = field(default_factory=list)


# ═══════════════════════════════════════════════════════════════════════════
# Alert System
# ═══════════════════════════════════════════════════════════════════════════

@dataclass(slots=True)
class Alert:
    """A real-time alert generated by the detection engine."""
    alert_id: str = field(default_factory=lambda: uuid.uuid4().hex[:12])
    timestamp: Optional[datetime] = None
    priority: AlertPriority = AlertPriority.INFO
    severity: Severity = Severity.LOW
    title: str = ""
    description: str = ""
    source: str = ""
    category: str = ""
    host: str = ""
    src_ip: str = ""
    dst_ip: str = ""
    process_name: str = ""
    process_pid: int = 0
    mitre_tactic: Optional[MITRETactic] = None
    mitre_technique: str = ""
    kill_chain_phase: Optional[KillChainPhase] = None
    iocs: list[str] = field(default_factory=list)
    evidence: list[str] = field(default_factory=list)
    recommended_actions: list[ResponseAction] = field(default_factory=list)
    acknowledged: bool = False
    escalated: bool = False
    suppressed: bool = False


@dataclass(slots=True)
class AlertGroup:
    """Correlated alerts forming an incident cluster."""
    group_id: str = field(default_factory=lambda: uuid.uuid4().hex[:12])
    name: str = ""
    alerts: list[Alert] = field(default_factory=list)
    first_seen: Optional[datetime] = None
    last_seen: Optional[datetime] = None
    severity: Severity = Severity.LOW
    confidence: float = 0.0
    kill_chain_phases: list[KillChainPhase] = field(default_factory=list)
    affected_hosts: list[str] = field(default_factory=list)


# ═══════════════════════════════════════════════════════════════════════════
# Automated Response
# ═══════════════════════════════════════════════════════════════════════════

@dataclass(slots=True)
class ResponseCommand:
    """A single automated or recommended response action."""
    command_id: str = field(default_factory=lambda: uuid.uuid4().hex[:12])
    action: ResponseAction = ResponseAction.NOTIFY_ADMIN
    platform: Platform = Platform.ANY
    command_str: str = ""
    description: str = ""
    requires_elevation: bool = False
    reversible: bool = True
    estimated_impact: str = ""
    preconditions: list[str] = field(default_factory=list)
    execution_status: str = "pending"  # pending, executed, failed, skipped
    execution_result: str = ""
    executed_at: Optional[datetime] = None


@dataclass(slots=True)
class Playbook:
    """A pre-defined response playbook for a specific threat type."""
    playbook_id: str = field(default_factory=lambda: uuid.uuid4().hex[:12])
    name: str = ""
    description: str = ""
    trigger_conditions: list[str] = field(default_factory=list)
    severity_threshold: Severity = Severity.HIGH
    commands: list[ResponseCommand] = field(default_factory=list)
    tags: list[str] = field(default_factory=list)


@dataclass(slots=True)
class ResponsePlan:
    """A complete response plan generated for a detected threat."""
    plan_id: str = field(default_factory=lambda: uuid.uuid4().hex[:12])
    incident_id: str = ""
    severity: Severity = Severity.LOW
    commands: list[ResponseCommand] = field(default_factory=list)
    executed_count: int = 0
    failed_count: int = 0
    skipped_count: int = 0
    generated_at: Optional[datetime] = None
    summary: str = ""


# ═══════════════════════════════════════════════════════════════════════════
# Extracted Files
# ═══════════════════════════════════════════════════════════════════════════

@dataclass(slots=True)
class CarvedFile:
    """A file carved from network streams or disk monitoring."""
    filename: str
    file_type: FileType
    size: int
    md5: str = ""
    sha1: str = ""
    sha256: str = ""
    quarantine_path: str = ""
    src_ip: Optional[str] = None
    dst_ip: Optional[str] = None
    src_port: Optional[int] = None
    dst_port: Optional[int] = None
    timestamp: Optional[datetime] = None
    magic_bytes: str = ""
    entropy: float = 0.0
    is_packed: bool = False
    suspicious_score: float = 0.0


# ═══════════════════════════════════════════════════════════════════════════
# PCAP Metadata
# ═══════════════════════════════════════════════════════════════════════════

@dataclass(slots=True)
class PcapMetadata:
    """High-level metadata from a static PCAP file."""
    filename: str
    file_size: int
    packet_count: int
    capture_duration: float
    link_type: str
    first_packet_time: Optional[datetime] = None
    last_packet_time: Optional[datetime] = None
    unique_src_ips: int = 0
    unique_dst_ips: int = 0
    tcp_packet_count: int = 0
    udp_packet_count: int = 0
    dns_packet_count: int = 0
    http_packet_count: int = 0
    tls_packet_count: int = 0


# ═══════════════════════════════════════════════════════════════════════════
# Live Monitoring Session State
# ═══════════════════════════════════════════════════════════════════════════

@dataclass(slots=True)
class MonitorSession:
    """State container for an active monitoring session."""
    session_id: str = field(default_factory=lambda: uuid.uuid4().hex[:12])
    platform: Platform = Platform.ANY
    started_at: Optional[datetime] = None
    interfaces: list[str] = field(default_factory=list)
    monitored_processes: list[int] = field(default_factory=list)
    monitored_paths: list[str] = field(default_factory=list)
    packet_count: int = 0
    event_count: int = 0
    alert_count: int = 0
    active: bool = True


# ═══════════════════════════════════════════════════════════════════════════
# Aggregated Analysis Result (unified for both static + live)
# ═══════════════════════════════════════════════════════════════════════════

@dataclass(slots=True)
class AnalysisResult:
    """Top-level container for complete analysis output."""
    pcap_metadata: Optional[PcapMetadata] = None
    monitor_session: Optional[MonitorSession] = None
    flows: list[FlowMetadata] = field(default_factory=list)
    dns_queries: list[DNSQuery] = field(default_factory=list)
    http_requests: list[HTTPRequest] = field(default_factory=list)
    tls_sessions: list[TLSMetadata] = field(default_factory=list)
    credentials: list[CredentialArtifact] = field(default_factory=list)
    carved_files: list[CarvedFile] = field(default_factory=list)
    ioc_matches: list[IntelMatch] = field(default_factory=list)
    behavioral_profile: Optional[BehavioralProfile] = None
    threat_actors: list[ThreatActor] = field(default_factory=list)
    campaigns: list[CampaignProfile] = field(default_factory=list)
    damage_assessment: Optional[DamageAssessment] = None
    alerts: list[Alert] = field(default_factory=list)
    alert_groups: list[AlertGroup] = field(default_factory=list)
    response_plan: Optional[ResponsePlan] = None
    system_events: list[SystemEvent] = field(default_factory=list)
    anomalies: list[dict[str, Any]] = field(default_factory=list)
    errors: list[str] = field(default_factory=list)
    analysis_start: Optional[datetime] = None
    analysis_end: Optional[datetime] = None
    elapsed_seconds: float = 0.0

    def summary_dict(self) -> dict[str, Any]:
        """Serialize to a dictionary for JSON output."""
        return {
            "pcap_summary": self.pcap_metadata.__dict__ if self.pcap_metadata else None,
            "monitor_session": self.monitor_session.__dict__ if self.monitor_session else None,
            "flow_count": len(self.flows),
            "dns_query_count": len(self.dns_queries),
            "http_request_count": len(self.http_requests),
            "tls_session_count": len(self.tls_sessions),
            "credential_count": len(self.credentials),
            "carved_file_count": len(self.carved_files),
            "ioc_match_count": len(self.ioc_matches),
            "behavioral_score": self.behavioral_profile.behavioral_score if self.behavioral_profile else 0.0,
            "threat_actor_count": len(self.threat_actors),
            "campaign_count": len(self.campaigns),
            "damage_score": self.damage_assessment.overall_score if self.damage_assessment else 0.0,
            "alert_count": len(self.alerts),
            "response_commands": len(self.response_plan.commands) if self.response_plan else 0,
            "elapsed_seconds": self.elapsed_seconds,
        }
