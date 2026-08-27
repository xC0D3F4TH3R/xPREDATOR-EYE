"""
config.py - Complete configuration for the PcapMalAnalyzer Threat Intelligence Suite.

Centralises all thresholds, paths, API keys, detection rules, behavioural
baselines, platform-specific settings, and playbook defaults.
"""

from __future__ import annotations

import os
import platform
import shutil
from pathlib import Path

# ═══════════════════════════════════════════════════════════════════════════
# Paths
# ═══════════════════════════════════════════════════════════════════════════

PROJECT_ROOT = Path(__file__).resolve().parent
_APP_ROOT = Path(os.environ.get("PCAPANALYZER_HOME", Path.home() / ".xpredator-eye"))
QUARANTINE_DIR = _APP_ROOT / "quarantine"
PLAYBOOK_DIR = _APP_ROOT / "playbooks"
DATA_DIR = _APP_ROOT / "data"
TEMP_DIR = Path(os.environ.get("PCAPANALYZER_TEMP", _APP_ROOT / "tmp"))
DEFAULT_OUTPUT_DIR = Path(os.environ.get("PCAPANALYZER_OUTPUT", _APP_ROOT / "output"))

# Also support project-level data (for default blocklist, etc.)
PROJECT_DATA_DIR = PROJECT_ROOT / "data"

# ═══════════════════════════════════════════════════════════════════════════
# Platform Detection
# ═══════════════════════════════════════════════════════════════════════════

CURRENT_PLATFORM = platform.system().lower()  # windows, linux, darwin

# External tool paths (auto-detected or overridable)
TSHARK_PATH = os.environ.get("TSHARK_PATH", shutil.which("tshark") or "tshark")
DUMPCAP_PATH = os.environ.get("DUMPCAP_PATH", shutil.which("dumpcap") or "dumpcap")

# ═══════════════════════════════════════════════════════════════════════════
# Ingestion / PCAP
# ═══════════════════════════════════════════════════════════════════════════

MAX_PCAP_SIZE_BYTES: int = 4 * 1024 * 1024 * 1024  # 4 GB

PCAP_MAGIC_LE: bytes = b"\xd4\xc3\xb2\xa1"
PCAP_MAGIC_BE: bytes = b"\xa1\xb2\xc3\xd4"
PCAP_MAGIC_NANO: bytes = b"\x4d\x3c\xb2\xa1"
PCAP_MAGIC_NANO_BE: bytes = b"\xa1\xb2\x3c\x4d"
PCAPNG_MAGIC: bytes = b"\x0a\x0d\x0d\x0a"

VALID_MAGIC_BYTES: list[bytes] = [
    PCAP_MAGIC_LE, PCAP_MAGIC_BE, PCAP_MAGIC_NANO, PCAP_MAGIC_NANO_BE, PCAPNG_MAGIC,
]

# ═══════════════════════════════════════════════════════════════════════════
# Live Capture Settings
# ═══════════════════════════════════════════════════════════════════════════

CAPTURE_SNAPLEN: int = 65535
CAPTURE_BUFFER_MB: int = 128
CAPTURE_PROMISCUOUS: bool = True
CAPTURE_FILTER_DEFAULT: str = ""
LIVE_POLL_INTERVAL_SEC: float = 0.5
LIVE_PACKET_QUEUE_SIZE: int = 50000

# ═══════════════════════════════════════════════════════════════════════════
# Parser - DNS
# ═══════════════════════════════════════════════════════════════════════════

DNS_ENTROPY_THRESHOLD: float = 3.5
DNS_DGA_MIN_LABEL_LENGTH: int = 12
DNS_HIGH_VOLUME_THRESHOLD: int = 5000
DNS_TUNNEL_SIZE_THRESHOLD: int = 512  # bytes per query/response (tunneling)

# ═══════════════════════════════════════════════════════════════════════════
# Parser - HTTP
# ═══════════════════════════════════════════════════════════════════════════

SUSPICIOUS_USER_AGENTS: list[str] = [
    "curl", "wget", "python-requests", "python-urllib", "go-http-client",
    "java/", "powershell", "bitsadmin", "certutil", "msxml", "xmlhttp",
    "nsiqfp", "havij", "sqlmap", "nikto", "nmap", "masscan", "zgrab",
    "censys", "shodan", "bot", "spider", "scraper", "automated",
]

CREDENTIAL_PATTERNS: list[str] = [
    r"(?:user(?:name)?|login|email)\s*[:=]\s*\S+",
    r"(?:pass(?:word)?|pwd|passwd)\s*[:=]\s*\S+",
    r"Authorization:\s*Basic\s+[A-Za-z0-9+/=]+",
    r"(?:api[_-]?key|token|secret)\s*[:=]\s*\S+",
]

# ═══════════════════════════════════════════════════════════════════════════
# Parser - TLS / JA3
# ═══════════════════════════════════════════════════════════════════════════

TLS_CLIENTHELLO_MIN_SIZE: int = 20

# ═══════════════════════════════════════════════════════════════════════════
# File Carving
# ═══════════════════════════════════════════════════════════════════════════

FILE_SIGNATURES: dict[str, list[bytes]] = {
    "executable": [
        b"MZ", b"\x7fELF", b"\xca\xfe\xba\xbe",
        b"\xfe\xed\xfa\xce", b"\xfe\xed\xfa\xcf",
    ],
    "script": [
        b"#!/", b"<?php", b"<%", b"import ", b"from ", b"require ", b"function ",
    ],
    "document": [
        b"%PDF", b"\xd0\xcf\x11\xe0", b"PK\x03\x04", b"{\rtf",
    ],
    "archive": [
        b"PK\x03\x04", b"PK\x05\x06", b"Rar!\x1a\x07", b"\x1f\x8b", b"\xfd7zXZ",
    ],
    "image": [
        b"\x89PNG", b"\xff\xd8\xff", b"GIF8", b"RIFF",
    ],
}

MIN_CARVED_FILE_SIZE: int = 64
MAX_STREAM_BUFFER_SIZE: int = 64 * 1024 * 1024

# ═══════════════════════════════════════════════════════════════════════════
# Process Monitor
# ═══════════════════════════════════════════════════════════════════════════

PROCESS_POLL_INTERVAL: float = 2.0  # seconds between snapshots
PROCESS_CPU_SUSPICIOUS: float = 90.0  # percent
PROCESS_MEMORY_SUSPICIOUS_MB: int = 1024
PROCESS_THREAD_SUSPICIOUS: int = 500
PROCESS_SNAPSHOT_HISTORY: int = 500  # snapshots (dicts) kept in memory
PROCESS_MAX_EVENTS: int = 10000  # system events kept in memory
PROCESS_HASH_CACHE_SIZE: int = 4096  # max cached executable hashes

# Known benign executables by name (lowercase) - reduce false positives
KNOWN_BENIGN_PROCESSES: set[str] = {
    "system", "svchost.exe", "csrss.exe", "wininit.exe", "winlogon.exe",
    "lsass.exe", "services.exe", "explorer.exe", "dwm.exe", "taskhostw.exe",
    "conhost.exe", "sihost.exe", "ctfmon.exe", "runtimebroker.exe",
    "chrome.exe", "firefox.exe", "msedge.exe", "code.exe", "python.exe",
    "python3", "python3.11", "python3.12", "bash", "sh", "zsh",
    "sshd", "cron", "systemd", "init", "kernel",
}

# ═══════════════════════════════════════════════════════════════════════════
# File Monitor
# ═══════════════════════════════════════════════════════════════════════════

FILE_MONITOR_INTERVAL: float = 5.0
FILE_CHANGE_DEBOUNCE: float = 2.0

# Critical paths that should always be monitored (platform-adaptive)
CRITICAL_PATHS_WINDOWS: list[str] = [
    r"C:\Windows\System32",
    r"C:\Windows\SysWOW64",
    r"C:\Windows\Temp",
    os.path.expandvars(r"%APPDATA%"),
    os.path.expandvars(r"%LOCALAPPDATA%"),
]

CRITICAL_PATHS_LINUX: list[str] = [
    "/tmp", "/var/tmp", "/etc/crontab", "/etc/passwd",
    "/etc/shadow", "/etc/sudoers", "/var/log",
]

CRITICAL_PATHS_MACOS: list[str] = [
    "/tmp", "/var/tmp", "/Library/LaunchAgents",
    "/Library/LaunchDaemons", "/etc/periodic",
]

# ═══════════════════════════════════════════════════════════════════════════
# Behavioral Engine
# ═══════════════════════════════════════════════════════════════════════════

# Minimum number of correlated events to form a pattern
BEHAVIOR_MIN_PATTERN_EVENTS: int = 3
BEHAVIOR_MIN_EVENTS_PER_PATTERN: int = 3  # Alias for backward compatibility

# Time window for sequence correlation (seconds)
BEHAVIOR_SEQUENCE_WINDOW: float = 300.0  # 5 minutes

# Score thresholds
BEHAVIOR_SCORE_SUSPICIOUS: float = 0.4
BEHAVIOR_SCORE_MALICIOUS: float = 0.7
BEHAVIOR_SCORE_CRITICAL: float = 0.9

# Anomaly detection: standard deviations from baseline
BEHAVIOR_ANOMALY_STDDEV: float = 2.5

# ═══════════════════════════════════════════════════════════════════════════
# Threat Actor Profiling
# ═══════════════════════════════════════════════════════════════════════════

# Minimum TTPs required to form an actor profile
ACTOR_MIN_TTPS: int = 3

# Attribution confidence thresholds
ACTOR_CONFIDENCE_LOW: float = 0.3
ACTOR_CONFIDENCE_MEDIUM: float = 0.6
ACTOR_CONFIDENCE_HIGH: float = 0.8

# ═══════════════════════════════════════════════════════════════════════════
# Damage Assessment
# ═══════════════════════════════════════════════════════════════════════════

DAMAGE_SCORE_LOW: float = 20.0
DAMAGE_SCORE_MEDIUM: float = 45.0
DAMAGE_SCORE_HIGH: float = 70.0
DAMAGE_SCORE_CRITICAL: float = 90.0

# ═══════════════════════════════════════════════════════════════════════════
# Alert System
# ═══════════════════════════════════════════════════════════════════════════

# Rate limiting
ALERT_MAX_PER_MINUTE: int = 60
ALERT_DEDUP_WINDOW: float = 60.0  # seconds
ALERT_AUTO_ESCALATE_AFTER: int = 3  # escalations after N similar alerts

# Alert persistence
ALERT_LOG_FILE: str = "alerts.jsonl"

# ═══════════════════════════════════════════════════════════════════════════
# Response Engine
# ═══════════════════════════════════════════════════════════════════════════

RESPONSE_DRY_RUN_DEFAULT: bool = True  # Always dry-run unless explicitly opted in
RESPONSE_ELEVATION_REQUIRED: list[str] = [
    "block_ip", "kill_process", "isolate_host", "block_port", "flush_dns",
]

# ═══════════════════════════════════════════════════════════════════════════
# Intelligence / API
# ═══════════════════════════════════════════════════════════════════════════

INTEL_RATE_LIMIT_RPM: int = 4
INTEL_REQUEST_TIMEOUT: int = 10
VT_API_KEY_ENV: str = "VIRUSTOTAL_API_KEY"
ABUSEIPDB_API_KEY_ENV: str = "ABUSEIPDB_API_KEY"
OTX_API_KEY_ENV: str = "OTX_API_KEY"
SHODAN_API_KEY_ENV: str = "SHODAN_API_KEY"

# ═══════════════════════════════════════════════════════════════════════════
# Reporter
# ═══════════════════════════════════════════════════════════════════════════

JSON_INDENT: int = 2
REPORT_MAX_FLOWS: int = 500
REPORT_MAX_EVENTS: int = 1000

# ═══════════════════════════════════════════════════════════════════════════
# Logging
# ═══════════════════════════════════════════════════════════════════════════

LOG_FORMAT: str = "%(asctime)s | %(levelname)-8s | %(name)-20s | %(message)s"
LOG_DATE_FORMAT: str = "%Y-%m-%d %H:%M:%S"

# ═══════════════════════════════════════════════════════════════════════════
# Runtime-overridable settings (also sourced from ~/.xpredator-eye/config.yaml)
# ═══════════════════════════════════════════════════════════════════════════

LOG_LEVEL: int = 20  # logging.INFO
LOG_FILE: str | None = None

BEHAVIOR_SUSPICIOUS_THRESHOLD: float = 0.4
BEHAVIOR_MALICIOUS_THRESHOLD: float = 0.7
BEHAVIOR_CRITICAL_THRESHOLD: float = 0.9

ALERT_AUTO_CORRELATE: bool = True
ALERT_CORRELATION_WINDOW: float = 600.0

RESPONSE_REQUIRE_CONFIRMATION: bool = True
RESPONSE_MAX_AUTO_BLOCKS: int = 10
RESPONSE_COOLDOWN_PERIOD: int = 60

ML_MODEL_PATH: Path = _APP_ROOT / "models" / "classifier.pkl"
ML_ANOMALY_CONTAMINATION: float = 0.1
ML_CONFIDENCE_THRESHOLD: float = 0.7

YARA_RULES_DIR: Path = _APP_ROOT / "rules"
YARA_SCAN_TIMEOUT: int = 30

LLM_ENABLED: bool = False
LLM_MODEL: str = "llama3.2:3b"
OLLAMA_URL: str = "http://localhost:11434"
LLM_TEMPERATURE: float = 0.3
LLM_MAX_TOKENS: int = 1024

SIEM_ELASTICSEARCH_ENABLED: bool = False
SIEM_ELASTICSEARCH_HOSTS: list[str] = ["http://localhost:9200"]
SIEM_ELASTICSEARCH_INDEX_PREFIX: str = "xpredator"

SIEM_SPLUNK_ENABLED: bool = False
SIEM_SPLUNK_HEC_URL: str = ""
SIEM_SPLUNK_HEC_TOKEN: str = ""
SIEM_SPLUNK_SOURCE: str = "xpredator"

DEFAULT_CLASSIFICATION: str = "UNCLASSIFIED // FOR OFFICIAL USE ONLY"

USER_CONFIG_PATH = Path(
    os.environ.get("PCAPANALYZER_CONFIG", Path.home() / ".xpredator-eye" / "config.yaml")
)


def load_user_config() -> Path | None:
    """Apply overrides from ``USER_CONFIG_PATH`` (a ``config.yaml`` file).

    Supports the documented configuration schema. Values are applied onto the
    module-level constants so every consumer picks them up at import time.
    """
    path = USER_CONFIG_PATH
    if not path.exists():
        # Fall back to a project-bundled config.yaml if present (repo root).
        bundled = Path(__file__).resolve().parent.parent / "config.yaml"
        if bundled.exists():
            path = bundled
        else:
            return None

        try:
            import yaml  # type: ignore[import-not-found]
        except ImportError:
            return None

        data = yaml.safe_load(path.read_text(encoding="utf-8")) or {}
        g = data.get("general") or {}
        c = data.get("capture") or {}
        d = data.get("dns") or {}
        b = data.get("behavioral") or {}
        p = data.get("process") or {}
        fo = data.get("file") or {}
        a = data.get("alert") or {}
        r = data.get("response") or {}
        da = data.get("damage") or {}
        ml = data.get("ml") or {}
        ya = data.get("yara") or {}
        llm = data.get("llm") or {}
        siem = (data.get("siem") or {}).get("elasticsearch") or {}
        splunk = (data.get("siem") or {}).get("splunk") or {}
        rep = data.get("reporting") or {}
        lg = data.get("logging") or {}

        _MB = 1024 * 1024

        def _get(key, section, default=None):
            v = section.get(key)
            return default if v is None else v

        # General
        if _get("log_level", g):
            LOG_LEVEL = getattr(__import__("logging"), str(_get("log_level", g)).upper(), 20)
            globals()["LOG_LEVEL"] = LOG_LEVEL
        if _get("output_dir", g):
            globals()["DEFAULT_OUTPUT_DIR"] = Path(str(_get("output_dir", g))).expanduser()
        if _get("temp_dir", g):
            globals()["TEMP_DIR"] = Path(str(_get("temp_dir", g))).expanduser()
        if _get("quarantine_dir", g):
            globals()["QUARANTINE_DIR"] = Path(str(_get("quarantine_dir", g))).expanduser()
        if _get("file", lg):
            globals()["LOG_FILE"] = str(_get("file", lg))

        # Capture
        if _get("snaplen", c):
            globals()["CAPTURE_SNAPLEN"] = int(_get("snaplen", c))
        if _get("buffer_size", c):
            globals()["CAPTURE_BUFFER_MB"] = max(1, int(_get("buffer_size", c)) // _MB)
        if _get("promiscuous", c) is not None:
            globals()["CAPTURE_PROMISCUOUS"] = bool(_get("promiscuous", c))
        if _get("packet_queue_size", c):
            globals()["LIVE_PACKET_QUEUE_SIZE"] = int(_get("packet_queue_size", c))
        if _get("capture_filter", c) is not None:
            globals()["CAPTURE_FILTER_DEFAULT"] = str(_get("capture_filter", c))

        # DNS
        if _get("entropy_threshold", d):
            globals()["DNS_ENTROPY_THRESHOLD"] = float(_get("entropy_threshold", d))
        if _get("dga_min_label_length", d):
            globals()["DNS_DGA_MIN_LABEL_LENGTH"] = int(_get("dga_min_label_length", d))
        if _get("high_volume_threshold", d):
            globals()["DNS_HIGH_VOLUME_THRESHOLD"] = int(_get("high_volume_threshold", d))
        if _get("tunnel_size_threshold", d):
            globals()["DNS_TUNNEL_SIZE_THRESHOLD"] = int(_get("tunnel_size_threshold", d))

        # Behavioral
        if _get("sequence_window", b):
            globals()["BEHAVIOR_SEQUENCE_WINDOW"] = float(_get("sequence_window", b))
        if _get("suspicious_threshold", b):
            globals()["BEHAVIOR_SUSPICIOUS_THRESHOLD"] = float(_get("suspicious_threshold", b))
        if _get("malicious_threshold", b):
            globals()["BEHAVIOR_MALICIOUS_THRESHOLD"] = float(_get("malicious_threshold", b))
        if _get("critical_threshold", b):
            globals()["BEHAVIOR_CRITICAL_THRESHOLD"] = float(_get("critical_threshold", b))

        # Process monitor
        if _get("poll_interval", p):
            globals()["PROCESS_POLL_INTERVAL"] = float(_get("poll_interval", p))
        if _get("high_cpu_threshold", p):
            globals()["PROCESS_CPU_SUSPICIOUS"] = float(_get("high_cpu_threshold", p))
        if _get("high_memory_threshold", p):
            globals()["PROCESS_MEMORY_SUSPICIOUS_MB"] = max(1, int(_get("high_memory_threshold", p)) // _MB)

        # File monitor
        if _get("poll_interval", fo):
            globals()["FILE_MONITOR_INTERVAL"] = float(_get("poll_interval", fo))

        # Alerts
        if _get("dedup_window", a):
            globals()["ALERT_DEDUP_WINDOW"] = float(_get("dedup_window", a))
        if _get("max_alerts_per_minute", a):
            globals()["ALERT_MAX_PER_MINUTE"] = int(_get("max_alerts_per_minute", a))
        if _get("auto_correlate", a) is not None:
            globals()["ALERT_AUTO_CORRELATE"] = bool(_get("auto_correlate", a))
        if _get("correlation_window", a):
            globals()["ALERT_CORRELATION_WINDOW"] = float(_get("correlation_window", a))

        # Response
        if _get("dry_run_default", r) is not None:
            globals()["RESPONSE_DRY_RUN_DEFAULT"] = bool(_get("dry_run_default", r))
        if _get("require_confirmation", r) is not None:
            globals()["RESPONSE_REQUIRE_CONFIRMATION"] = bool(_get("require_confirmation", r))
        if _get("max_auto_blocks", r):
            globals()["RESPONSE_MAX_AUTO_BLOCKS"] = int(_get("max_auto_blocks", r))
        if _get("cooldown_period", r):
            globals()["RESPONSE_COOLDOWN_PERIOD"] = int(_get("cooldown_period", r))

        # Damage assessment
        if _get("critical_score", da):
            globals()["DAMAGE_SCORE_CRITICAL"] = float(_get("critical_score", da))
        if _get("high_score", da):
            globals()["DAMAGE_SCORE_HIGH"] = float(_get("high_score", da))
        if _get("medium_score", da):
            globals()["DAMAGE_SCORE_MEDIUM"] = float(_get("medium_score", da))

        # ML
        if _get("model_path", ml):
            globals()["ML_MODEL_PATH"] = Path(str(_get("model_path", ml))).expanduser()
        if _get("anomaly_contamination", ml):
            globals()["ML_ANOMALY_CONTAMINATION"] = float(_get("anomaly_contamination", ml))
        if _get("confidence_threshold", ml):
            globals()["ML_CONFIDENCE_THRESHOLD"] = float(_get("confidence_threshold", ml))

        # YARA
        if _get("rules_dir", ya):
            globals()["YARA_RULES_DIR"] = Path(str(_get("rules_dir", ya))).expanduser()
        if _get("scan_timeout", ya):
            globals()["YARA_SCAN_TIMEOUT"] = int(_get("scan_timeout", ya))

        # LLM
        if _get("enabled", llm) is not None:
            globals()["LLM_ENABLED"] = bool(_get("enabled", llm))
        if _get("model", llm):
            globals()["LLM_MODEL"] = str(_get("model", llm))
        if _get("ollama_url", llm):
            globals()["OLLAMA_URL"] = str(_get("ollama_url", llm))
        if _get("temperature", llm):
            globals()["LLM_TEMPERATURE"] = float(_get("temperature", llm))
        if _get("max_tokens", llm):
            globals()["LLM_MAX_TOKENS"] = int(_get("max_tokens", llm))

        # SIEM (Elasticsearch)
        if _get("enabled", siem) is not None:
            globals()["SIEM_ELASTICSEARCH_ENABLED"] = bool(_get("enabled", siem))
        if _get("hosts", siem):
            globals()["SIEM_ELASTICSEARCH_HOSTS"] = [str(h) for h in siem["hosts"]]
        if _get("index_prefix", siem):
            globals()["SIEM_ELASTICSEARCH_INDEX_PREFIX"] = str(_get("index_prefix", siem))

        # SIEM (Splunk HEC)
        if _get("enabled", splunk) is not None:
            globals()["SIEM_SPLUNK_ENABLED"] = bool(_get("enabled", splunk))
        if _get("hec_url", splunk):
            globals()["SIEM_SPLUNK_HEC_URL"] = str(_get("hec_url", splunk))
        if _get("hec_token", splunk):
            globals()["SIEM_SPLUNK_HEC_TOKEN"] = str(_get("hec_token", splunk))
        if _get("source", splunk):
            globals()["SIEM_SPLUNK_SOURCE"] = str(_get("source", splunk))

        # Reporting
        if _get("classification", rep):
            globals()["DEFAULT_CLASSIFICATION"] = str(_get("classification", rep))

        globals()["USER_CONFIG_PATH"] = path
        return path


load_user_config()
