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
QUARANTINE_DIR = PROJECT_ROOT / "quarantine"
PLAYBOOK_DIR = PROJECT_ROOT / "playbooks"
DATA_DIR = PROJECT_ROOT / "data"
TEMP_DIR = Path(os.environ.get("PCAPANALYZER_TEMP", Path.cwd() / "pcapanalyzer_tmp"))
DEFAULT_OUTPUT_DIR = Path(os.environ.get("PCAPANALYZER_OUTPUT", Path.cwd() / "pcapanalyzer_output"))

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
