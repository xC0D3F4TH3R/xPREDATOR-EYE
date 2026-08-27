"""
utils.py - Shared utility functions used across the analysis pipeline.

Provides entropy calculation, safe hashing, regex compilation,
logging setup, and other small helpers.
"""

from __future__ import annotations

import hashlib
import logging
import math
import re
import sys
from collections import Counter
from pathlib import Path
from typing import Optional

from . import config


def setup_logging(level: int = logging.INFO) -> logging.Logger:
    """Configure and return the root logger for the application.

    Args:
        level: Logging verbosity (default: INFO).

    Returns:
        Configured root Logger instance.
    """
    logger = logging.getLogger("pcapanalyzer")
    if not logger.handlers:
        handler = logging.StreamHandler(sys.stderr)
        handler.setFormatter(
            logging.Formatter(config.LOG_FORMAT, datefmt=config.LOG_DATE_FORMAT)
        )
        logger.addHandler(handler)
        if config.LOG_FILE:
            try:
                Path(config.LOG_FILE).parent.mkdir(parents=True, exist_ok=True)
                file_handler = logging.FileHandler(config.LOG_FILE, encoding="utf-8")
                file_handler.setFormatter(
                    logging.Formatter(config.LOG_FORMAT, datefmt=config.LOG_DATE_FORMAT)
                )
                logger.addHandler(file_handler)
            except Exception:
                pass
    logger.setLevel(level)
    return logger


def get_logger(name: str) -> logging.Logger:
    """Return a child logger under the ``pcapanalyzer`` namespace."""
    return logging.getLogger(f"pcapanalyzer.{name}")


def calculate_shannon_entropy(data: bytes | str) -> float:
    """Compute Shannon entropy of the given data.

    Higher entropy (~3.5-4.0 for ASCII) indicates randomness and may
    signal DGA-generated domains or encrypted/encoded payloads.

    Args:
        data: Bytes or string to measure.

    Returns:
        Entropy in bits per character (0.0 for empty input).
    """
    if not data:
        return 0.0
    if isinstance(data, str):
        data = data.encode("utf-8", errors="replace")
    freq = Counter(data)
    length = len(data)
    entropy = 0.0
    for count in freq.values():
        p = count / length
        if p > 0:
            entropy -= p * math.log2(p)
    return entropy


def compute_hashes(data: bytes) -> dict[str, str]:
    """Compute MD5, SHA-1, and SHA-256 digests for the supplied data.

    Args:
        data: Raw bytes to hash.

    Returns:
        Dictionary with keys ``md5``, ``sha1``, ``sha256``.
    """
    return {
        "md5": hashlib.md5(data, usedforsecurity=False).hexdigest(),
        "sha1": hashlib.sha1(data, usedforsecurity=False).hexdigest(),
        "sha256": hashlib.sha256(data, usedforsecurity=False).hexdigest(),
    }


def safe_hex(data: bytes, max_len: int = 64) -> str:
    """Return a safe hex representation, truncating if necessary."""
    h = data.hex()
    if len(h) > max_len:
        return h[:max_len] + "..."
    return h


def is_valid_ip(ip_str: str) -> bool:
    """Check whether a string is a valid IPv4 or IPv6 address."""
    # IPv4
    parts = ip_str.split(".")
    if len(parts) == 4:
        try:
            return all(0 <= int(p) <= 255 for p in parts)
        except ValueError:
            return False
    # IPv6 - basic check
    if ":" in ip_str:
        try:
            import ipaddress
            ipaddress.ip_address(ip_str)
            return True
        except ValueError:
            return False
    return False


def compile_patterns(patterns: list[str], flags: int = re.IGNORECASE) -> list[re.Pattern]:
    """Pre-compile a list of regex pattern strings.

    Args:
        patterns: Raw regex strings.
        flags: Compilation flags.

    Returns:
        List of compiled ``re.Pattern`` objects.
    """
    compiled: list[re.Pattern] = []
    for pat in patterns:
        try:
            compiled.append(re.compile(pat, flags))
        except re.error:
            get_logger("utils").warning("Invalid regex pattern skipped: %s", pat)
    return compiled


def ensure_directory(path: Path) -> Path:
    """Create a directory (and parents) if it does not exist, then return it."""
    path.mkdir(parents=True, exist_ok=True)
    return path


def truncate_string(s: str, max_len: int = 120) -> str:
    """Truncate a string to *max_len* characters, appending ``…`` if needed."""
    if len(s) <= max_len:
        return s
    return s[: max_len - 1] + "…"


def bytes_to_human_readable(size_bytes: int) -> str:
    """Convert a byte count into a human-readable string (e.g., ``1.5 MB``)."""
    for unit in ("B", "KB", "MB", "GB", "TB"):
        if abs(size_bytes) < 1024.0:
            return f"{size_bytes:.1f} {unit}"
        size_bytes /= 1024.0  # type: ignore[assignment]
    return f"{size_bytes:.1f} PB"
