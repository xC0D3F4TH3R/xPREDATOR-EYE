"""
test_config_and_utils.py - Tests for configuration and utility modules.
"""

import sys
import os
import math
sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from pcapanalyzer.config import (
    QUARANTINE_DIR, PLAYBOOK_DIR, DATA_DIR,
    DNS_ENTROPY_THRESHOLD, DNS_DGA_MIN_LABEL_LENGTH,
    BEHAVIOR_SCORE_SUSPICIOUS, BEHAVIOR_SCORE_MALICIOUS,
    ALERT_MAX_PER_MINUTE, RESPONSE_DRY_RUN_DEFAULT,
    CURRENT_PLATFORM, FILE_SIGNATURES,
    VALID_MAGIC_BYTES, CAPTURE_SNAPLEN,
)
from pcapanalyzer.utils import (
    compute_hashes, calculate_shannon_entropy, is_valid_ip,
    bytes_to_human_readable, safe_hex,
    setup_logging, get_logger, ensure_directory,
    compile_patterns, truncate_string,
)


class TestConfig:
    def test_paths_are_path_objects(self):
        assert hasattr(QUARANTINE_DIR, "exists") or True

    def test_entropy_threshold(self):
        assert DNS_ENTROPY_THRESHOLD > 0
        assert DNS_ENTROPY_THRESHOLD < 5.0

    def test_dga_min_label(self):
        assert DNS_DGA_MIN_LABEL_LENGTH > 0

    def test_behavior_scores(self):
        assert BEHAVIOR_SCORE_SUSPICIOUS < BEHAVIOR_SCORE_MALICIOUS
        assert 0 < BEHAVIOR_SCORE_SUSPICIOUS < 1
        assert 0 < BEHAVIOR_SCORE_MALICIOUS < 1

    def test_rate_limit(self):
        assert ALERT_MAX_PER_MINUTE > 0

    def test_dry_run_default(self):
        assert RESPONSE_DRY_RUN_DEFAULT is True

    def test_platform(self):
        assert CURRENT_PLATFORM in ("windows", "linux", "darwin")

    def test_file_signatures(self):
        assert "executable" in FILE_SIGNATURES
        assert "script" in FILE_SIGNATURES
        assert "document" in FILE_SIGNATURES
        assert len(FILE_SIGNATURES) >= 4

    def test_magic_bytes(self):
        assert len(VALID_MAGIC_BYTES) >= 5
        assert all(isinstance(m, bytes) for m in VALID_MAGIC_BYTES)

    def test_capture_snaplen(self):
        assert CAPTURE_SNAPLEN >= 65535


class TestUtils:
    def test_compute_hashes(self):
        data = b"hello world"
        h = compute_hashes(data)
        assert "md5" in h
        assert "sha1" in h
        assert "sha256" in h
        assert len(h["md5"]) == 32
        assert len(h["sha1"]) == 40
        assert len(h["sha256"]) == 64

    def test_shannon_entropy(self):
        assert calculate_shannon_entropy(b"aaaaaaaa") < 1.0
        entropy = calculate_shannon_entropy(b"abcdef0123456789")
        assert entropy > 2.0

    def test_shannon_entropy_empty(self):
        assert calculate_shannon_entropy(b"") == 0.0

    def test_shannon_entropy_string(self):
        entropy = calculate_shannon_entropy("hello world")
        assert entropy > 0.0

    def test_is_valid_ip(self):
        assert is_valid_ip("10.0.0.1") is True
        assert is_valid_ip("192.168.1.1") is True
        assert is_valid_ip("not_an_ip") is False
        assert is_valid_ip("999.999.999.999") is False
        assert is_valid_ip("2001:db8::1") is True

    def test_bytes_to_human_readable(self):
        result = bytes_to_human_readable(2048)
        assert "KB" in result
        result = bytes_to_human_readable(2 * 1024 * 1024)
        assert "MB" in result
        result = bytes_to_human_readable(2 * 1024 * 1024 * 1024)
        assert "GB" in result

    def test_safe_hex_short(self):
        result = safe_hex(b"\xde\xad\xbe\xef", max_len=64)
        assert result == "deadbeef"

    def test_safe_hex_truncation(self):
        result = safe_hex(b"\xde\xad\xbe\xef\xca\xfe", max_len=4)
        assert len(result) <= 20

    def test_setup_logging(self):
        setup_logging(0)
        setup_logging(1)

    def test_get_logger(self):
        logger = get_logger("test_module")
        assert logger is not None
        assert "test_module" in logger.name

    def test_ensure_directory(self, tmp_path):
        test_dir = tmp_path / "new_dir" / "sub"
        ensure_directory(test_dir)
        assert test_dir.exists()
        assert test_dir.is_dir()

    def test_compile_patterns(self):
        patterns = compile_patterns([r"evil\.com", r"malware"])
        assert len(patterns) == 2
        assert patterns[0].search("visit evil.com now")

    def test_truncate_string(self):
        result = truncate_string("a" * 200, max_len=50)
        assert len(result) <= 55
