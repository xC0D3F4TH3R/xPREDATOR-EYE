"""
test_intelligence.py - Tests for intelligence engine, blocklist, and IOC extraction.
"""

import sys
import os
import json
from pathlib import Path
sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from pcapanalyzer.intelligence import IntelligenceEngine, LocalBlocklist
from pcapanalyzer.models import (
    DNSQuery, HTTPRequest, TLSMetadata, CarvedFile, CredentialArtifact,
    IOC, IOCType, Severity, FileType, Protocol,
)


class TestLocalBlocklist:
    def test_init(self):
        bl = LocalBlocklist()
        assert bl is not None
        assert len(bl.ips) == 0

    def test_load_from_file(self, tmp_path):
        bl = LocalBlocklist()
        bl_file = tmp_path / "test_blocklist.json"
        bl_file.write_text(json.dumps({
            "ips": ["1.2.3.4"],
            "domains": ["evil.com"],
            "md5_hashes": ["abc123"],
            "sha256_hashes": [],
            "ja3_hashes": [],
        }))
        bl.load_from_file(bl_file)
        assert "1.2.3.4" in bl.ips
        assert "evil.com" in bl.domains
        assert "abc123" in bl.md5_hashes

    def test_direct_set_manipulation(self):
        bl = LocalBlocklist()
        bl.ips.add("10.0.0.99")
        bl.domains.add("malware.com")
        assert "10.0.0.99" in bl.ips
        assert "malware.com" in bl.domains
        assert "10.0.0.1" not in bl.ips

    def test_load_nonexistent_file(self):
        bl = LocalBlocklist()
        bl.load_from_file(Path("/nonexistent/file.json"))
        assert len(bl.ips) == 0

    def test_load_default_blocklist(self):
        bl = LocalBlocklist()
        default_path = Path(__file__).resolve().parent.parent / "data" / "default_blocklist.json"
        if default_path.exists():
            bl.load_from_file(default_path)
            assert len(bl.ips) > 0 or len(bl.domains) > 0


class TestIntelligenceEngine:
    def test_init(self):
        engine = IntelligenceEngine()
        assert engine is not None

    def test_load_blocklist(self, tmp_path):
        bl_file = tmp_path / "test_blocklist.json"
        bl_file.write_text(json.dumps({
            "ips": ["192.168.1.100"],
            "domains": ["test-bad.com"],
            "md5_hashes": [],
            "sha256_hashes": [],
            "ja3_hashes": [],
        }))
        engine = IntelligenceEngine()
        engine.load_blocklist(bl_file)
        assert engine.blocklist is not None

    def test_extract_iocs_from_dns(self):
        engine = IntelligenceEngine()
        queries = [
            DNSQuery(query_name="evil.com", query_type="A", src_ip="10.0.0.1",
                      possible_dga=True),
            DNSQuery(query_name="safe.google.com", query_type="A"),
        ]
        engine.extract_iocs(dns_queries=queries)
        assert len(engine._all_iocs) > 0

    def test_extract_iocs_from_http(self):
        engine = IntelligenceEngine()
        requests = [
            HTTPRequest(method="GET", uri="/malware", host="evil.com",
                         user_agent="malicious-bot/1.0", src_ip="10.0.0.1"),
        ]
        engine.extract_iocs(http_requests=requests)
        assert len(engine._all_iocs) > 0

    def test_extract_iocs_from_tls(self):
        engine = IntelligenceEngine()
        sessions = [
            TLSMetadata(sni="malware.com", ja3="abc123def", src_ip="10.0.0.1"),
        ]
        engine.extract_iocs(tls_sessions=sessions)
        assert len(engine._all_iocs) > 0

    def test_extract_iocs_from_files(self):
        engine = IntelligenceEngine()
        files = [
            CarvedFile(filename="bad.exe", file_type=FileType.EXECUTABLE,
                        size=1024, md5="abc123", sha256="def456"),
        ]
        engine.extract_iocs(carved_files=files)
        assert len(engine._all_iocs) > 0

    def test_match_local_no_blocklist(self):
        engine = IntelligenceEngine()
        engine._all_iocs.append(
            IOC(value="10.0.0.1", ioc_type=IOCType.IP, severity=Severity.LOW)
        )
        matches = engine.match_local()
        assert isinstance(matches, list)

    def test_match_local_with_blocklist(self, tmp_path):
        bl_file = tmp_path / "bl.json"
        bl_file.write_text(json.dumps({
            "ips": ["10.0.0.1"],
            "domains": ["evil.com"],
            "md5_hashes": [],
            "sha256_hashes": [],
            "ja3_hashes": [],
        }))
        engine = IntelligenceEngine()
        engine.load_blocklist(bl_file)
        engine._all_iocs.extend([
            IOC(value="10.0.0.1", ioc_type=IOCType.IP),
            IOC(value="safe.com", ioc_type=IOCType.DOMAIN),
            IOC(value="evil.com", ioc_type=IOCType.DOMAIN),
        ])
        matches = engine.match_local()
        assert len(matches) >= 2
