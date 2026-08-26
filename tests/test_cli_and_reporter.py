"""
test_cli_and_reporter.py - Tests for CLI parser and reporter.
"""

import sys
import os
import json
from pathlib import Path
sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from pcapanalyzer.cli import build_parser
from pcapanalyzer.reporter import generate_json_report
from pcapanalyzer.models import (
    AnalysisResult, PcapMetadata, Severity, Alert, AlertPriority,
    DNSQuery, HTTPRequest, TLSMetadata, CarvedFile, IntelMatch,
    IOC, IOCType, FileType, BehavioralProfile, ThreatActor, DamageAssessment,
)


class TestCLIParser:
    def test_build_parser(self):
        parser = build_parser()
        assert parser is not None

    def test_live_mode_args(self):
        parser = build_parser()
        args = parser.parse_args(["live"])
        assert args.mode == "live"

    def test_live_mode_interface(self):
        parser = build_parser()
        args = parser.parse_args(["live", "--interface", "Ethernet"])
        assert args.interface == "Ethernet"

    def test_live_mode_filter(self):
        parser = build_parser()
        args = parser.parse_args(["live", "-f", "tcp port 443"])
        assert args.filter == "tcp port 443"

    def test_live_mode_respond(self):
        parser = build_parser()
        args = parser.parse_args(["live", "--respond"])
        assert args.respond is True

    def test_live_mode_duration(self):
        parser = build_parser()
        args = parser.parse_args(["live", "--duration", "300"])
        assert args.duration == 300

    def test_live_mode_interfaces(self):
        parser = build_parser()
        args = parser.parse_args(["live", "--interfaces"])
        assert args.interfaces is True

    def test_analyze_mode(self):
        parser = build_parser()
        args = parser.parse_args(["analyze", "capture.pcap"])
        assert args.mode == "analyze"
        assert args.pcap_file == "capture.pcap"

    def test_analyze_mode_output(self):
        parser = build_parser()
        args = parser.parse_args(["analyze", "test.pcap", "-o", "my_output/"])
        assert args.output_dir == "my_output/"

    def test_analyze_mode_blocklist(self):
        parser = build_parser()
        args = parser.parse_args(["analyze", "test.pcap", "-b", "blocklist.json"])
        assert args.blocklist == "blocklist.json"

    def test_analyze_mode_respond(self):
        parser = build_parser()
        args = parser.parse_args(["analyze", "test.pcap", "--respond"])
        assert args.respond is True

    def test_analyze_mode_json_only(self):
        parser = build_parser()
        args = parser.parse_args(["analyze", "test.pcap", "--json-only"])
        assert args.json_only is True

    def test_verbose_flag(self):
        parser = build_parser()
        args = parser.parse_args(["live", "-v"])
        assert args.verbose is True

    def test_quiet_flag(self):
        parser = build_parser()
        args = parser.parse_args(["analyze", "test.pcap", "-q"])
        assert args.quiet is True

    def test_no_mode_shows_help(self):
        parser = build_parser()
        args = parser.parse_args([])
        assert args.mode is None


class TestReporter:
    def test_generate_json_report(self, tmp_path):
        result = AnalysisResult(
            pcap_metadata=PcapMetadata(
                filename="test.pcap", file_size=1024, packet_count=100,
                capture_duration=5.0, link_type="LINKTYPE_ETHERNET",
            ),
        )
        output = tmp_path / "test_report.json"
        path = generate_json_report(result, output)
        assert path.exists()

        with open(path, "r", encoding="utf-8") as f:
            data = json.load(f)
        assert "report_metadata" in data
        assert data["report_metadata"]["tool"] in ("xPREDATOR-EYE", "PcapMalAnalyzer")
        assert data["pcap_summary"]["filename"] == "test.pcap"

    def test_report_with_alerts(self, tmp_path):
        result = AnalysisResult()
        result.alerts.append(
            Alert(title="Test Alert", severity=Severity.HIGH,
                   priority=AlertPriority.ERROR, src_ip="10.0.0.1")
        )
        output = tmp_path / "alerts_report.json"
        generate_json_report(result, output)

        with open(output, "r", encoding="utf-8") as f:
            data = json.load(f)
        assert len(data["alerts"]) == 1

    def test_report_with_dns(self, tmp_path):
        result = AnalysisResult()
        result.dns_queries.append(
            DNSQuery(query_name="evil.com", query_type="A", src_ip="10.0.0.1",
                      possible_dga=True)
        )
        output = tmp_path / "dns_report.json"
        generate_json_report(result, output)

        with open(output, "r", encoding="utf-8") as f:
            data = json.load(f)
        assert len(data["dns_queries"]) == 1

    def test_report_full(self, tmp_path):
        result = AnalysisResult(
            pcap_metadata=PcapMetadata(
                filename="full.pcap", file_size=5_000_000, packet_count=10000,
                capture_duration=120.0, link_type="LINKTYPE_ETHERNET",
            ),
        )
        result.dns_queries.append(DNSQuery(query_name="evil.com", query_type="A"))
        result.http_requests.append(HTTPRequest(method="GET", uri="/mal", host="evil.com"))
        result.tls_sessions.append(TLSMetadata(sni="evil.com", ja3="abc123"))
        result.alerts.append(Alert(title="Alert", severity=Severity.CRITICAL))
        result.carved_files.append(CarvedFile(filename="bad.exe", file_type=FileType.EXECUTABLE, size=1024))

        output = tmp_path / "full_report.json"
        generate_json_report(result, output)

        with open(output, "r", encoding="utf-8") as f:
            data = json.load(f)
        assert data["flow_count"] == 0
        assert len(data["dns_queries"]) == 1
        assert len(data["http_requests"]) == 1
        assert len(data["tls_sessions"]) == 1
        assert len(data["alerts"]) == 1
        assert len(data["carved_files"]) == 1
