"""
test_models.py - Tests for the complete data model layer.
"""

import sys
import os
sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from datetime import datetime
from pcapanalyzer.models import (
    FlowTuple, FlowMetadata, LivePacket, DNSQuery, HTTPRequest,
    TLSMetadata, CredentialArtifact, ProcessSnapshot, FileChange,
    SystemEvent, BehaviorEvent, BehaviorPattern, BehavioralProfile,
    ThreatActor, CampaignProfile, DamageAssessment, DamageVector,
    LateralMovement, DataExfiltration, IOC, IntelMatch, Alert,
    AlertGroup, ResponseCommand, Playbook, ResponsePlan, CarvedFile,
    PcapMetadata, MonitorSession, AnalysisResult, Severity,
    KillChainPhase, MITRETactic, AlertPriority, ResponseAction,
    Platform, Protocol, FileType, IOCType,
    SuiteError, IngestionError, ParseError, ExtractionError,
    IntelligenceError, CaptureError, MonitorError, ResponseError,
)


class TestFlowTuple:
    def test_creation(self):
        ft = FlowTuple("10.0.0.1", "10.0.0.2", 12345, 443, 6)
        assert ft.src_ip == "10.0.0.1"
        assert ft.dst_port == 443
        assert ft.protocol == 6

    def test_str(self):
        ft = FlowTuple("10.0.0.1", "10.0.0.2", 12345, 443, 6)
        s = str(ft)
        assert "10.0.0.1" in s
        assert "443" in s

    def test_reverse(self):
        ft = FlowTuple("10.0.0.1", "10.0.0.2", 12345, 443, 6)
        r = ft.reverse()
        assert r.src_ip == "10.0.0.2"
        assert r.dst_ip == "10.0.0.1"
        assert r.src_port == 443
        assert r.dst_port == 12345

    def test_frozen(self):
        ft = FlowTuple("10.0.0.1", "10.0.0.2", 12345, 443, 6)
        try:
            ft.src_ip = "10.0.0.3"
            assert False, "Should be frozen"
        except AttributeError:
            pass


class TestSeverity:
    def test_ordering(self):
        assert Severity.CRITICAL > Severity.HIGH > Severity.MEDIUM > Severity.LOW > Severity.INFO

    def test_ge(self):
        assert Severity.HIGH >= Severity.MEDIUM
        assert not Severity.LOW >= Severity.HIGH

    def test_numeric(self):
        assert Severity.CRITICAL.numeric == 4
        assert Severity.INFO.numeric == 0


class TestEnums:
    def test_protocol_values(self):
        assert Protocol.HTTP.value == "http"
        assert Protocol.DNS.value == "dns"

    def test_kill_chain_phases(self):
        phases = list(KillChainPhase)
        assert len(phases) == 7
        assert KillChainPhase.RECONNAISSANCE.value == "reconnaissance"
        assert KillChainPhase.ACTIONS_ON_OBJECTIVES.value == "actions_on_objectives"

    def test_mitre_tactics(self):
        assert MITRETactic.C2.value == "TA0011"
        assert MITRETactic.EXFILTRATION.value == "TA0010"

    def test_alert_priority_ordering(self):
        assert AlertPriority.EMERGENCY.value > AlertPriority.CRITICAL.value
        assert AlertPriority.DEBUG.value == 0

    def test_platform_values(self):
        assert Platform.WINDOWS.value == "windows"
        assert Platform.LINUX.value == "linux"
        assert Platform.MACOS.value == "macos"


class TestExceptions:
    def test_hierarchy(self):
        assert issubclass(IngestionError, SuiteError)
        assert issubclass(ParseError, SuiteError)
        assert issubclass(ExtractionError, SuiteError)
        assert issubclass(IntelligenceError, SuiteError)
        assert issubclass(CaptureError, SuiteError)
        assert issubclass(MonitorError, SuiteError)
        assert issubclass(ResponseError, SuiteError)

    def test_raise_catch(self):
        try:
            raise IngestionError("test")
        except SuiteError as e:
            assert "test" in str(e)


class TestDNSQuery:
    def test_creation(self):
        dq = DNSQuery(query_name="evil.com", query_type="A", src_ip="10.0.0.1")
        assert dq.query_name == "evil.com"
        assert dq.query_type == "A"
        assert dq.possible_dga is False

    def test_dga_flag(self):
        dq = DNSQuery(query_name="xjkqzmwoap.blogspot.com", query_type="A",
                       high_entropy=True, possible_dga=True)
        assert dq.possible_dga is True
        assert dq.high_entropy is True


class TestHTTPRequest:
    def test_creation(self):
        hr = HTTPRequest(method="GET", uri="/index.html", host="example.com",
                         user_agent="Mozilla/5.0")
        assert hr.method == "GET"
        assert hr.host == "example.com"


class TestTLSMetadata:
    def test_creation(self):
        tm = TLSMetadata(sni="example.com", ja3="abc123", version="TLSv1.3")
        assert tm.sni == "example.com"
        assert tm.ja3 == "abc123"


class TestCredentialArtifact:
    def test_creation(self):
        ca = CredentialArtifact(protocol=Protocol.HTTP, username="admin",
                                 password="secret123")
        assert ca.username == "admin"
        assert ca.protocol == Protocol.HTTP


class TestProcessSnapshot:
    def test_creation(self):
        ps = ProcessSnapshot(pid=1234, name="suspicious.exe",
                              cpu_percent=95.0, memory_rss=500_000_000)
        assert ps.pid == 1234
        assert ps.cpu_percent == 95.0

    def test_anomaly_flags(self):
        ps = ProcessSnapshot(pid=1, name="test", anomaly_flags=["HIGH_CPU", "UNUSUAL_PATH"])
        assert len(ps.anomaly_flags) == 2


class TestBehaviorEvent:
    def test_creation(self):
        be = BehaviorEvent(event_type="network_connect", src_ip="10.0.0.1",
                            dst_ip="185.234.72.18", dst_port=443,
                            mitre_tactic=MITRETactic.C2)
        assert be.event_type == "network_connect"
        assert be.mitre_tactic == MITRETactic.C2

    def test_unique_id(self):
        be1 = BehaviorEvent(event_type="test")
        be2 = BehaviorEvent(event_type="test")
        assert be1.event_id != be2.event_id


class TestThreatActor:
    def test_creation(self):
        ta = ThreatActor(aliases=["APT28", "Fancy Bear"],
                          motivation="espionage",
                          sophistication="expert")
        assert "APT28" in ta.aliases
        assert ta.sophistication == "expert"

    def test_unique_id(self):
        ta1 = ThreatActor()
        ta2 = ThreatActor()
        assert ta1.actor_id != ta2.actor_id


class TestDamageAssessment:
    def test_creation(self):
        da = DamageAssessment(overall_score=75.0, severity=Severity.HIGH,
                               blast_radius=5)
        assert da.overall_score == 75.0
        assert da.blast_radius == 5


class TestAlert:
    def test_creation(self):
        alert = Alert(title="Test Alert", severity=Severity.HIGH,
                       priority=AlertPriority.ERROR)
        assert alert.title == "Test Alert"
        assert alert.severity == Severity.HIGH
        assert alert.priority == AlertPriority.ERROR

    def test_unique_id(self):
        a1 = Alert(title="A")
        a2 = Alert(title="A")
        assert a1.alert_id != a2.alert_id


class TestResponseCommand:
    def test_creation(self):
        rc = ResponseCommand(action=ResponseAction.BLOCK_IP,
                              command_str="netsh advfirewall ...",
                              platform=Platform.WINDOWS)
        assert rc.action == ResponseAction.BLOCK_IP
        assert rc.platform == Platform.WINDOWS


class TestCarvedFile:
    def test_creation(self):
        cf = CarvedFile(filename="carved_0001.bin", file_type=FileType.EXECUTABLE,
                          size=1024, md5="abc", sha256="def")
        assert cf.filename == "carved_0001.bin"
        assert cf.size == 1024


class TestAnalysisResult:
    def test_creation(self):
        ar = AnalysisResult()
        assert ar.flows == []
        assert ar.alerts == []
        assert ar.threat_actors == []

    def test_summary_dict(self):
        ar = AnalysisResult()
        d = ar.summary_dict()
        assert "flow_count" in d
        assert "alert_count" in d
        assert d["flow_count"] == 0

    def test_with_pcap_metadata(self):
        pm = PcapMetadata(filename="test.pcap", file_size=1024,
                            packet_count=100, capture_duration=5.0,
                            link_type="LINKTYPE_ETHERNET")
        ar = AnalysisResult(pcap_metadata=pm)
        d = ar.summary_dict()
        assert d["pcap_summary"] is not None
        assert d["pcap_summary"]["filename"] == "test.pcap"
        assert d["flow_count"] == 0
