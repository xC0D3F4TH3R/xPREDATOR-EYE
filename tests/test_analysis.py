"""
test_analysis.py - Tests for behavior engine, threat actor profiler, damage assessor.
"""

import sys
import os
from datetime import datetime
sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from pcapanalyzer.analysis.behavior_engine import BehaviorEngine, SEQUENCE_RULES
from pcapanalyzer.analysis.threat_actor import ThreatActorProfiler
from pcapanalyzer.analysis.damage_assessor import DamageAssessor
from pcapanalyzer.models import (
    BehaviorEvent, Severity, KillChainPhase, MITRETactic,
    SystemEvent, FileChange, LivePacket, ProcessSnapshot,
    IntelMatch, IOC, IOCType, BehavioralProfile, BehaviorPattern,
)


class TestBehaviorEngine:
    def setup_method(self):
        self.engine = BehaviorEngine()

    def test_init(self):
        assert self.engine.event_count == 0

    def test_ingest_event(self):
        be = BehaviorEvent(event_type="network_connect",
                            src_ip="10.0.0.1", dst_ip="8.8.8.8", dst_port=443)
        self.engine.ingest_event(be)
        assert self.engine.event_count == 1

    def test_ingest_multiple_events(self):
        for i in range(10):
            be = BehaviorEvent(event_type="network_connect",
                                src_ip=f"10.0.0.{i}", dst_ip="8.8.8.8", dst_port=443)
            self.engine.ingest_event(be)
        assert self.engine.event_count == 10

    def test_ingest_system_event(self):
        se = SystemEvent(event_type="network_connect",
                          details={"src_ip": "10.0.0.1", "dst_ip": "8.8.8.8", "dst_port": 443})
        self.engine.ingest_system_event(se)
        assert self.engine.event_count == 1

    def test_ingest_packet(self):
        pkt = LivePacket(timestamp=1000000.0, src_ip="10.0.0.1", dst_ip="8.8.8.8",
                          src_port=12345, dst_port=443, protocol=6, length=100)
        self.engine.ingest_packet(pkt)
        assert self.engine.event_count == 1

    def test_ingest_dns_packet(self):
        pkt = LivePacket(timestamp=1000000.0, src_ip="10.0.0.1", dst_ip="8.8.8.8",
                          src_port=12345, dst_port=53, protocol=17, length=50,
                          dns_query="evil.com")
        self.engine.ingest_packet(pkt)
        event = self.engine._events[0]
        assert event.event_type == "dns_query"

    def test_ingest_tls_packet(self):
        pkt = LivePacket(timestamp=1000000.0, src_ip="10.0.0.1", dst_ip="8.8.8.8",
                          src_port=12345, dst_port=443, protocol=6, length=100,
                          tls_sni="malware.com")
        self.engine.ingest_packet(pkt)
        event = self.engine._events[0]
        assert event.event_type == "tls_connection"
        assert event.target == "malware.com"

    def test_ingest_http_packet(self):
        pkt = LivePacket(timestamp=1000000.0, src_ip="10.0.0.1", dst_ip="8.8.8.8",
                          src_port=12345, dst_port=80, protocol=6, length=100,
                          http_host="evil.com")
        self.engine.ingest_packet(pkt)
        event = self.engine._events[0]
        assert event.event_type == "http_request"

    def test_ingest_file_change(self):
        fc = FileChange(path="/tmp/malware.exe", change_type="created",
                         size=1024, timestamp=datetime.now())
        self.engine.ingest_file_change(fc)
        assert self.engine.event_count == 1
        event = self.engine._events[0]
        assert event.event_type == "file_created"

    def test_ingest_process_snapshot(self):
        ps = ProcessSnapshot(pid=1234, name="suspicious.exe",
                              cpu_percent=95.0, memory_rss=500_000_000,
                              suspicious_score=0.8, anomaly_flags=["HIGH_CPU"],
                              timestamp=datetime.now())
        self.engine.ingest_process_snapshot(ps)
        assert self.engine.event_count == 1

    def test_analyze_empty(self):
        profile = self.engine.analyze()
        assert profile.behavioral_score == 0.0
        assert profile.patterns == []

    def test_detect_pattern(self):
        self.engine.ingest_event(BehaviorEvent(
            event_type="process_start", source_pid=1234,
            source_process="mal.exe", timestamp=datetime.now()))
        self.engine.ingest_event(BehaviorEvent(
            event_type="network_connect", src_ip="10.0.0.1",
            dst_ip="1.2.3.4", dst_port=443, timestamp=datetime.now()))
        patterns = self.engine.detect_patterns()
        assert len(patterns) >= 1

    def test_analyze_with_events(self):
        self.engine.ingest_event(BehaviorEvent(event_type="process_start", timestamp=datetime.now()))
        self.engine.ingest_event(BehaviorEvent(event_type="network_connect", timestamp=datetime.now()))
        profile = self.engine.analyze()
        assert profile.total_events == 2

    def test_sequence_rules_defined(self):
        assert len(SEQUENCE_RULES) >= 8
        for rule in SEQUENCE_RULES:
            assert "name" in rule
            assert "sequence" in rule
            assert "severity" in rule
            assert "kill_chain" in rule
            assert "mitre" in rule


class TestThreatActorProfiler:
    def setup_method(self):
        self.profiler = ThreatActorProfiler()

    def test_init(self):
        assert len(self.profiler.get_actors()) == 0

    def test_profile_from_behavior_empty(self):
        bp = BehavioralProfile()
        actor = self.profiler.profile_from_behavior(bp)
        assert actor is None

    def test_profile_from_behavior_with_patterns(self):
        bp = BehavioralProfile(
            patterns=[BehaviorPattern(
                name="Test Pattern",
                kill_chain_phases=[KillChainPhase.COMMAND_AND_CONTROL],
                mitre_tactics=[MITRETactic.C2],
                techniques=["T1071"],
            )]
        )
        actor = self.profiler.profile_from_behavior(bp)
        assert actor is not None

    def test_correlate_iocs(self):
        from pcapanalyzer.models import ThreatActor
        ta = ThreatActor(aliases=["APT28"], ttps=["T1071"],
                          motivation="espionage", sophistication="expert")
        self.profiler._actors.append(ta)

        ioc = IOC(value="185.234.72.18", ioc_type=IOCType.IP, severity=Severity.HIGH)
        match = IntelMatch(ioc=ioc, matched=True, threat_name="APT28", confidence=0.8)
        self.profiler.correlate_iocs([match])
        assert len(ta.iocs) > 0
        assert "185.234.72.18" in ta.iocs

    def test_build_campaign(self):
        from pcapanalyzer.models import ThreatActor
        ta = ThreatActor(aliases=["APT28"], ttps=["T1071", "T1003"],
                          motivation="espionage", sophistication="expert")
        self.profiler._actors.append(ta)
        self.profiler.build_campaign()
        campaigns = self.profiler.get_campaigns()
        assert len(campaigns) > 0


class TestDamageAssessor:
    def setup_method(self):
        self.assessor = DamageAssessor()

    def test_assess_empty(self):
        bp = BehavioralProfile()
        result = self.assessor.assess(profile=bp)
        assert result is not None
        assert result.overall_score >= 0

    def test_assess_with_patterns(self):
        bp = BehavioralProfile(
            behavioral_score=0.8,
            patterns=[
                BehaviorPattern(
                    name="Critical Pattern",
                    severity=Severity.CRITICAL,
                    kill_chain_phases=[KillChainPhase.ACTIONS_ON_OBJECTIVES],
                    confidence=1.0,
                ),
            ],
            total_events=100,
        )
        result = self.assessor.assess(profile=bp)
        assert result.overall_score >= 0
        assert result.severity in (Severity.INFO, Severity.LOW, Severity.MEDIUM, Severity.HIGH, Severity.CRITICAL)
        assert len(result.vectors) == 4

    def test_assess_with_events(self):
        events = [
            BehaviorEvent(event_type="credential_access", src_ip="10.0.0.1"),
            BehaviorEvent(event_type="lateral_movement", src_ip="10.0.0.1", dst_ip="10.0.0.2", dst_port=445),
            BehaviorEvent(event_type="data_exfiltration", src_ip="10.0.0.1", dst_ip="185.234.72.18"),
            BehaviorEvent(event_type="file_created", raw_data={"path": "/tmp/stage.zip"}),
        ]
        result = self.assessor.assess(events=events)
        assert result.overall_score > 0
        assert len(result.vectors) == 4
