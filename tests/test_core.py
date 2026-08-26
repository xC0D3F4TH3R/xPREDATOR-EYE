"""
test_core.py - Tests for alert system, response engine, and orchestration.
"""

import sys
import os
from datetime import datetime
from pathlib import Path
sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from pcapanalyzer.core.alert_system import AlertSystem
from pcapanalyzer.response.response_engine import ResponseEngine
from pcapanalyzer.models import (
    Alert, AlertPriority, Severity, BehaviorPattern,
    IntelMatch, IOC, IOCType, KillChainPhase, MITRETactic,
    DamageAssessment, ResponsePlan, Platform,
)


class TestAlertSystem:
    def setup_method(self):
        self.alert_sys = AlertSystem()

    def test_init(self):
        assert self.alert_sys.alert_count == 0

    def test_raise_alert(self):
        alert = Alert(title="Test Alert", severity=Severity.HIGH,
                       priority=AlertPriority.ERROR, src_ip="10.0.0.1")
        result = self.alert_sys.raise_alert(alert)
        assert result is not None
        assert self.alert_sys.alert_count == 1

    def test_dedup(self):
        alert = Alert(title="Dup Alert", severity=Severity.HIGH,
                       priority=AlertPriority.ERROR, src_ip="10.0.0.1", dst_ip="8.8.8.8")
        self.alert_sys.raise_alert(alert)
        alert2 = Alert(title="Dup Alert", severity=Severity.HIGH,
                        priority=AlertPriority.ERROR, src_ip="10.0.0.1", dst_ip="8.8.8.8")
        result = self.alert_sys.raise_alert(alert2)
        assert result is None

    def test_alert_from_pattern(self):
        pattern = BehaviorPattern(
            name="Test Pattern",
            description="Test",
            severity=Severity.HIGH,
            confidence=0.8,
            kill_chain_phases=[KillChainPhase.COMMAND_AND_CONTROL],
            techniques=["T1071"],
        )
        alert = self.alert_sys.alert_from_pattern(pattern, host="test-host")
        assert alert.title == "Test Pattern"
        assert alert.severity == Severity.HIGH
        assert alert.host == "test-host"

    def test_alert_from_intel_match(self):
        ioc = IOC(value="evil.com", ioc_type=IOCType.DOMAIN, severity=Severity.HIGH)
        match = IntelMatch(ioc=ioc, matched=True, threat_name="Cobalt Strike",
                            details="Known C2 domain", source="vt")
        alert = self.alert_sys.alert_from_intel_match(match)
        assert "evil.com" in alert.iocs
        assert alert.severity == Severity.HIGH

    def test_correlate(self):
        for i in range(3):
            alert = Alert(title=f"Cluster test {i}", severity=Severity.HIGH,
                           priority=AlertPriority.ERROR, src_ip="10.0.0.1")
            self.alert_sys.raise_alert(alert)
        groups = self.alert_sys.correlate()
        assert len(groups) >= 1

    def test_callbacks(self):
        received = []
        self.alert_sys.register_callback(lambda a: received.append(a))
        alert = Alert(title="Callback test", severity=Severity.LOW)
        self.alert_sys.raise_alert(alert)
        assert len(received) == 1

    def test_get_alerts_min_priority(self):
        self.alert_sys.raise_alert(Alert(title="Low", severity=Severity.LOW,
                                          priority=AlertPriority.NOTICE))
        self.alert_sys.raise_alert(Alert(title="High", severity=Severity.HIGH,
                                          priority=AlertPriority.ERROR))
        high_alerts = self.alert_sys.get_alerts(min_priority=AlertPriority.ERROR)
        assert len(high_alerts) == 1

    def test_critical_count(self):
        self.alert_sys.raise_alert(Alert(title="Crit", severity=Severity.CRITICAL))
        assert self.alert_sys.critical_count == 1


class TestResponseEngine:
    def setup_method(self):
        self.engine = ResponseEngine(dry_run=True)

    def test_init(self):
        assert self.engine.dry_run is True

    def test_generate_plan_empty(self):
        plan = self.engine.generate_plan(alerts=[], assessment=None)
        assert plan is not None
        assert len(plan.commands) == 0

    def test_generate_plan_with_critical_alerts(self):
        alerts = [
            Alert(title="Suspicious Process + Network", severity=Severity.CRITICAL,
                   priority=AlertPriority.CRITICAL, src_ip="10.0.0.1",
                   dst_ip="185.234.72.18", process_name="malware.exe"),
            Alert(title="C2 Communication", severity=Severity.HIGH,
                   priority=AlertPriority.ERROR, src_ip="10.0.0.1",
                   dst_ip="185.234.72.18"),
        ]
        plan = self.engine.generate_plan(alerts=alerts, assessment=None)
        assert len(plan.commands) > 0

    def test_generate_plan_with_damage(self):
        damage = DamageAssessment(
            overall_score=85.0,
            severity=Severity.HIGH,
            compromised_hosts=["10.0.0.1", "10.0.0.2"],
        )
        alerts = [
            Alert(title="Lateral Movement", severity=Severity.CRITICAL),
        ]
        plan = self.engine.generate_plan(alerts=alerts, assessment=damage)
        assert len(plan.commands) > 0
        assert plan.severity.numeric >= Severity.HIGH.numeric

    def test_has_playbooks(self):
        assert len(self.engine._playbooks) >= 4
