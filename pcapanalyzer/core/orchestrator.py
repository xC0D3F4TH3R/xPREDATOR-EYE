"""
orchestrator.py - Master pipeline connecting all engines.

The central coordinator that wires live capture, process/file monitoring,
behavioral analysis, threat actor profiling, damage assessment, alerting,
intelligence matching, and response generation into a unified pipeline.
"""

from __future__ import annotations

import time
from datetime import datetime
from pathlib import Path
from typing import Optional

from .. import config
from ..models import (
    AnalysisResult, Alert, BehaviorEvent, MonitorSession, Platform,
    Severity, ResponsePlan,
)
from ..utils import get_logger

logger = get_logger("orchestrator")


class Orchestrator:
    """Master pipeline orchestrator for live monitoring mode.

    Usage::

        orch = Orchestrator(interface="Ethernet")
        orch.start()
        # ... runs until interrupted ...
        orch.stop()
    """

    def __init__(
        self,
        interface: Optional[str] = None,
        capture_filter: str = "",
        watch_paths: Optional[list[str]] = None,
        blocklist_path: Optional[Path] = None,
        dry_run: bool = True,
        output_dir: Optional[Path] = None,
    ) -> None:
        self.interface = interface
        self.capture_filter = capture_filter
        self.watch_paths = watch_paths
        self.blocklist_path = blocklist_path
        self.dry_run = dry_run
        self.output_dir = output_dir or config.DEFAULT_OUTPUT_DIR

        self._result = AnalysisResult(analysis_start=datetime.now())
        self._monitor_session = MonitorSession(
            platform=Platform.ANY,
            started_at=datetime.now(),
            interfaces=[interface] if interface else [],
        )
        self._result.monitor_session = self._monitor_session

        # Lazy-init engines
        self._capture_engine = None
        self._process_monitor = None
        self._file_monitor = None
        self._behavior_engine = None
        self._threat_profiler = None
        self._damage_assessor = None
        self._alert_system = None
        self._response_engine = None
        self._intelligence = None
        self._dashboard = None

        self._running = False

    def _init_engines(self) -> None:
        """Initialize all sub-engines."""
        from ..capture.live_capture import LiveCaptureEngine
        from ..capture.process_monitor import ProcessMonitor
        from ..capture.file_monitor import FileMonitor
        from ..analysis.behavior_engine import BehaviorEngine
        from ..analysis.threat_actor import ThreatActorProfiler
        from ..analysis.damage_assessor import DamageAssessor
        from ..analysis.behavior_engine import BehaviorEngine
        from ..core.alert_system import AlertSystem
        from ..response.response_engine import ResponseEngine
        from ..intelligence import IntelligenceEngine
        from ..ui.dashboard import LiveDashboard

        self._capture_engine = LiveCaptureEngine(
            interface=self.interface,
            capture_filter=self.capture_filter,
        )
        self._process_monitor = ProcessMonitor()
        self._file_monitor = FileMonitor()
        self._behavior_engine = BehaviorEngine()
        self._threat_profiler = ThreatActorProfiler()
        self._damage_assessor = DamageAssessor()
        self._alert_system = AlertSystem(output_dir=self.output_dir)
        self._response_engine = ResponseEngine(dry_run=self.dry_run)
        self._intelligence = IntelligenceEngine()
        self._dashboard = LiveDashboard()

        if self.blocklist_path and self.blocklist_path.exists():
            self._intelligence.load_blocklist(self.blocklist_path)

        # Wire alert callbacks
        self._alert_system.register_callback(self._on_alert)

    def _on_alert(self, alert: Alert) -> None:
        """Callback for new alerts - update dashboard."""
        if self._dashboard:
            self._dashboard.update_alerts(self._alert_system.get_alerts())

    def start(self) -> None:
        """Start all monitoring engines."""
        logger.info("=" * 70)
        logger.info("  PcapMalAnalyzer - Live Threat Intelligence Suite")
        logger.info("=" * 70)

        self._init_engines()
        self._running = True

        # Start subsystems
        self._process_monitor.start()
        self._file_monitor.start()
        self._dashboard.start()

        if self.watch_paths:
            for p in self.watch_paths:
                self._file_monitor.add_watch_path(p)

        # Start capture (may fail if tshark unavailable)
        try:
            self._capture_engine.start(filter=self.capture_filter)
            logger.info("Live capture active on %s", self.interface or "default interface")
        except Exception as exc:
            logger.warning("Live capture unavailable: %s", exc)
            logger.info("Continuing with process and file monitoring only")

        logger.info("All engines active. Monitoring... (Ctrl+C to stop)")

        # Main monitoring loop
        try:
            self._monitoring_loop()
        except KeyboardInterrupt:
            logger.info("Interrupted by user")
        finally:
            self.stop()

    def _monitoring_loop(self) -> None:
        """Core loop: consume events from all sources, analyze, alert."""
        analysis_interval = 10.0  # seconds between full analysis cycles
        last_analysis = 0.0

        while self._running:
            try:
                now = time.monotonic()

                # Consume live packets
                if self._capture_engine and self._capture_engine.is_running:
                    pkt_count = 0
                    for pkt in self._capture_engine.packet_stream(timeout=0.5):
                        self._behavior_engine.ingest_packet(pkt)
                        pkt_count += 1
                        self._monitor_session.packet_count += 1
                    if self._dashboard:
                        self._dashboard.update_packet_count(self._monitor_session.packet_count)

                # Consume process events
                if self._process_monitor:
                    events = self._process_monitor.get_events()
                    for ev in events:
                        self._behavior_engine.ingest_system_event(ev)
                        self._monitor_session.event_count += 1
                    procs = list(self._process_monitor.get_snapshot().values())
                    if self._dashboard:
                        self._dashboard.update_processes(procs)

                # Consume file events
                if self._file_monitor:
                    file_events = self._file_monitor.get_events()
                    for ev in file_events:
                        self._behavior_engine.ingest_system_event(ev)
                        self._monitor_session.event_count += 1
                    changes = self._file_monitor.get_changes()
                    if self._dashboard:
                        self._dashboard.update_file_changes(changes)

                # Periodic full analysis
                if now - last_analysis >= analysis_interval:
                    self._run_analysis_cycle()
                    last_analysis = now

                if self._dashboard:
                    self._dashboard.update_event_count(self._monitor_session.event_count)

            except Exception as exc:
                logger.error("Monitoring loop error: %s", exc)
                time.sleep(1.0)

    def _run_analysis_cycle(self) -> None:
        """Run behavioral analysis, profiling, damage assessment, and alerting."""
        try:
            # 1. Behavioral Analysis
            profile = self._behavior_engine.analyze()
            self._result.behavioral_profile = profile

            if self._dashboard:
                self._dashboard.update_scores(
                    behavioral=profile.behavioral_score,
                )

            # 2. Generate alerts from patterns
            for pattern in profile.patterns:
                alert = self._alert_system.alert_from_pattern(pattern)
                self._alert_system.raise_alert(alert)

            # 3. Threat Actor Profiling
            if profile.patterns:
                actor = self._threat_profiler.profile_from_behavior(profile)
                if actor:
                    self._result.threat_actors = self._threat_profiler.get_actors()

            # 4. Damage Assessment
            assessment = self._damage_assessor.assess(
                profile=profile,
                events=self._behavior_engine._event_window,
                system_events=self._process_monitor.get_events() if self._process_monitor else None,
                process_snapshots=list(self._process_monitor.get_snapshot().values()) if self._process_monitor else None,
            )
            self._result.damage_assessment = assessment

            if self._dashboard:
                self._dashboard.update_scores(
                    behavioral=profile.behavioral_score,
                    damage=assessment.overall_score / 100.0,
                )

            # 5. Generate Response Plan if severity warrants it
            critical_alerts = self._alert_system.get_alerts(min_priority=4)  # ERROR+
            if critical_alerts:
                plan = self._response_engine.generate_plan(
                    critical_alerts, assessment,
                )
                self._result.response_plan = plan
                logger.warning(
                    "Response plan ready: %d commands (dry_run=%s)",
                    len(plan.commands), self._response_engine.dry_run,
                )

        except Exception as exc:
            logger.error("Analysis cycle error: %s", exc)

    def stop(self) -> None:
        """Stop all engines and generate final report."""
        self._running = False
        logger.info("Shutting down all engines...")

        if self._capture_engine:
            self._capture_engine.stop()
        if self._process_monitor:
            self._process_monitor.stop()
        if self._file_monitor:
            self._file_monitor.stop()
        if self._dashboard:
            self._dashboard.stop()

        self._result.analysis_end = datetime.now()
        if self._result.analysis_start:
            self._result.elapsed_seconds = (
                self._result.analysis_end - self._result.analysis_start
            ).total_seconds()

        # Correlate alerts
        if self._alert_system:
            self._result.alert_groups = self._alert_system.correlate()
            self._result.alerts = self._alert_system.get_alerts()
            self._monitor_session.alert_count = self._alert_system.alert_count

        # Generate final report
        self._generate_final_report()

        logger.info("Orchestrator stopped. Session: %s", self._monitor_session.session_id)

    def _generate_final_report(self) -> None:
        """Write the final JSON report and summary."""
        from ..reporter import generate_json_report
        from ..utils import ensure_directory

        report_dir = self.output_dir / "reports"
        ensure_directory(report_dir)

        ts = datetime.now().strftime("%Y%m%d_%H%M%S")
        json_path = report_dir / f"live_analysis_{ts}.json"

        try:
            generate_json_report(self._result, json_path)
            logger.info("Final report: %s", json_path)
        except Exception as exc:
            logger.error("Report generation failed: %s", exc)

    def get_result(self) -> AnalysisResult:
        return self._result
