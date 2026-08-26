"""
orchestrator.py - Master pipeline connecting all engines.

The central coordinator that wires live capture, process/file monitoring,
behavioral analysis, threat actor profiling, damage assessment, alerting,
intelligence matching, and response generation into a unified pipeline.
"""

from __future__ import annotations

import platform
import threading
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
        self.watch_paths = watch_paths or []
        self.blocklist_path = blocklist_path
        self.dry_run = dry_run
        self.output_dir = output_dir or config.DEFAULT_OUTPUT_DIR

        self._result = AnalysisResult(analysis_start=datetime.now())

        # Detect platform
        sys_platform = platform.system().lower()
        platform_map = {"windows": Platform.WINDOWS, "linux": Platform.LINUX,
                        "darwin": Platform.MACOS}
        detected = platform_map.get(sys_platform, Platform.ANY)

        self._monitor_session = MonitorSession(
            platform=detected,
            started_at=datetime.now(),
            interfaces=[interface] if interface else [],
        )
        self._result.monitor_session = self._monitor_session

        # Engines - initialized on start()
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
        self._analysis_thread: Optional[threading.Thread] = None

    def _init_engines(self) -> None:
        """Initialize all sub-engines with safe error handling."""
        try:
            from ..capture.live_capture import LiveCaptureEngine
            self._capture_engine = LiveCaptureEngine(
                interface=self.interface,
                capture_filter=self.capture_filter,
                output_dir=self.output_dir / "captures",
            )
            logger.info("LiveCaptureEngine initialized")
        except Exception as exc:
            logger.error("Failed to init LiveCaptureEngine: %s", exc)

        try:
            from ..capture.process_monitor import ProcessMonitor
            self._process_monitor = ProcessMonitor()
            logger.info("ProcessMonitor initialized")
        except Exception as exc:
            logger.error("Failed to init ProcessMonitor: %s", exc)

        try:
            from ..capture.file_monitor import FileMonitor
            self._file_monitor = FileMonitor()
            if self.watch_paths:
                self._file_monitor.set_watch_paths(self.watch_paths)
            else:
                self._file_monitor.load_platform_defaults()
            logger.info("FileMonitor initialized (%d paths)", len(self._file_monitor._watch_paths))
        except Exception as exc:
            logger.error("Failed to init FileMonitor: %s", exc)

        try:
            from ..analysis.behavior_engine import BehaviorEngine
            self._behavior_engine = BehaviorEngine()
            logger.info("BehaviorEngine initialized")
        except Exception as exc:
            logger.error("Failed to init BehaviorEngine: %s", exc)

        try:
            from ..analysis.threat_actor import ThreatActorProfiler
            self._threat_profiler = ThreatActorProfiler()
            logger.info("ThreatActorProfiler initialized")
        except Exception as exc:
            logger.error("Failed to init ThreatActorProfiler: %s", exc)

        try:
            from ..analysis.damage_assessor import DamageAssessor
            self._damage_assessor = DamageAssessor()
            logger.info("DamageAssessor initialized")
        except Exception as exc:
            logger.error("Failed to init DamageAssessor: %s", exc)

        try:
            from ..core.alert_system import AlertSystem
            self._alert_system = AlertSystem(output_dir=self.output_dir)
            logger.info("AlertSystem initialized")
        except Exception as exc:
            logger.error("Failed to init AlertSystem: %s", exc)

        try:
            from ..response.response_engine import ResponseEngine
            self._response_engine = ResponseEngine(dry_run=self.dry_run)
            logger.info("ResponseEngine initialized")
        except Exception as exc:
            logger.error("Failed to init ResponseEngine: %s", exc)

        try:
            from ..intelligence import IntelligenceEngine
            self._intelligence = IntelligenceEngine()
            if self.blocklist_path and self.blocklist_path.exists():
                self._intelligence.load_blocklist(self.blocklist_path)
            logger.info("IntelligenceEngine initialized")
        except Exception as exc:
            logger.error("Failed to init IntelligenceEngine: %s", exc)

        try:
            from ..ui.dashboard import LiveDashboard
            self._dashboard = LiveDashboard()
            self._dashboard.start()
            logger.info("LiveDashboard initialized")
        except Exception as exc:
            logger.error("Failed to init LiveDashboard: %s", exc)

    def start(self) -> None:
        """Start the full monitoring pipeline."""
        if self._running:
            logger.warning("Orchestrator already running")
            return

        self._init_engines()
        self._running = True

        # Start live capture
        if self._capture_engine:
            try:
                self._capture_engine.start(filter=self.capture_filter)
                logger.info("Live capture started")
            except Exception as exc:
                logger.error("Failed to start capture: %s", exc)

        # Start process monitor
        if self._process_monitor:
            try:
                self._process_monitor.start()
                logger.info("Process monitor started")
            except Exception as exc:
                logger.error("Failed to start process monitor: %s", exc)

        # Start file monitor
        if self._file_monitor:
            try:
                self._file_monitor.start()
                logger.info("File monitor started")
            except Exception as exc:
                logger.error("Failed to start file monitor: %s", exc)

        # Start analysis loop
        self._analysis_thread = threading.Thread(
            target=self._analysis_loop, daemon=True, name="analysis-loop",
        )
        self._analysis_thread.start()

        logger.info("=== Orchestrator pipeline started ===")

    def _analysis_loop(self) -> None:
        """Periodic analysis cycle feeding events into behavioral engine."""
        while self._running:
            try:
                self._run_analysis_cycle()
            except Exception as exc:
                logger.error("Analysis cycle error: %s", exc)
            time.sleep(config.BEHAVIOR_SEQUENCE_WINDOW / 6)

    def _run_analysis_cycle(self) -> None:
        """Execute one analysis cycle."""
        if not self._behavior_engine:
            return

        # Ingest packets from capture
        if self._capture_engine and self._capture_engine.is_running:
            count = 0
            for pkt in self._capture_engine.packet_stream(timeout=0.1):
                self._behavior_engine.ingest_packet(pkt)
                self._monitor_session.packet_count += 1
                count += 1
                if count > 500:
                    break
            if self._dashboard:
                self._dashboard.update_packet_count(self._monitor_session.packet_count)

        # Ingest file changes
        if self._file_monitor:
            changes = self._file_monitor.get_changes()
            for fc in changes:
                self._behavior_engine.ingest_file_change(fc)
            if self._dashboard and changes:
                self._dashboard.update_file_changes(changes)

        # Ingest process snapshots
        if self._process_monitor:
            snapshot = self._process_monitor.get_latest_snapshot()
            if snapshot:
                self._behavior_engine.ingest_process_snapshot(snapshot)
                procs = self._process_monitor.get_all_processes()
                if self._dashboard and procs:
                    self._dashboard.update_processes(procs)

        self._monitor_session.event_count = self._behavior_engine.event_count

        if self._dashboard:
            self._dashboard.update_event_count(self._monitor_session.event_count)

        # Run behavioral analysis
        profile = self._behavior_engine.analyze()
        self._result.behavioral_profile = profile

        if self._dashboard:
            self._dashboard.update_scores(
                behavioral=profile.behavioral_score,
                damage=0.0,
            )

        # Raise alerts for high-severity patterns
        if self._alert_system:
            for pattern in profile.patterns:
                alert = self._alert_system.alert_from_pattern(pattern)
                self._alert_system.raise_alert(alert)

            if self._dashboard:
                self._dashboard.update_alerts(self._alert_system.get_alerts())
            self._monitor_session.alert_count = self._alert_system.alert_count

        # Threat actor profiling
        if self._threat_profiler and profile.patterns:
            self._threat_profiler.profile_from_behavior(profile)
            self._result.threat_actors = self._threat_profiler.get_actors()

        # Damage assessment
        if self._damage_assessor:
            self._result.damage_assessment = self._damage_assessor.assess(
                profile=profile,
            )
            if self._dashboard and self._result.damage_assessment:
                self._dashboard.update_scores(
                    behavioral=profile.behavioral_score,
                    damage=self._result.damage_assessment.overall_score / 100.0,
                )

    def stop(self) -> None:
        """Stop all engines and generate final report."""
        logger.info("Stopping orchestrator...")
        self._running = False

        # Stop capture
        pkt_count = 0
        if self._capture_engine:
            pkt_count = self._capture_engine.stop()

        # Stop monitors
        if self._process_monitor:
            self._process_monitor.stop()

        if self._file_monitor:
            self._file_monitor.stop()

        if self._dashboard:
            self._dashboard.stop()

        # Run final analysis
        if self._behavior_engine:
            profile = self._behavior_engine.analyze()
            self._result.behavioral_profile = profile

        if self._alert_system:
            self._result.alerts = self._alert_system.get_alerts()
            self._result.alert_groups = self._alert_system.correlate()

        if self._threat_profiler:
            self._result.threat_actors = self._threat_profiler.get_actors()
            self._result.campaigns = self._threat_profiler.get_campaigns()

        if self._damage_assessor:
            self._result.damage_assessment = self._damage_assessor.assess(
                profile=self._result.behavioral_profile,
            )

        # Generate response plan
        critical = [a for a in self._result.alerts if a.severity.numeric >= Severity.HIGH.numeric]
        if critical and self._response_engine:
            self._result.response_plan = self._response_engine.generate_plan(
                critical, self._result.damage_assessment,
            )

        # Write final report
        self._write_report()

        elapsed = (datetime.now() - self._result.analysis_start).total_seconds() if self._result.analysis_start else 0.0
        self._result.elapsed_seconds = elapsed
        self._monitor_session.active = False

        logger.info("=== Orchestrator stopped (elapsed=%.1fs, packets=%d, alerts=%d) ===",
                     elapsed, pkt_count, self._monitor_session.alert_count)

    def _write_report(self) -> None:
        """Write the final JSON report."""
        try:
            from ..reporter import generate_json_report
            ts = datetime.now().strftime("%Y%m%d_%H%M%S")
            report_path = self.output_dir / "reports" / f"live_analysis_{ts}.json"
            report_path.parent.mkdir(parents=True, exist_ok=True)
            generate_json_report(self._result, report_path)
            logger.info("Final report written: %s", report_path)
        except Exception as exc:
            logger.error("Failed to write report: %s", exc)

    def get_result(self) -> AnalysisResult:
        """Return the current analysis result."""
        return self._result
