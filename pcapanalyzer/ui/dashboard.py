"""
dashboard.py - Real-time Rich terminal dashboard.

Renders a live-updating terminal UI showing all monitoring activity,
alerts, behavioral analysis, threat actor profiles, and damage assessment.
"""

from __future__ import annotations

import threading
import time
from datetime import datetime
from typing import Optional

from rich.console import Console
from rich.live import Live
from rich.table import Table
from rich.panel import Panel
from rich.layout import Layout
from rich.text import Text
from rich import box

from .. import config
from ..models import (
    AnalysisResult, Alert, AlertPriority, Severity,
    BehavioralProfile, ThreatActor, DamageAssessment,
    ProcessSnapshot, FileChange, LivePacket,
)
from ..utils import get_logger, bytes_to_human_readable

logger = get_logger("dashboard")
console = Console()


class LiveDashboard:
    """Real-time terminal dashboard for monitoring all analysis activity.

    Usage::

        dashboard = LiveDashboard()
        dashboard.start()
        dashboard.update_alerts(alerts)
        dashboard.stop()
    """

    def __init__(self) -> None:
        self._running = False
        self._live: Optional[Live] = None
        self._lock = threading.Lock()
        self._stats = {
            "packets": 0,
            "events": 0,
            "alerts": 0,
            "critical": 0,
            "high": 0,
            "processes": 0,
            "file_changes": 0,
            "behavioral_score": 0.0,
            "damage_score": 0.0,
            "start_time": datetime.now(),
        }
        self._recent_alerts: list[Alert] = []
        self._top_processes: list[ProcessSnapshot] = []
        self._recent_files: list[FileChange] = []

    def start(self) -> None:
        """Start the live dashboard."""
        self._running = True
        self._stats["start_time"] = datetime.now()
        logger.info("Live dashboard started")

    def stop(self) -> None:
        """Stop the live dashboard."""
        self._running = False
        logger.info("Live dashboard stopped")

    def update_packet_count(self, count: int) -> None:
        with self._lock:
            self._stats["packets"] = count

    def update_event_count(self, count: int) -> None:
        with self._lock:
            self._stats["events"] = count

    def update_alerts(self, alerts: list[Alert]) -> None:
        with self._lock:
            self._recent_alerts = sorted(alerts, key=lambda a: a.timestamp or datetime.min, reverse=True)[:15]
            self._stats["alerts"] = len(alerts)
            self._stats["critical"] = sum(1 for a in alerts if a.severity == Severity.CRITICAL)
            self._stats["high"] = sum(1 for a in alerts if a.severity == Severity.HIGH)

    def update_processes(self, procs: list[ProcessSnapshot]) -> None:
        with self._lock:
            self._top_processes = sorted(procs, key=lambda p: p.suspicious_score, reverse=True)[:8]

    def update_file_changes(self, changes: list[FileChange]) -> None:
        with self._lock:
            self._recent_files = changes[-10:] if changes else []

    def update_scores(self, behavioral: float = 0.0, damage: float = 0.0) -> None:
        with self._lock:
            self._stats["behavioral_score"] = behavioral
            self._stats["damage_score"] = damage

    def render_frame(self) -> Layout:
        """Build and return the full dashboard layout."""
        with self._lock:
            layout = Layout()

            header = self._build_header()
            stats_panel = self._build_stats_panel()
            alerts_table = self._build_alerts_table()
            processes_table = self._build_processes_table()
            files_table = self._build_files_table()
            score_panel = self._build_score_panel()

            layout.split_column(
                Layout(header, size=3),
                Layout(name="upper", size=12),
                Layout(name="lower"),
            )

            layout["upper"].split_row(
                Layout(stats_panel),
                Layout(score_panel),
            )

            layout["lower"].split_row(
                Layout(alerts_table),
                Layout(name="right_col"),
            )

            layout["right_col"].split_column(
                Layout(processes_table),
                Layout(files_table),
            )

            return layout

    def _build_header(self) -> Panel:
        elapsed = (datetime.now() - self._stats["start_time"]).total_seconds()
        text = Text()
        text.append("  PcapMalAnalyzer ", style="bold white on blue")
        text.append("  LIVE MONITORING  ", style="bold white on red")
        text.append(f"  {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}  ", style="dim")
        text.append(f"  Uptime: {elapsed:.0f}s  ", style="cyan")
        return Panel(text, border_style="blue")

    def _build_stats_panel(self) -> Panel:
        table = Table(show_header=False, box=None, padding=(0, 2))
        table.add_column("Metric", style="bold")
        table.add_column("Value", style="cyan")
        table.add_row("Packets Captured", f"{self._stats['packets']:,}")
        table.add_row("Events Processed", f"{self._stats['events']:,}")
        table.add_row("Total Alerts", f"{self._stats['alerts']}")
        table.add_row("CRITICAL", Text(str(self._stats['critical']), style="bold red"))
        table.add_row("HIGH", Text(str(self._stats['high']), style="bold yellow"))
        table.add_row("File Changes", str(self._stats["file_changes"]))
        return Panel(table, title="[bold]Statistics[/]", border_style="cyan")

    def _build_score_panel(self) -> Panel:
        b_score = self._stats["behavioral_score"]
        d_score = self._stats["damage_score"]

        def score_bar(score: float, width: int = 20) -> Text:
            filled = int(score * width)
            empty = width - filled
            color = "green" if score < 0.3 else "yellow" if score < 0.6 else "red"
            t = Text()
            t.append("█" * filled, style=f"bold {color}")
            t.append("░" * empty, style="dim")
            t.append(f" {score:.0%}", style=f"bold {color}")
            return t

        table = Table(show_header=False, box=None, padding=(0, 2))
        table.add_column("Metric", style="bold")
        table.add_column("Score")
        table.add_row("Behavioral Score", score_bar(b_score))
        table.add_row("Damage Score", score_bar(d_score))
        return Panel(table, title="[bold]Threat Scores[/]", border_style="red" if b_score > 0.6 else "yellow" if b_score > 0.3 else "green")

    def _build_alerts_table(self) -> Panel:
        table = Table(
            title="Recent Alerts", box=box.SIMPLE_HEAVY,
            show_lines=True, title_style="bold red",
        )
        table.add_column("Time", width=8, style="dim")
        table.add_column("Priority", width=10)
        table.add_column("Title", max_width=30)
        table.add_column("Source IP", width=15)
        table.add_column("Severity", width=10)

        for alert in self._recent_alerts:
            pri_color = {
                AlertPriority.CRITICAL: "bold red", AlertPriority.ERROR: "red",
                AlertPriority.WARNING: "yellow", AlertPriority.NOTICE: "cyan",
            }.get(alert.priority, "white")

            sev_color = {
                Severity.CRITICAL: "bold red", Severity.HIGH: "red",
                Severity.MEDIUM: "yellow", Severity.LOW: "green",
            }.get(alert.severity, "white")

            time_str = alert.timestamp.strftime("%H:%M:%S") if alert.timestamp else "—"
            table.add_row(
                time_str,
                Text(alert.priority.name, style=pri_color),
                alert.title[:30],
                alert.src_ip or "—",
                Text(alert.severity.value, style=sev_color),
            )

        if not self._recent_alerts:
            table.add_row("—", "—", "No alerts yet", "—", "—")

        return Panel(table, border_style="red" if self._stats["critical"] > 0 else "green")

    def _build_processes_table(self) -> Panel:
        table = Table(
            title="Top Suspicious Processes", box=box.SIMPLE_HEAVY,
            show_lines=True, title_style="bold yellow",
        )
        table.add_column("PID", width=7)
        table.add_column("Name", max_width=20, style="cyan")
        table.add_column("User", width=12)
        table.add_column("CPU%", width=6)
        table.add_column("Mem(MB)", width=8)
        table.add_column("Score", width=6)
        table.add_column("Flags", max_width=20)

        for proc in self._top_processes:
            score_color = "green" if proc.suspicious_score < 0.3 else "yellow" if proc.suspicious_score < 0.6 else "red"
            table.add_row(
                str(proc.pid),
                proc.name[:20],
                proc.username[:12] if proc.username else "—",
                f"{proc.cpu_percent:.0f}",
                f"{proc.memory_rss / 1024 / 1024:.0f}",
                Text(f"{proc.suspicious_score:.2f}", style=score_color),
                ", ".join(proc.anomaly_flags[:2]) if proc.anomaly_flags else "—",
            )

        if not self._top_processes:
            table.add_row("—", "Monitoring...", "—", "—", "—", "—", "—")

        return Panel(table, border_style="yellow")

    def _build_files_table(self) -> Panel:
        table = Table(
            title="Recent File Changes", box=box.SIMPLE_HEAVY,
            show_lines=True, title_style="bold magenta",
        )
        table.add_column("Type", width=10)
        table.add_column("Path", max_width=45, style="cyan")
        table.add_column("Size", width=8)
        table.add_column("Time", width=8, style="dim")

        for fc in self._recent_files:
            type_color = {
                "created": "green", "modified": "yellow", "deleted": "red",
            }.get(fc.change_type, "white")
            time_str = fc.timestamp.strftime("%H:%M:%S") if fc.timestamp else "—"
            table.add_row(
                Text(fc.change_type, style=type_color),
                fc.path[:45],
                bytes_to_human_readable(fc.size) if fc.size else "—",
                time_str,
            )

        if not self._recent_files:
            table.add_row("—", "Monitoring...", "—", "—")

        return Panel(table, border_style="magenta")
