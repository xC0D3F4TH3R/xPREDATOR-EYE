"""
test_capture.py - Tests for capture engines (process monitor, file monitor, live capture).

NOTE: ProcessMonitor.start() calls psutil.process_iter() to build a baseline of
ALL running processes. On Windows with 300+ system processes, this can take 30+ seconds
and may appear to hang. Tests below focus on init, state, and file monitoring which
are fast and deterministic.
"""

import sys
import os
import time
sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from pcapanalyzer.capture.process_monitor import ProcessMonitor
from pcapanalyzer.capture.file_monitor import FileMonitor
from pcapanalyzer.capture.live_capture import LiveCaptureEngine


class TestProcessMonitor:
    """Tests for ProcessMonitor (fast init/state tests only)."""

    def test_init(self):
        pm = ProcessMonitor()
        assert pm is not None
        assert pm._running is False

    def test_has_required_methods(self):
        pm = ProcessMonitor()
        assert callable(pm.get_snapshot)
        assert callable(pm.get_diff)
        assert callable(pm.get_top_suspicious)
        assert callable(pm.get_events)
        assert callable(pm.start)
        assert callable(pm.stop)

    def test_get_events_empty(self):
        pm = ProcessMonitor()
        events = pm.get_events()
        assert isinstance(events, list)
        assert len(events) == 0

    def test_get_events_with_filter(self):
        from datetime import datetime, timedelta
        pm = ProcessMonitor()
        events = pm.get_events(since=datetime.now() - timedelta(hours=1))
        assert isinstance(events, list)

    def test_baseline_type(self):
        pm = ProcessMonitor()
        assert isinstance(pm._baseline, dict)


class TestFileMonitor:
    """Tests for FileMonitor (uses tmp_path, fast and deterministic)."""

    def test_init(self):
        fm = FileMonitor()
        assert fm is not None
        assert fm._running is False

    def test_set_watch_paths(self):
        fm = FileMonitor()
        fm.set_watch_paths(["/nonexistent/path"])
        assert len(fm._watch_paths) == 0

    def test_set_watch_paths_real(self, tmp_path):
        fm = FileMonitor()
        fm.set_watch_paths([str(tmp_path)])
        assert len(fm._watch_paths) == 1

    def test_add_watch_path(self, tmp_path):
        fm = FileMonitor()
        test_file = tmp_path / "test.txt"
        test_file.write_text("test")
        fm.add_watch_path(str(test_file))
        assert len(fm._watch_paths) == 1

    def test_baseline(self, tmp_path):
        fm = FileMonitor()
        test_file = tmp_path / "baseline.txt"
        test_file.write_text("initial")
        fm.set_watch_paths([str(tmp_path)])
        fm._take_baseline()
        assert len(fm._baseline) >= 1

    def test_get_changes_empty(self):
        fm = FileMonitor()
        changes = fm.get_changes()
        assert isinstance(changes, list)
        assert len(changes) == 0

    def test_detect_new_file(self, tmp_path):
        fm = FileMonitor()
        fm.set_watch_paths([str(tmp_path)])
        fm._take_baseline()

        new_file = tmp_path / "new_file.txt"
        new_file.write_text("created")
        fm._scan_for_changes()
        changes = fm.get_changes()
        assert any(c.change_type == "created" for c in changes)

    def test_detect_modified_file(self, tmp_path):
        test_file = tmp_path / "modify_me.txt"
        test_file.write_text("original")

        fm = FileMonitor()
        fm.set_watch_paths([str(tmp_path)])
        fm._take_baseline()

        test_file.write_text("modified content")
        fm._scan_for_changes()
        changes = fm.get_changes()
        assert any(c.change_type == "modified" for c in changes)

    def test_start_stop_with_paths(self, tmp_path):
        test_file = tmp_path / "watch.txt"
        test_file.write_text("test")

        fm = FileMonitor(interval=10.0)
        fm.set_watch_paths([str(tmp_path)])
        fm.start()
        assert fm._running is True
        assert fm._thread is not None
        assert fm._thread.is_alive()
        fm.stop()
        assert fm._running is False


class TestLiveCaptureEngine:
    """Tests for LiveCaptureEngine (no real capture)."""

    def test_init(self):
        engine = LiveCaptureEngine()
        assert engine is not None
        assert engine._running is False
        assert engine.packet_count == 0

    def test_init_with_interface(self):
        engine = LiveCaptureEngine(interface="Ethernet")
        assert engine.interface == "Ethernet"

    def test_init_with_filter(self):
        engine = LiveCaptureEngine(capture_filter="tcp port 443")
        assert engine.capture_filter == "tcp port 443"

    def test_build_cmd_live(self):
        engine = LiveCaptureEngine(interface="eth0", capture_filter="tcp port 443")
        cmd = engine._build_tshark_cmd(live=True)
        assert "tshark" in cmd[0] or "tshark" in cmd
        assert "-i" in cmd
        assert "eth0" in cmd
        assert "tcp port 443" in cmd

    def test_packet_count_init(self):
        engine = LiveCaptureEngine()
        assert engine.packet_count == 0

    def test_stop_without_start(self):
        engine = LiveCaptureEngine()
        count = engine.stop()
        assert count == 0

    def test_is_running_initial(self):
        engine = LiveCaptureEngine()
        assert engine._running is False

    def test_filter_propagation(self):
        engine = LiveCaptureEngine(capture_filter="udp port 53")
        assert engine.capture_filter == "udp port 53"
