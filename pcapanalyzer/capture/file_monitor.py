"""
file_monitor.py - Cross-platform file integrity monitoring.

Watches critical directories for creation, modification, deletion.
Detects suspicious file activity and computes hashes for changed files.
"""

from __future__ import annotations

import os
import platform
import threading
import time
from datetime import datetime
from pathlib import Path
from typing import Optional

from .. import config
from ..models import FileChange, SystemEvent, Severity
from ..utils import get_logger, compute_hashes

logger = get_logger("file_monitor")


class FileMonitor:
    """Periodic file-integrity monitor using polling with baselines."""

    def __init__(self, interval: float = config.FILE_MONITOR_INTERVAL) -> None:
        self.interval = interval
        self._watch_paths: list[Path] = []
        self._baseline: dict[str, dict] = {}
        self._changes: list[FileChange] = []
        self._events: list[SystemEvent] = []
        self._running = False
        self._thread: Optional[threading.Thread] = None
        self._lock = threading.Lock()

    def set_watch_paths(self, paths: list[str]) -> None:
        self._watch_paths = [Path(p) for p in paths if os.path.exists(p)]
        logger.info("Watching %d paths", len(self._watch_paths))

    def add_watch_path(self, path: str) -> None:
        p = Path(path)
        if os.path.exists(p) and p not in self._watch_paths:
            self._watch_paths.append(p)

    def load_platform_defaults(self) -> None:
        if platform.system() == "Windows":
            paths = config.CRITICAL_PATHS_WINDOWS
        elif platform.system() == "Darwin":
            paths = config.CRITICAL_PATHS_MACOS
        else:
            paths = config.CRITICAL_PATHS_LINUX
        self.set_watch_paths(paths)

    def start(self) -> None:
        if self._running:
            return
        if not self._watch_paths:
            self.load_platform_defaults()
        self._take_baseline()
        self._running = True
        self._thread = threading.Thread(
            target=self._monitor_loop, daemon=True, name="file-monitor",
        )
        self._thread.start()
        logger.info("File monitor started (interval=%.1fs, paths=%d)",
                     self.interval, len(self._watch_paths))

    def stop(self) -> None:
        self._running = False
        if self._thread and self._thread.is_alive():
            self._thread.join(timeout=5)
        logger.info("File monitor stopped. Detected %d changes", len(self._changes))

    def _take_baseline(self) -> None:
        baseline: dict[str, dict] = {}
        for path in self._watch_paths:
            if path.is_file():
                baseline[str(path)] = self._file_meta(path)
            elif path.is_dir():
                try:
                    for entry in path.rglob("*"):
                        if entry.is_file():
                            try:
                                baseline[str(entry)] = self._file_meta(entry)
                            except (OSError, PermissionError):
                                pass
                except (OSError, PermissionError):
                    pass
        self._baseline = baseline
        logger.info("File baseline captured: %d files", len(baseline))

    def _file_meta(self, path: Path) -> dict:
        stat = path.stat()
        return {"size": stat.st_size, "mtime": stat.st_mtime, "ctime": stat.st_ctime}

    def _monitor_loop(self) -> None:
        while self._running:
            try:
                self._scan_for_changes()
            except Exception as exc:
                logger.error("File monitor error: %s", exc)
            time.sleep(self.interval)

    def _scan_for_changes(self) -> None:
        current: dict[str, dict] = {}
        for path in self._watch_paths:
            if path.is_file():
                try:
                    current[str(path)] = self._file_meta(path)
                except (OSError, PermissionError):
                    pass
            elif path.is_dir():
                try:
                    for entry in path.rglob("*"):
                        if entry.is_file():
                            try:
                                current[str(entry)] = self._file_meta(entry)
                            except (OSError, PermissionError):
                                pass
                except (OSError, PermissionError):
                    pass

        baseline_paths = set(self._baseline.keys())
        current_paths = set(current.keys())

        with self._lock:
            for fp in current_paths - baseline_paths:
                fc = FileChange(path=fp, change_type="created",
                                size=current[fp]["size"], timestamp=datetime.now())
                try:
                    h = compute_hashes(Path(fp).read_bytes()[:65536])
                    fc.md5, fc.sha256 = h["md5"], h["sha256"]
                except OSError:
                    pass
                self._changes.append(fc)
                self._events.append(SystemEvent(
                    event_type="file_created", severity=Severity.MEDIUM,
                    source="file_monitor",
                    details={"path": fp, "size": current[fp]["size"]},
                    timestamp=datetime.now()))

            for fp in baseline_paths - current_paths:
                fc = FileChange(path=fp, change_type="deleted", timestamp=datetime.now())
                self._changes.append(fc)
                self._events.append(SystemEvent(
                    event_type="file_deleted", severity=Severity.MEDIUM,
                    source="file_monitor", details={"path": fp},
                    timestamp=datetime.now()))

            for fp in baseline_paths & current_paths:
                old_m, new_m = self._baseline[fp], current[fp]
                if abs(new_m["mtime"] - old_m["mtime"]) > 0.01 or new_m["size"] != old_m["size"]:
                    fc = FileChange(path=fp, change_type="modified",
                                    size=new_m["size"], timestamp=datetime.now())
                    try:
                        h = compute_hashes(Path(fp).read_bytes()[:65536])
                        fc.md5, fc.sha256 = h["md5"], h["sha256"]
                    except OSError:
                        pass
                    self._changes.append(fc)
                    self._events.append(SystemEvent(
                        event_type="file_modified", severity=Severity.LOW,
                        source="file_monitor",
                        details={"path": fp, "old_size": old_m["size"], "new_size": new_m["size"]},
                        timestamp=datetime.now()))
            self._baseline = current

    def get_changes(self) -> list[FileChange]:
        with self._lock:
            return list(self._changes)

    def get_events(self, since: Optional[datetime] = None) -> list[SystemEvent]:
        if since:
            return [e for e in self._events if e.timestamp and e.timestamp >= since]
        return list(self._events)

    def clear_changes(self) -> None:
        with self._lock:
            self._changes.clear()
