"""
process_monitor.py - Cross-platform real-time process monitoring.

Uses psutil to snapshot, diff, and track all running processes, their
network connections, open files, and parent-child relationships.
Detects anomalous behaviour via heuristic scoring.
"""

from __future__ import annotations

import os
import platform
import threading
import time
from collections import defaultdict
from datetime import datetime
from typing import Optional

import psutil  # type: ignore[import-untyped]

from .. import config
from ..models import ProcessSnapshot, ProcessDiff, SystemEvent, Severity
from ..utils import get_logger, compute_hashes

logger = get_logger("process_monitor")


class ProcessMonitor:
    """Continuously monitors system processes and detects anomalies.

    Usage::

        monitor = ProcessMonitor()
        monitor.start()
        # ... later ...
        diff = monitor.get_diff()
        monitor.stop()
    """

    def __init__(self, poll_interval: float = config.PROCESS_POLL_INTERVAL) -> None:
        self.poll_interval = poll_interval
        self._snapshots: list[dict[int, ProcessSnapshot]] = []
        self._running = False
        self._thread: Optional[threading.Thread] = None
        self._baseline: dict[int, ProcessSnapshot] = {}
        self._latest_snapshot: dict[int, ProcessSnapshot] = {}
        self._events: list[SystemEvent] = []
        self._lock = threading.Lock()
        self._hash_cache: dict[tuple, tuple[str, str]] = {}

    def start(self) -> None:
        """Begin periodic process monitoring in a background thread."""
        if self._running:
            return
        self._running = True
        self._thread = threading.Thread(
            target=self._monitor_loop, daemon=True, name="proc-monitor",
        )
        self._thread.start()
        logger.info("Process monitor started (interval=%.1fs)", self.poll_interval)

    def stop(self) -> None:
        """Stop the monitoring thread."""
        self._running = False
        if self._thread and self._thread.is_alive():
            self._thread.join(timeout=5)
        logger.info("Process monitor stopped")

    def _take_baseline(self) -> None:
        """Capture the initial process state."""
        self._baseline = self._snapshot_all()
        logger.info("Baseline captured: %d processes", len(self._baseline))

    def _snapshot_all(self) -> dict[int, ProcessSnapshot]:
        """Take a point-in-time snapshot of all running processes."""
        snapshots: dict[int, ProcessSnapshot] = {}
        for proc in psutil.process_iter(["pid", "name", "exe", "cmdline", "username",
                                          "cpu_percent", "memory_info", "status",
                                          "create_time", "num_threads", "ppid"]):
            try:
                info = proc.info
                pid = info["pid"]
                mem = info.get("memory_info")

                connections = []
                try:
                    for conn in proc.net_connections(kind="inet"):
                        connections.append({
                            "fd": conn.fd,
                            "family": str(conn.family),
                            "type": str(conn.type),
                            "laddr": f"{conn.laddr.ip}:{conn.laddr.port}" if conn.laddr else "",
                            "raddr": f"{conn.raddr.ip}:{conn.raddr.port}" if conn.raddr else "",
                            "status": conn.status,
                        })
                except (psutil.AccessDenied, psutil.NoSuchProcess):
                    pass

                open_files = []
                try:
                    for f in proc.open_files():
                        open_files.append(f.path)
                except (psutil.AccessDenied, psutil.NoSuchProcess):
                    pass

                # Compute executable hash for known-path processes (cached by mtime/size)
                md5 = sha256 = ""
                exe_path = info.get("exe") or ""
                if exe_path and os.path.isfile(exe_path):
                    try:
                        stat = os.stat(exe_path)
                        cache_key = (exe_path, stat.st_size, stat.st_mtime)
                        cached = self._hash_cache.get(cache_key)
                        if cached:
                            md5, sha256 = cached
                        else:
                            with open(exe_path, "rb") as fh:
                                data = fh.read(8192)  # read first 8KB for speed
                            hashes = compute_hashes(data)
                            md5 = hashes["md5"]
                            sha256 = hashes["sha256"]
                            if len(self._hash_cache) >= config.PROCESS_HASH_CACHE_SIZE:
                                self._hash_cache.clear()
                            self._hash_cache[cache_key] = (md5, sha256)
                    except OSError:
                        pass

                ss = ProcessSnapshot(
                    pid=pid,
                    name=info.get("name") or "",
                    exe_path=exe_path,
                    cmdline=info.get("cmdline") or [],
                    username=info.get("username") or "",
                    cpu_percent=info.get("cpu_percent") or 0.0,
                    memory_rss=mem.rss if mem else 0,
                    memory_vms=mem.vms if mem else 0,
                    status=info.get("status") or "unknown",
                    create_time=info.get("create_time"),
                    connections=connections,
                    open_files=open_files,
                    threads=info.get("num_threads") or 0,
                    parent_pid=info.get("ppid") or 0,
                    md5=md5,
                    sha256=sha256,
                    timestamp=datetime.now(),
                )

                # Compute suspiciousness score
                ss.suspicious_score = self._score_process(ss)
                ss.anomaly_flags = self._detect_anomalies(ss)

                snapshots[pid] = ss

            except (psutil.NoSuchProcess, psutil.AccessDenied, psutil.ZombieProcess):
                continue

        return snapshots

    def _score_process(self, ss: ProcessSnapshot) -> float:
        """Compute a 0.0-1.0 suspiciousness score for a process."""
        score = 0.0
        name_lower = ss.name.lower()

        # Unknown process name
        if name_lower not in config.KNOWN_BENIGN_PROCESSES:
            score += 0.15

        # High CPU usage
        if ss.cpu_percent > config.PROCESS_CPU_SUSPICIOUS:
            score += 0.2

        # Excessive memory
        if ss.memory_rss > config.PROCESS_MEMORY_SUSPICIOUS_MB * 1024 * 1024:
            score += 0.15

        # Too many threads
        if ss.threads > config.PROCESS_THREAD_SUSPICIOUS:
            score += 0.15

        # Network connections from unusual processes
        if ss.connections and name_lower in config.KNOWN_BENIGN_PROCESSES:
            score += 0.05

        # Suspicious command-line indicators
        cmdline_str = " ".join(ss.cmdline).lower()
        suspicious_cl = [
            "powershell", "cmd.exe /c", "/bin/sh -c", "bash -c",
            "certutil", "bitsadmin", "mshta", "rundll32", "regsvr32",
            "wscript", "cscript", "psexec", "wmic", "schtasks",
            "base64", "eval(", "exec(", "invoke-expression",
            "downloadstring", "webclient", "http://", "https://",
        ]
        for indicator in suspicious_cl:
            if indicator in cmdline_str:
                score += 0.2
                break

        # Runs from temp directories
        exe = ss.exe_path.lower()
        if "/tmp" in exe or "\\temp" in exe or "\\appdata\\local\\temp" in exe:
            score += 0.25

        return min(score, 1.0)

    def _detect_anomalies(self, ss: ProcessSnapshot) -> list[str]:
        """Identify specific anomaly flags on a process."""
        flags: list[str] = []
        if ss.cpu_percent > config.PROCESS_CPU_SUSPICIOUS:
            flags.append("high_cpu")
        if ss.memory_rss > config.PROCESS_MEMORY_SUSPICIOUS_MB * 1024 * 1024:
            flags.append("high_memory")
        if ss.threads > config.PROCESS_THREAD_SUSPICIOUS:
            flags.append("excessive_threads")
        if not ss.exe_path or not os.path.isfile(ss.exe_path):
            flags.append("missing_binary")
        if ss.exe_path.lower().endswith((".tmp", ".temp", ".dat")):
            flags.append("suspicious_extension")
        cmdline_str = " ".join(ss.cmdline).lower()
        if "base64" in cmdline_str or "invoke-expression" in cmdline_str:
            flags.append("obfuscated_command")
        return flags

    def _monitor_loop(self) -> None:
        """Background loop taking periodic snapshots and detecting changes."""
        # Capture the baseline in the background so startup never blocks.
        try:
            self._baseline = self._snapshot_all()
            logger.info("Baseline captured: %d processes", len(self._baseline))
        except Exception as exc:
            logger.error("Initial process baseline failed: %s", exc)

        while self._running:
            try:
                current = self._snapshot_all()
                diff = self._compute_diff(self._baseline, current)
                with self._lock:
                    self._latest_snapshot = current
                    self._snapshots.append(current)
                    if len(self._snapshots) > config.PROCESS_SNAPSHOT_HISTORY:
                        del self._snapshots[: -config.PROCESS_SNAPSHOT_HISTORY]
                self._emit_events(diff)
                self._baseline = current
            except Exception as exc:
                logger.error("Process monitor error: %s", exc)
            time.sleep(self.poll_interval)

    def _compute_diff(
        self,
        old: dict[int, ProcessSnapshot],
        new: dict[int, ProcessSnapshot],
    ) -> ProcessDiff:
        """Compute the delta between two process snapshots."""
        diff = ProcessDiff()

        old_pids = set(old.keys())
        new_pids = set(new.keys())

        diff.new_processes = [new[pid] for pid in new_pids - old_pids]
        diff.terminated_processes = [old[pid] for pid in old_pids - new_pids]

        for pid in old_pids & new_pids:
            old_proc = old[pid]
            new_proc = new[pid]
            if (old_proc.connections != new_proc.connections or
                    old_proc.open_files != new_proc.open_files or
                    old_proc.cpu_percent != new_proc.cpu_percent):
                diff.modified_processes.append((old_proc, new_proc))
                # Detect new connections
                old_conns = {c["raddr"] for c in old_proc.connections if c["raddr"]}
                new_conns = {c["raddr"] for c in new_proc.connections if c["raddr"]}
                for nc in new_conns - old_conns:
                    diff.new_connections.append({"process": new_proc.name, "remote": nc})

        return diff

    def _emit_events(self, diff: ProcessDiff) -> None:
        """Convert a diff into SystemEvent objects."""
        new_events: list[SystemEvent] = []
        for proc in diff.new_processes:
            severity = Severity.HIGH if proc.suspicious_score > 0.5 else Severity.INFO
            new_events.append(SystemEvent(
                event_type="process_start",
                severity=severity,
                source="process_monitor",
                details={
                    "pid": proc.pid, "name": proc.name,
                    "exe": proc.exe_path, "cmdline": proc.cmdline,
                    "user": proc.username, "score": proc.suspicious_score,
                },
                timestamp=proc.timestamp,
                related_pid=proc.pid,
            ))
            if proc.suspicious_score > 0.6:
                logger.warning(
                    "Suspicious process started: %s (pid=%d, score=%.2f)",
                    proc.name, proc.pid, proc.suspicious_score,
                )

        for proc in diff.terminated_processes:
            new_events.append(SystemEvent(
                event_type="process_exit",
                severity=Severity.INFO,
                source="process_monitor",
                details={"pid": proc.pid, "name": proc.name},
                timestamp=datetime.now(),
            ))

        for conn in diff.new_connections:
            new_events.append(SystemEvent(
                event_type="network_connect",
                severity=Severity.LOW,
                source="process_monitor",
                details=conn,
                timestamp=datetime.now(),
            ))

        with self._lock:
            self._events.extend(new_events)
            if len(self._events) > config.PROCESS_MAX_EVENTS:
                del self._events[: len(self._events) - config.PROCESS_MAX_EVENTS]

    def get_snapshot(self) -> dict[int, ProcessSnapshot]:
        """Take and return an immediate snapshot."""
        return self._snapshot_all()

    def get_latest_snapshot(self) -> dict[int, ProcessSnapshot]:
        """Return the most recent snapshot captured by the monitor loop."""
        with self._lock:
            return dict(self._latest_snapshot)

    def get_all_processes(self) -> list[ProcessSnapshot]:
        """Return all processes from the latest snapshot as a list."""
        with self._lock:
            if self._latest_snapshot:
                return list(self._latest_snapshot.values())
        return list(self._snapshot_all().values())

    def get_diff(self) -> ProcessDiff:
        """Return the latest diff against baseline."""
        current = self._snapshot_all()
        return self._compute_diff(self._baseline, current)

    def get_events(self, since: Optional[datetime] = None) -> list[SystemEvent]:
        """Return events, optionally filtered by timestamp."""
        with self._lock:
            events = list(self._events)
        if since:
            return [e for e in events if e.timestamp and e.timestamp >= since]
        return events

    def get_top_suspicious(self, limit: int = 10) -> list[ProcessSnapshot]:
        """Return the top N most suspicious processes from the latest snapshot."""
        with self._lock:
            if self._latest_snapshot:
                ranked = sorted(
                    self._latest_snapshot.values(),
                    key=lambda p: p.suspicious_score, reverse=True,
                )
                return ranked[:limit]
        current = self._snapshot_all()
        ranked = sorted(current.values(), key=lambda p: p.suspicious_score, reverse=True)
        return ranked[:limit]
