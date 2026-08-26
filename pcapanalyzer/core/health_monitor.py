"""
health_monitor.py - Engine health monitoring and self-diagnostics.

Monitors the health of all xPREDATOR-EYE engines, detects degradation,
and provides self-healing capabilities.
"""

from __future__ import annotations

import threading
import time
from dataclasses import dataclass, field
from datetime import datetime
from typing import Optional

from ..utils import get_logger

logger = get_logger("health_monitor")


@dataclass
class EngineHealth:
    name: str
    status: str = "unknown"
    last_heartbeat: Optional[datetime] = None
    error_count: int = 0
    last_error: str = ""
    metrics: dict = field(default_factory=dict)


class HealthMonitor:
    """Monitors health of all engine components."""

    def __init__(self, check_interval: float = 30.0) -> None:
        self._engines: dict[str, EngineHealth] = {}
        self._check_interval = check_interval
        self._running = False
        self._thread: Optional[threading.Thread] = None
        self._lock = threading.Lock()

    def register_engine(self, name: str) -> None:
        with self._lock:
            self._engines[name] = EngineHealth(name=name, status="registered")

    def heartbeat(self, name: str, metrics: Optional[dict] = None) -> None:
        with self._lock:
            if name not in self._engines:
                self._engines[name] = EngineHealth(name=name)
            self._engines[name].last_heartbeat = datetime.now()
            self._engines[name].status = "healthy"
            if metrics:
                self._engines[name].metrics.update(metrics)

    def report_error(self, name: str, error: str) -> None:
        with self._lock:
            if name not in self._engines:
                self._engines[name] = EngineHealth(name=name)
            self._engines[name].error_count += 1
            self._engines[name].last_error = error
            self._engines[name].status = "degraded" if self._engines[name].error_count < 5 else "failed"

    def get_all_health(self) -> dict[str, EngineHealth]:
        with self._lock:
            return dict(self._engines)

    def get_overall_status(self) -> str:
        with self._lock:
            statuses = [e.status for e in self._engines.values()]
            if any(s == "failed" for s in statuses):
                return "degraded"
            if any(s == "degraded" for s in statuses):
                return "partial"
            return "healthy"

    def start(self) -> None:
        if self._running:
            return
        self._running = True
        self._thread = threading.Thread(target=self._check_loop, daemon=True, name="health-monitor")
        self._thread.start()
        logger.info("Health monitor started (interval=%ss)", self._check_interval)

    def stop(self) -> None:
        self._running = False
        if self._thread:
            self._thread.join(timeout=5)

    def _check_loop(self) -> None:
        while self._running:
            time.sleep(self._check_interval)
            self._check_stale_heartbeats()

    def _check_stale_heartbeats(self) -> None:
        cutoff = time.time() - (self._check_interval * 3)
        with self._lock:
            for engine in self._engines.values():
                if engine.last_heartbeat and engine.last_heartbeat.timestamp() < cutoff:
                    if engine.status == "healthy":
                        engine.status = "stale"
                        logger.warning("Engine %s heartbeat stale", engine.name)

    def get_summary(self) -> dict:
        with self._lock:
            return {
                "overall": self.get_overall_status(),
                "engines": {
                    name: {"status": e.status, "errors": e.error_count, "last_heartbeat": e.last_heartbeat.isoformat() if e.last_heartbeat else None}
                    for name, e in self._engines.items()
                },
            }
