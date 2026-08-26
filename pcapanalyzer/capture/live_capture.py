"""
live_capture.py - Real-time packet capture engine.

Interfaces with tshark/dumpcap for live traffic capture on any platform.
Provides a generator-based streaming API for downstream consumers.
"""

from __future__ import annotations

import csv
import io
import subprocess
import threading
import time
from collections import deque
from datetime import datetime
from pathlib import Path
from typing import Generator, Optional

from .. import config
from ..models import LivePacket, CaptureError
from ..utils import get_logger

logger = get_logger("live_capture")


class LiveCaptureEngine:
    """Manages live packet capture via tshark/dumpcap.

    Usage::

        engine = LiveCaptureEngine(interface="Ethernet")
        engine.start(filter="tcp port 443")
        for packet in engine.packet_stream():
            process(packet)
        engine.stop()
    """

    TSHARK_FIELDS = [
        "frame.time_epoch", "ip.src", "ip.dst", "tcp.srcport", "tcp.dstport",
        "ip.proto", "frame.len", "tcp.flags", "frame.protocols",
        "dns.qry.name", "http.host", "http.request.uri",
        "tls.handshake.extensions_server_name",
        "frame.time", "_ws.col.Info",
    ]

    def __init__(
        self,
        interface: Optional[str] = None,
        capture_filter: str = "",
        output_dir: Optional[Path] = None,
    ) -> None:
        self.interface = interface
        self.capture_filter = capture_filter or config.CAPTURE_FILTER_DEFAULT
        self.output_dir = output_dir or config.TEMP_DIR
        self._process: Optional[subprocess.Popen] = None
        self._packet_queue: deque[LivePacket] = deque(maxlen=config.LIVE_PACKET_QUEUE_SIZE)
        self._running = False
        self._lock = threading.Lock()
        self._packet_count = 0
        self._capture_thread: Optional[threading.Thread] = None

    def _find_interface(self) -> str:
        """Auto-detect the default network interface via tshark."""
        if self.interface:
            return self.interface
        try:
            result = subprocess.run(
                [config.TSHARK_PATH, "-D"],
                capture_output=True, text=True, timeout=10,
            )
            if result.returncode == 0 and result.stdout.strip():
                lines = result.stdout.strip().split("\n")
                return lines[0].split(".")[0].strip()
        except Exception as exc:
            logger.warning("Interface auto-detection failed: %s", exc)
        return ""

    def _build_tshark_cmd(self, live: bool = True) -> list[str]:
        """Construct the tshark command line."""
        cmd = [config.TSHARK_PATH]

        if live:
            iface = self._find_interface()
            if iface:
                cmd.extend(["-i", iface])
            cmd.extend([
                "-a", "duration:0",  # no auto-stop
                "-l",  # line-buffered output
            ])
        else:
            cmd.extend(["-r", "-"])  # read from stdin

        # Output format: parseable fields
        cmd.append("-T")
        cmd.append("fields")
        for field in self.TSHARK_FIELDS:
            cmd.extend(["-e", field])
        cmd.extend(["-E", "separator=|", "-E", "occurrence=f", "-E", "header=y"])

        if self.capture_filter:
            cmd.extend(["-f", self.capture_filter])

        # Snaplen and buffer
        cmd.extend(["-s", str(config.CAPTURE_SNAPLEN)])

        return cmd

    def start(self, filter: str = "") -> None:
        """Start live packet capture in a background thread."""
        if self._running:
            logger.warning("Capture already running")
            return

        if filter:
            self.capture_filter = filter

        cmd = self._build_tshark_cmd(live=True)
        logger.info("Starting capture: %s", " ".join(cmd))

        try:
            self._process = subprocess.Popen(
                cmd,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True,
                bufsize=1,
            )
        except FileNotFoundError:
            raise CaptureError(
                f"tshark not found at '{config.TSHARK_PATH}'. "
                "Install Wireshark or set TSHARK_PATH environment variable."
            )
        except Exception as exc:
            raise CaptureError(f"Failed to start capture: {exc}") from exc

        self._running = True
        self._capture_thread = threading.Thread(
            target=self._read_packets, daemon=True, name="capture-reader",
        )
        self._capture_thread.start()
        logger.info("Live capture started on interface %s", self.interface or "auto")

    def _read_packets(self) -> None:
        """Read tshark output line-by-line and parse into LivePacket objects."""
        if not self._process or not self._process.stdout:
            return

        try:
            reader = io.TextIOWrapper(self._process.stdout, encoding="utf-8", errors="replace")
            header_skipped = False

            for line in reader:
                if not self._running:
                    break

                line = line.strip()
                if not line:
                    continue

                # Skip header row
                if not header_skipped:
                    header_skipped = True
                    continue

                try:
                    packet = self._parse_tshark_line(line)
                    if packet is not None:
                        with self._lock:
                            self._packet_queue.append(packet)
                            self._packet_count += 1
                except Exception as exc:
                    logger.debug("Packet parse error: %s", exc)

        except Exception as exc:
            logger.error("Capture reader error: %s", exc)
        finally:
            self._running = False

    def _parse_tshark_line(self, line: str) -> Optional[LivePacket]:
        """Parse a pipe-delimited tshark field line into a LivePacket."""
        fields = line.split("|")
        if len(fields) < 8:
            return None

        try:
            ts = float(fields[0]) if fields[0] else time.time()
            src_ip = fields[1] if fields[1] else ""
            dst_ip = fields[2] if fields[2] else ""
            src_port = int(fields[3]) if fields[3] else 0
            dst_port = int(fields[4]) if fields[4] else 0
            proto = int(fields[5]) if fields[5] else 0
            pkt_len = int(fields[6]) if fields[6] else 0
            flags = fields[7] if fields[7] else ""
            app_proto = fields[8] if len(fields) > 8 else ""
            dns_qry = fields[9] if len(fields) > 9 else ""
            http_host = fields[10] if len(fields) > 10 else ""
            http_uri = fields[11] if len(fields) > 11 else ""
            tls_sni = fields[12] if len(fields) > 12 else ""
            info = fields[14] if len(fields) > 14 else ""

            return LivePacket(
                timestamp=ts,
                src_ip=src_ip, dst_ip=dst_ip,
                src_port=src_port, dst_port=dst_port,
                protocol=proto, length=pkt_len,
                flags=flags, app_protocol=app_proto,
                dns_query=dns_qry, http_host=http_host,
                http_uri=http_uri, tls_sni=tls_sni,
                raw_summary=info,
            )
        except (ValueError, IndexError):
            return None

    def packet_stream(self, timeout: float = 0.0) -> Generator[LivePacket, None, None]:
        """Yield packets as they arrive from the capture.

        Args:
            timeout: Maximum seconds to wait for new packets (0 = block forever).

        Yields:
            LivePacket objects as they arrive.
        """
        deadline = time.monotonic() + timeout if timeout > 0 else float("inf")
        while self._running or self._packet_queue:
            with self._lock:
                if self._packet_queue:
                    yield self._packet_queue.popleft()
                    deadline = time.monotonic() + timeout if timeout > 0 else float("inf")
                    continue
            if time.monotonic() > deadline:
                return
            time.sleep(config.LIVE_POLL_INTERVAL_SEC)

    def stop(self) -> int:
        """Stop capture and return total packet count."""
        self._running = False
        if self._process:
            self._process.terminate()
            try:
                self._process.wait(timeout=5)
            except subprocess.TimeoutExpired:
                self._process.kill()
            self._process = None
        if self._capture_thread and self._capture_thread.is_alive():
            self._capture_thread.join(timeout=3)
        logger.info("Capture stopped. Total packets: %d", self._packet_count)
        return self._packet_count

    @property
    def is_running(self) -> bool:
        return self._running

    @property
    def packet_count(self) -> int:
        return self._packet_count

    def list_interfaces(self) -> list[str]:
        """Return available network interfaces."""
        try:
            result = subprocess.run(
                [config.TSHARK_PATH, "-D"],
                capture_output=True, text=True, timeout=10,
            )
            if result.returncode == 0:
                return [line.strip() for line in result.stdout.strip().split("\n") if line.strip()]
        except Exception as exc:
            logger.error("Failed to list interfaces: %s", exc)
        return []

    def capture_to_pcap(self, output_path: Path, duration: int = 60, filter: str = "") -> Path:
        """Capture to a PCAP file for a fixed duration.

        Args:
            output_path: Destination PCAP file.
            duration: Seconds to capture.
            filter: BPF capture filter string.

        Returns:
            Path to the written PCAP file.
        """
        cmd = [config.DUMPCAP_PATH, "-w", str(output_path)]
        if self.interface:
            cmd.extend(["-i", self.interface])
        if filter:
            cmd.extend(["-f", filter])
        cmd.extend(["-a", f"duration:{duration}", "-s", str(config.CAPTURE_SNAPLEN)])

        logger.info("Writing capture to %s for %ds", output_path, duration)
        try:
            subprocess.run(cmd, check=True, timeout=duration + 30)
        except FileNotFoundError:
            raise CaptureError(f"dumpcap not found at '{config.DUMPCAP_PATH}'")
        except Exception as exc:
            raise CaptureError(f"PCAP capture failed: {exc}") from exc

        return output_path
