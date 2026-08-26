"""
extractor.py - TCP/UDP stream reassembly and file carving.

Reconstructs application-layer streams from the PCAP, identifies embedded
files by magic-byte signatures, computes cryptographic hashes for every
carved payload, and stores them in a quarantined output directory.
"""

from __future__ import annotations

import os
from collections import defaultdict
from datetime import datetime
from pathlib import Path
from typing import Generator, Optional

from scapy.all import PcapReader, IP, IPv6, TCP, UDP, Raw  # type: ignore[import-untyped]

from . import config
from .models import CarvedFile, FileType, Severity
from .utils import (
    get_logger,
    compute_hashes,
    ensure_directory,
    safe_hex,
)

logger = get_logger("extractor")


# ---------------------------------------------------------------------------
# Stream Reassembly
# ---------------------------------------------------------------------------

class _StreamBuffer:
    """Mutable buffer accumulating raw payload bytes for a single flow."""

    __slots__ = ("src_ip", "dst_ip", "src_port", "dst_port", "protocol",
                 "packets", "total_bytes", "first_ts", "last_ts")

    def __init__(
        self, src_ip: str, dst_ip: str,
        src_port: int, dst_port: int, protocol: str = "TCP",
    ) -> None:
        self.src_ip = src_ip
        self.dst_ip = dst_ip
        self.src_port = src_port
        self.dst_port = dst_port
        self.protocol = protocol
        self.packets: list[tuple[bytes, float]] = []  # (payload, timestamp)
        self.total_bytes: int = 0
        self.first_ts: Optional[float] = None
        self.last_ts: Optional[float] = None

    @property
    def key(self) -> tuple:
        return (self.src_ip, self.dst_ip, self.src_port, self.dst_port)

    def append(self, payload: bytes, ts: float) -> None:
        self.packets.append((payload, ts))
        self.total_bytes += len(payload)
        if self.first_ts is None or ts < self.first_ts:
            self.first_ts = ts
        if self.last_ts is None or ts > self.last_ts:
            self.last_ts = ts

    def reassembled(self) -> bytes:
        """Return concatenated payloads (simple in-order reassembly)."""
        return b"".join(p for p, _ in self.packets)

    def flush(self) -> bytes:
        """Return reassembled data and clear the buffer."""
        data = self.reassembled()
        self.packets.clear()
        self.total_bytes = 0
        return data


def reassemble_streams(
    filepath: str,
    max_buffer: int = config.MAX_STREAM_BUFFER_SIZE,
) -> Generator[tuple[tuple, bytes], None, None]:
    """Stream through the PCAP and yield reassembled TCP/UDP payloads.

    Buffers are flushed when they exceed *max_buffer* bytes to bound
    memory usage.

    Args:
        filepath: Path to a validated PCAP file.
        max_buffer: Maximum bytes to hold before flushing.

    Yields:
        ``(flow_key, reassembled_bytes)`` tuples.
    """
    buffers: dict[tuple, _StreamBuffer] = {}

    try:
        with PcapReader(filepath) as reader:
            for pkt in reader:
                try:
                    ip_layer = pkt.getlayer(IP) or pkt.getlayer(IPv6)
                    if ip_layer is None:
                        continue
                    if not pkt.haslayer(Raw):
                        continue

                    src_ip = getattr(ip_layer, "src", "0.0.0.0")
                    dst_ip = getattr(ip_layer, "dst", "0.0.0.0")
                    payload = bytes(pkt[Raw].load)
                    ts = float(pkt.time)

                    src_port = dst_port = 0
                    proto = "TCP"
                    if pkt.haslayer(TCP):
                        src_port = pkt[TCP].sport
                        dst_port = pkt[TCP].dport
                    elif pkt.haslayer(UDP):
                        src_port = pkt[UDP].sport
                        dst_port = pkt[UDP].dport
                        proto = "UDP"
                    else:
                        continue

                    buf_key = (src_ip, dst_ip, src_port, dst_port)
                    buf = buffers.get(buf_key)
                    if buf is None:
                        buf = _StreamBuffer(
                            src_ip, dst_ip, src_port, dst_port, proto,
                        )
                        buffers[buf_key] = buf

                    buf.append(payload, ts)

                    # Flush to bound memory
                    if buf.total_bytes >= max_buffer:
                        data = buf.flush()
                        if len(data) >= config.MIN_CARVED_FILE_SIZE:
                            yield buf_key, data

                except Exception as exc:
                    logger.debug("Stream reassembly packet error: %s", exc)
                    continue

        # Flush remaining buffers
        for key, buf in buffers.items():
            data = buf.flush()
            if len(data) >= config.MIN_CARVED_FILE_SIZE:
                yield key, data

    except Exception as exc:
        logger.error("Stream reassembly failed: %s", exc)


# ---------------------------------------------------------------------------
# File Carving
# ---------------------------------------------------------------------------

def _identify_file_type(data: bytes) -> tuple[FileType, str]:
    """Identify file type from magic bytes at offset 0.

    Returns:
        ``(FileType, magic_hex_description)`` tuple.
    """
    for ftype, signatures in config.FILE_SIGNATURES.items():
        for sig in signatures:
            if data[:len(sig)] == sig:
                file_type_map = {
                    "executable": FileType.EXECUTABLE,
                    "script": FileType.SCRIPT,
                    "document": FileType.DOCUMENT,
                    "archive": FileType.ARCHIVE,
                    "image": FileType.IMAGE,
                }
                return file_type_map.get(ftype, FileType.UNKNOWN), sig.hex()

    return FileType.UNKNOWN, safe_hex(data[:16], max_len=32)


def carve_files(
    filepath: str,
    quarantine_dir: Optional[Path] = None,
) -> list[CarvedFile]:
    """Reassemble streams, identify embedded files, hash, and quarantine.

    This is the main public entry-point for the extraction module.

    Args:
        filepath: Path to a validated PCAP file.
        quarantine_dir: Directory to store carved files. Defaults to
            ``config.QUARANTINE_DIR``.

    Returns:
        List of ``CarvedFile`` descriptors.
    """
    qdir = quarantine_dir or config.QUARANTINE_DIR
    ensure_directory(qdir)

    carved: list[CarvedFile] = []
    file_counter = 0

    for flow_key, stream_data in reassemble_streams(filepath):
        # Only attempt carving on streams large enough
        if len(stream_data) < config.MIN_CARVED_FILE_SIZE:
            continue

        # Check for embedded files at common offsets
        offsets = _find_file_offsets(stream_data)
        if not offsets:
            # Still try the beginning of the stream
            offsets = [0]

        for offset in offsets:
            chunk = stream_data[offset:]
            if len(chunk) < config.MIN_CARVED_FILE_SIZE:
                continue

            file_type, magic_hex = _identify_file_type(chunk)
            if file_type == FileType.UNKNOWN:
                # Skip truly unknown types to reduce noise
                # But still capture large payloads
                if len(chunk) < 1024:
                    continue

            hashes = compute_hashes(chunk)
            file_counter += 1

            ext_map = {
                FileType.EXECUTABLE: ".bin",
                FileType.SCRIPT: ".scr",
                FileType.DOCUMENT: ".doc",
                FileType.ARCHIVE: ".zip",
                FileType.IMAGE: ".img",
                FileType.UNKNOWN: ".raw",
            }
            ext = ext_map.get(file_type, ".raw")
            fname = f"carved_{file_counter:04d}{ext}"
            quarantine_path = qdir / fname

            try:
                quarantine_path.write_bytes(chunk)
            except OSError as exc:
                logger.error("Failed to write quarantined file %s: %s", fname, exc)
                continue

            cf = CarvedFile(
                filename=fname,
                file_type=file_type,
                size=len(chunk),
                md5=hashes["md5"],
                sha1=hashes["sha1"],
                sha256=hashes["sha256"],
                quarantine_path=str(quarantine_path),
                src_ip=flow_key[0],
                dst_ip=flow_key[1],
                src_port=flow_key[2],
                dst_port=flow_key[3],
                magic_bytes=magic_hex,
            )
            carved.append(cf)

            logger.info(
                "Carved file: %s (%s, %d bytes, MD5=%s)",
                fname, file_type.value, len(chunk), hashes["md5"][:12],
            )

    logger.info(
        "Carving complete: %d files extracted from %s", len(carved), filepath,
    )
    return carved


def _find_file_offsets(data: bytes) -> list[int]:
    """Scan *data* for known file-type magic bytes and return their offsets."""
    offsets: list[int] = []
    for signatures in config.FILE_SIGNATURES.values():
        for sig in signatures:
            idx = 0
            while True:
                pos = data.find(sig, idx)
                if pos == -1:
                    break
                offsets.append(pos)
                idx = pos + 1
    # Deduplicate and sort
    return sorted(set(offsets))
