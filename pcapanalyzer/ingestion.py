"""
ingestion.py - PCAP file validation, metadata extraction, and flow generation.

Handles the initial stage of the analysis pipeline: verifying file integrity,
reading packet-level metadata, and emitting flow tuples for downstream modules.
Uses a streaming / generator-based approach to limit memory consumption on
large captures.
"""

from __future__ import annotations

import os
from collections import defaultdict
from datetime import datetime
from pathlib import Path
from typing import Generator, Optional

from scapy.all import PcapReader, IP, IPv6, TCP, UDP, ICMP  # type: ignore[import-untyped]

from . import config
from .models import FlowMetadata, FlowTuple, PcapMetadata, IngestionError, Severity
from .utils import get_logger

logger = get_logger("ingestion")


# ---------------------------------------------------------------------------
# Validation
# ---------------------------------------------------------------------------

def validate_pcap(filepath: str | Path) -> Path:
    """Validate that *filepath* is an existing, readable, non-empty PCAP file
    whose magic bytes are recognised.

    Args:
        filepath: Path to the candidate PCAP file.

    Returns:
        Resolved ``Path`` on success.

    Raises:
        IngestionError: If any validation step fails.
    """
    path = Path(filepath).resolve()

    if not path.exists():
        raise IngestionError(f"File does not exist: {path}")
    if not path.is_file():
        raise IngestionError(f"Path is not a regular file: {path}")

    file_size = path.stat().st_size
    if file_size == 0:
        raise IngestionError(f"File is empty: {path}")
    if file_size > config.MAX_PCAP_SIZE_BYTES:
        raise IngestionError(
            f"File exceeds maximum allowed size "
            f"({file_size} > {config.MAX_PCAP_SIZE_BYTES} bytes)."
        )

    # Magic-byte check (first 4 bytes)
    try:
        with open(path, "rb") as fh:
            magic = fh.read(4)
    except OSError as exc:
        raise IngestionError(f"Cannot read file header: {exc}") from exc

    if magic not in config.VALID_MAGIC_BYTES:
        raise IngestionError(
            f"Unrecognised PCAP magic bytes: {magic.hex()}. "
            "File may be corrupt or in an unsupported format."
        )

    logger.info("PCAP validated: %s (%s)", path.name, _human_size(file_size))
    return path


# ---------------------------------------------------------------------------
# Metadata Extraction (streaming)
# ---------------------------------------------------------------------------

def extract_metadata(filepath: str | Path) -> PcapMetadata:
    """Read the PCAP file once to collect high-level metadata.

    The file is opened with ``PcapReader`` (streaming) so that even very
    large captures do not exhaust memory.

    Args:
        filepath: Validated PCAP file path.

    Returns:
        Populated ``PcapMetadata`` instance.
    """
    path = Path(filepath).resolve()
    file_size = path.stat().st_size

    src_ips: set[str] = set()
    dst_ips: set[str] = set()
    packet_count = 0
    tcp_count = 0
    udp_count = 0
    dns_count = 0
    http_count = 0
    tls_count = 0
    first_ts: Optional[datetime] = None
    last_ts: Optional[datetime] = None
    link_type = "UNKNOWN"

    try:
        with PcapReader(str(path)) as reader:
            link_type = str(reader.linktype)
            for pkt in reader:
                packet_count += 1
                ts = datetime.fromtimestamp(float(pkt.time))
                if first_ts is None or ts < first_ts:
                    first_ts = ts
                if last_ts is None or ts > last_ts:
                    last_ts = ts

                # IP layer extraction
                ip_layer = pkt.getlayer(IP) or pkt.getlayer(IPv6)
                if ip_layer is not None:
                    src = getattr(ip_layer, "src", "")
                    dst = getattr(ip_layer, "dst", "")
                    if src:
                        src_ips.add(src)
                    if dst:
                        dst_ips.add(dst)

                # Protocol counters
                if pkt.haslayer(TCP):
                    tcp_count += 1
                    dport = pkt[TCP].dport
                    if dport == 53 or pkt[TCP].sport == 53:
                        dns_count += 1
                    elif dport == 80 or pkt[TCP].sport == 80:
                        http_count += 1
                    elif dport == 443 or pkt[TCP].sport == 443:
                        tls_count += 1
                elif pkt.haslayer(UDP):
                    udp_count += 1
                    dport = pkt[UDP].dport
                    if dport == 53 or pkt[UDP].sport == 53:
                        dns_count += 1

    except Exception as exc:
        raise IngestionError(f"Failed to read PCAP packets: {exc}") from exc

    capture_duration = 0.0
    if first_ts and last_ts:
        capture_duration = (last_ts - first_ts).total_seconds()

    meta = PcapMetadata(
        filename=path.name,
        file_size=file_size,
        packet_count=packet_count,
        capture_duration=capture_duration,
        link_type=link_type,
        first_packet_time=first_ts,
        last_packet_time=last_ts,
        unique_src_ips=len(src_ips),
        unique_dst_ips=len(dst_ips),
        tcp_packet_count=tcp_count,
        udp_packet_count=udp_count,
        dns_packet_count=dns_count,
        http_packet_count=http_count,
        tls_packet_count=tls_count,
    )

    logger.info(
        "Metadata extracted: %d packets over %.1fs (%d TCP, %d UDP)",
        packet_count, capture_duration, tcp_count, udp_count,
    )
    return meta


# ---------------------------------------------------------------------------
# Flow Generation (generator-based, memory-efficient)
# ---------------------------------------------------------------------------

def generate_flows(filepath: str | Path) -> Generator[FlowMetadata, None, None]:
    """Yield ``FlowMetadata`` objects by streaming through the PCAP.

    Packets are grouped into flows keyed by the 5-tuple
    ``(src_ip, dst_ip, src_port, dst_port, protocol)``. Because the full
    capture is never loaded into memory, this scales to multi-GB files.

    Args:
        filepath: Validated PCAP file path.

    Yields:
        ``FlowMetadata`` for each unique flow observed.
    """
    path = Path(filepath).resolve()
    flows: dict[tuple, FlowMetadata] = {}

    try:
        with PcapReader(str(path)) as reader:
            for pkt in reader:
                try:
                    flow, meta = _packet_to_flow(pkt)
                    if flow is None:
                        continue
                    key = (
                        flow.src_ip, flow.dst_ip,
                        flow.src_port, flow.dst_port, flow.protocol,
                    )
                    if key in flows:
                        existing = flows[key]
                        existing.packet_count += 1
                        pkt_len = len(pkt)
                        existing.byte_count += pkt_len
                        ts = datetime.fromtimestamp(float(pkt.time))
                        if existing.first_seen is None or ts < existing.first_seen:
                            existing.first_seen = ts
                        if existing.last_seen is None or ts > existing.last_seen:
                            existing.last_seen = ts
                    else:
                        ts = datetime.fromtimestamp(float(pkt.time))
                        pkt_len = len(pkt)
                        new_meta = FlowMetadata(
                            flow=flow,
                            packet_count=1,
                            byte_count=pkt_len,
                            first_seen=ts,
                            last_seen=ts,
                        )
                        flows[key] = new_meta
                except Exception as exc:
                    logger.debug("Skipping malformed packet: %s", exc)
                    continue

    except Exception as exc:
        raise IngestionError(f"Failed to enumerate flows: {exc}") from exc

    logger.info("Extracted %d unique flows", len(flows))
    yield from flows.values()


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _packet_to_flow(pkt) -> tuple[Optional[FlowTuple], None]:
    """Derive a ``FlowTuple`` from a Scapy packet.

    Returns ``(FlowTuple, None)`` or ``(None, None)`` for non-IP packets.
    """
    ip_layer = pkt.getlayer(IP) or pkt.getlayer(IPv6)
    if ip_layer is None:
        return None, None

    src_ip: str = getattr(ip_layer, "src", "0.0.0.0")
    dst_ip: str = getattr(ip_layer, "dst", "0.0.0.0")
    proto_num: int = getattr(ip_layer, "proto", 0)

    src_port = 0
    dst_port = 0

    if pkt.haslayer(TCP):
        src_port = pkt[TCP].sport
        dst_port = pkt[TCP].dport
    elif pkt.haslayer(UDP):
        src_port = pkt[UDP].sport
        dst_port = pkt[UDP].dport

    return FlowTuple(
        src_ip=src_ip,
        dst_ip=dst_ip,
        src_port=src_port,
        dst_port=dst_port,
        protocol=proto_num,
    ), None


def _human_size(n: int) -> str:
    """Quick human-readable file-size string."""
    for unit in ("B", "KB", "MB", "GB"):
        if abs(n) < 1024.0:
            return f"{n:.1f} {unit}"
        n /= 1024.0  # type: ignore[assignment]
    return f"{n:.1f} TB"
