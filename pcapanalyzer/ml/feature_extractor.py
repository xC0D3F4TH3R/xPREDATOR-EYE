"""
feature_extractor.py - ML feature extraction from network flows and system events.

Extracts numerical features suitable for machine learning classification
of network traffic (benign, malware, C2, exfiltration, DoS, etc.).
"""

from __future__ import annotations

import math
from collections import Counter, defaultdict
from dataclasses import dataclass, field
from typing import Optional

from ..utils import get_logger, calculate_shannon_entropy

logger = get_logger("feature_extractor")


@dataclass
class FlowFeatures:
    """Feature vector extracted from a network flow."""
    src_ip: str = ""
    dst_ip: str = ""
    src_port: int = 0
    dst_port: int = 0
    protocol: int = 0
    duration: float = 0.0
    packet_count: int = 0
    byte_count: int = 0
    packets_per_second: float = 0.0
    bytes_per_second: float = 0.0
    avg_packet_size: float = 0.0
    std_packet_size: float = 0.0
    avg_inter_arrival: float = 0.0
    std_inter_arrival: float = 0.0
    min_inter_arrival: float = 0.0
    max_inter_arrival: float = 0.0
    tcp_syn_count: int = 0
    tcp_ack_count: int = 0
    tcp_fin_count: int = 0
    tcp_rst_count: int = 0
    byte_ratio_out_in: float = 0.0
    payload_entropy: float = 0.0
    unique_dst_ports: int = 0
    is_well_known_port: int = 0
    label: str = "unknown"

    def to_vector(self) -> list[float]:
        """Convert to a numerical feature vector for ML."""
        return [
            self.duration,
            self.packet_count,
            self.byte_count,
            self.packets_per_second,
            self.bytes_per_second,
            self.avg_packet_size,
            self.std_packet_size,
            self.avg_inter_arrival,
            self.std_inter_arrival,
            self.min_inter_arrival,
            self.max_inter_arrival,
            self.tcp_syn_count,
            self.tcp_ack_count,
            self.tcp_fin_count,
            self.tcp_rst_count,
            self.byte_ratio_out_in,
            self.payload_entropy,
            self.unique_dst_ports,
            self.is_well_known_port,
            self.src_port / 65535.0,
            self.dst_port / 65535.0,
            self.protocol / 255.0,
        ]

    @staticmethod
    def feature_names() -> list[str]:
        return [
            "duration", "packet_count", "byte_count",
            "packets_per_second", "bytes_per_second",
            "avg_packet_size", "std_packet_size",
            "avg_inter_arrival", "std_inter_arrival",
            "min_inter_arrival", "max_inter_arrival",
            "tcp_syn_count", "tcp_ack_count", "tcp_fin_count", "tcp_rst_count",
            "byte_ratio_out_in", "payload_entropy",
            "unique_dst_ports", "is_well_known_port",
            "src_port_norm", "dst_port_norm", "protocol_norm",
        ]


class FeatureExtractor:
    """Extracts ML features from parsed network data."""

    WELL_KNOWN_PORTS = {80, 443, 53, 25, 110, 143, 993, 995, 21, 22, 23, 3389, 3306, 5432, 8080, 8443}

    def extract_from_flows(
        self,
        flows: list,
        dns_queries: Optional[list] = None,
        http_requests: Optional[list] = None,
        tls_sessions: Optional[list] = None,
    ) -> list[FlowFeatures]:
        """Extract features from FlowMetadata objects."""
        features_list = []
        dns_by_ip = self._index_by_ip(dns_queries or [])
        http_by_ip = self._index_by_ip(http_requests or [])
        tls_by_ip = self._index_by_ip(tls_sessions or [])

        for flow_meta in flows:
            ft = flow_meta.flow
            duration = 0.0
            if flow_meta.first_seen and flow_meta.last_seen:
                duration = (flow_meta.last_seen - flow_meta.first_seen).total_seconds()

            pps = flow_meta.packet_count / max(duration, 0.001)
            bps = flow_meta.byte_count / max(duration, 0.001)
            avg_pkt = flow_meta.byte_count / max(flow_meta.packet_count, 1)

            ff = FlowFeatures(
                src_ip=ft.src_ip, dst_ip=ft.dst_ip,
                src_port=ft.src_port, dst_port=ft.dst_port,
                protocol=ft.protocol,
                duration=duration,
                packet_count=flow_meta.packet_count,
                byte_count=flow_meta.byte_count,
                packets_per_second=pps,
                bytes_per_second=bps,
                avg_packet_size=avg_pkt,
                is_well_known_port=1 if ft.dst_port in self.WELL_KNOWN_PORTS else 0,
            )

            ff.payload_entropy = self._estimate_flow_entropy(ft.src_ip, ft.dst_ip)
            features_list.append(ff)

        return features_list

    def extract_from_pcap_metadata(self, meta) -> list[float]:
        """Extract high-level features from PcapMetadata."""
        if not meta:
            return [0.0] * 15
        return [
            float(meta.packet_count),
            float(meta.tcp_packet_count),
            float(meta.udp_packet_count),
            float(meta.dns_packet_count),
            float(meta.http_packet_count),
            float(meta.tls_packet_count),
            float(meta.unique_src_ips),
            float(meta.unique_dst_ips),
            meta.capture_duration,
            meta.file_size / (1024 * 1024),
            meta.packet_count / max(meta.capture_duration, 1.0),
            meta.dns_packet_count / max(meta.packet_count, 1),
            meta.http_packet_count / max(meta.packet_count, 1),
            meta.tls_packet_count / max(meta.packet_count, 1),
            meta.udp_packet_count / max(meta.tcp_packet_count, 1),
        ]

    def _estimate_flow_entropy(self, src_ip: str, dst_ip: str) -> float:
        combined = f"{src_ip}:{dst_ip}"
        return calculate_shannon_entropy(combined)

    def _index_by_ip(self, artifacts: list) -> dict[str, list]:
        index = defaultdict(list)
        for a in artifacts:
            ip = getattr(a, "src_ip", None) or getattr(a, "dst_ip", None) or ""
            if ip:
                index[ip].append(a)
        return dict(index)
