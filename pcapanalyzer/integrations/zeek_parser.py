"""
zeek_parser.py - Zeek (Bro) log parser for network forensic integration.

Parses Zeek connection.log, dns.log, http.log, ssl.log, and files.log
for integration with the xPREDATOR-EYE analysis pipeline.
"""

from __future__ import annotations

import csv
from dataclasses import dataclass, field
from datetime import datetime
from pathlib import Path
from typing import Generator, Optional

from ..utils import get_logger

logger = get_logger("zeek_parser")


@dataclass
class ZeekConnection:
    ts: datetime
    uid: str
    orig_h: str
    orig_p: int
    resp_h: str
    resp_p: int
    proto: str
    service: str
    duration: float
    orig_bytes: int
    resp_bytes: int
    conn_state: str
    orig_pkts: int = 0
    resp_pkts: int = 0


@dataclass
class ZeekDNS:
    ts: datetime
    uid: str
    query: str
    qtype_name: str
    rcode_name: str
    answers: list[str] = field(default_factory=list)
    orig_h: str = ""
    resp_h: str = ""


@dataclass
class ZeekHTTP:
    ts: datetime
    uid: str
    method: str
    host: str
    uri: str
    user_agent: str = ""
    status_code: int = 0
    orig_h: str = ""
    resp_h: str = ""


class ZeekLogParser:
    """Parse Zeek log files and convert to xPREDATOR-EYE models."""

    def __init__(self, log_dir: str | Path) -> None:
        self.log_dir = Path(log_dir)

    def parse_connection_log(self) -> list[ZeekConnection]:
        connections = []
        log_file = self.log_dir / "conn.log"
        if not log_file.exists():
            logger.warning("conn.log not found at %s", log_file)
            return connections

        try:
            with open(log_file, "r", encoding="utf-8", errors="replace") as f:
                for line in f:
                    if line.startswith("#") or not line.strip():
                        continue
                    parts = line.strip().split("\t")
                    if len(parts) < 21:
                        continue
                    try:
                        connections.append(ZeekConnection(
                            ts=datetime.fromtimestamp(float(parts[0])),
                            uid=parts[1], orig_h=parts[2], orig_p=int(parts[3]),
                            resp_h=parts[4], resp_p=int(parts[5]),
                            proto=parts[6], service=parts[7],
                            duration=float(parts[8]) if parts[8] != "-" else 0.0,
                            orig_bytes=int(parts[9]) if parts[9] != "-" else 0,
                            resp_bytes=int(parts[10]) if parts[10] != "-" else 0,
                            conn_state=parts[11],
                            orig_pkts=int(parts[16]) if parts[16] != "-" else 0,
                            resp_pkts=int(parts[18]) if parts[18] != "-" else 0,
                        ))
                    except (ValueError, IndexError):
                        continue
        except Exception as exc:
            logger.error("Failed to parse conn.log: %s", exc)

        logger.info("Parsed %d Zeek connections", len(connections))
        return connections

    def parse_dns_log(self) -> list[ZeekDNS]:
        queries = []
        log_file = self.log_dir / "dns.log"
        if not log_file.exists():
            return queries

        try:
            with open(log_file, "r", encoding="utf-8", errors="replace") as f:
                for line in f:
                    if line.startswith("#") or not line.strip():
                        continue
                    parts = line.strip().split("\t")
                    if len(parts) < 10:
                        continue
                    try:
                        answers = parts[11].split(",") if len(parts) > 11 and parts[11] != "-" else []
                        queries.append(ZeekDNS(
                            ts=datetime.fromtimestamp(float(parts[0])),
                            uid=parts[1], orig_h=parts[2],
                            resp_h=parts[4], query=parts[9],
                            qtype_name=parts[13] if len(parts) > 13 else "",
                            rcode_name=parts[15] if len(parts) > 15 else "",
                            answers=answers,
                        ))
                    except (ValueError, IndexError):
                        continue
        except Exception as exc:
            logger.error("Failed to parse dns.log: %s", exc)

        logger.info("Parsed %d Zeek DNS queries", len(queries))
        return queries

    def parse_http_log(self) -> list[ZeekHTTP]:
        requests = []
        log_file = self.log_dir / "http.log"
        if not log_file.exists():
            return requests

        try:
            with open(log_file, "r", encoding="utf-8", errors="replace") as f:
                for line in f:
                    if line.startswith("#") or not line.strip():
                        continue
                    parts = line.strip().split("\t")
                    if len(parts) < 14:
                        continue
                    try:
                        requests.append(ZeekHTTP(
                            ts=datetime.fromtimestamp(float(parts[0])),
                            uid=parts[1], orig_h=parts[2],
                            resp_h=parts[4], method=parts[7],
                            host=parts[8], uri=parts[9],
                            user_agent=parts[11] if len(parts) > 11 else "",
                            status_code=int(parts[14]) if len(parts) > 14 and parts[14] != "-" else 0,
                        ))
                    except (ValueError, IndexError):
                        continue
        except Exception as exc:
            logger.error("Failed to parse http.log: %s", exc)

        logger.info("Parsed %d Zeek HTTP requests", len(requests))
        return requests

    def to_behavior_events(self) -> list:
        """Convert all Zeek logs to BehaviorEvent objects."""
        from ..models import BehaviorEvent, KillChainPhase, MITRETactic
        events = []

        for conn in self.parse_connection_log():
            events.append(BehaviorEvent(
                timestamp=conn.ts, event_type="network_connect",
                src_ip=conn.orig_h, dst_ip=conn.resp_h,
                dst_port=conn.resp_p,
                raw_data={"proto": conn.proto, "bytes": conn.orig_bytes + conn.resp_bytes},
            ))

        for dns in self.parse_dns_log():
            events.append(BehaviorEvent(
                timestamp=dns.ts, event_type="dns_query",
                src_ip=dns.orig_h, dst_ip=dns.resp_h,
                target=dns.query,
                raw_data={"answers": dns.answers, "rcode": dns.rcode_name},
            ))

        for http in self.parse_http_log():
            events.append(BehaviorEvent(
                timestamp=http.ts, event_type="http_request",
                src_ip=http.orig_h, dst_ip=http.resp_h,
                target=http.host,
                raw_data={"method": http.method, "uri": http.uri, "ua": http.user_agent, "status": http.status_code},
            ))

        return events
