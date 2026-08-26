"""
parser.py - Deep application-layer protocol parsing.

Extracts DNS queries/responses, HTTP request metadata, TLS ClientHello /
ServerHello fields, JA3 fingerprints, and cleartext credential artefacts.
Designed to degrade gracefully when protocol fields are absent or malformed.
"""

from __future__ import annotations

import hashlib
import re
from collections import defaultdict
from datetime import datetime
from typing import Optional

from scapy.all import (  # type: ignore[import-untyped]
    PcapReader, IP, IPv6, TCP, UDP, DNS, DNSQR, DNSRR,
    Raw, conf,
)
try:
    from scapy.layers.http import HTTP  # type: ignore[attr-defined]
except ImportError:
    try:
        from scapy.all import HTTP  # type: ignore[attr-defined]
    except ImportError:
        HTTP = None  # type: ignore[assignment,misc]

try:
    from scapy.layers.tls.all import TLS, TLSClientHello, TLSServerHello  # type: ignore[attr-defined]
except ImportError:
    try:
        from scapy.layers.tls.handshake import TLSClientHello, TLSServerHello  # type: ignore[attr-defined]
        from scapy.layers.tls.record import TLS  # type: ignore[attr-defined]
    except ImportError:
        try:
            from scapy.all import TLS, TLSClientHello, TLSServerHello  # type: ignore[attr-defined]
        except ImportError:
            TLS = TLSClientHello = TLSServerHello = None  # type: ignore[assignment,misc]

try:
    from scapy.layers.tls.handshake import TLS_Ext_ServerName  # type: ignore[import-untyped]
except ImportError:
    TLS_Ext_ServerName = None  # type: ignore[assignment,misc]

from . import config
from .models import (
    DNSQuery,
    HTTPRequest,
    TLSMetadata,
    CredentialArtifact,
    Protocol,
    PcapMetadata,
    Severity,
)
from .utils import (
    get_logger,
    calculate_shannon_entropy,
    compile_patterns,
    safe_hex,
)

logger = get_logger("parser")

# Pre-compile credential regexes once.
_CRED_RE = compile_patterns(config.CREDENTIAL_PATTERNS)


# ---------------------------------------------------------------------------
# DNS Parsing
# ---------------------------------------------------------------------------

def parse_dns(filepath: str) -> list[DNSQuery]:
    """Stream-parse the PCAP and return all DNS query/response records.

    Args:
        filepath: Path to a validated PCAP file.

    Returns:
        List of ``DNSQuery`` objects.
    """
    queries: list[DNSQuery] = []

    try:
        with PcapReader(filepath) as reader:
            for pkt in reader:
                try:
                    if not pkt.haslayer(DNS):
                        continue
                    dns = pkt[DNS]
                    ts = datetime.fromtimestamp(float(pkt.time))

                    src_ip = ""
                    if pkt.haslayer(IP):
                        src_ip = pkt[IP].src

                    # DNS Queries (qd section)
                    if dns.qr == 0 and dns.qdcount > 0:
                        qname = dns.qd.qname.decode("utf-8", errors="replace").rstrip(".")
                        qtype = _dns_type_str(dns.qd.qtype)
                        entropy = calculate_shannon_entropy(qname)
                        high_entropy = entropy > config.DNS_ENTROPY_THRESHOLD
                        possible_dga = (
                            high_entropy
                            and any(
                                len(label) >= config.DNS_DGA_MIN_LABEL_LENGTH
                                for label in qname.split(".")
                            )
                        )

                        dq = DNSQuery(
                            query_name=qname,
                            query_type=qtype,
                            timestamp=ts,
                            src_ip=src_ip,
                            high_entropy=high_entropy,
                            possible_dga=possible_dga,
                        )

                        # Attach any answers from the same packet
                        if dns.ancount > 0:
                            rr = dns.an
                            while rr:
                                if rr.type == 1:  # A record
                                    dq.resolved_ips.append(rr.rdata)
                                    dq.ttl = rr.ttl
                                dq.response_codes.append(_dns_type_str(rr.type))
                                rr = rr.payload if hasattr(rr, "payload") else None
                                if rr is None or not hasattr(rr, "type"):
                                    break

                        queries.append(dq)

                        if possible_dga:
                            logger.warning(
                                "Possible DGA domain detected: %s (entropy=%.2f)",
                                qname, entropy,
                            )
                    elif dns.qr == 1 and dns.ancount > 0:
                        # Response-only packets (no query name in qd)
                        pass

                except Exception as exc:
                    logger.debug("DNS parse error: %s", exc)
                    continue

    except Exception as exc:
        logger.error("Failed to open PCAP for DNS parsing: %s", exc)

    logger.info("Parsed %d DNS queries", len(queries))
    return queries


def _dns_type_str(dns_type: int) -> str:
    """Map DNS record type integer to human-readable string."""
    mapping = {
        1: "A", 2: "NS", 5: "CNAME", 6: "SOA", 12: "PTR",
        15: "MX", 16: "TXT", 28: "AAAA", 33: "SRV", 41: "OPT",
        43: "DS", 46: "RRSIG", 47: "NSEC", 48: "DNSKEY",
        252: "AXFR", 255: "ANY", 256: "URI",
    }
    return mapping.get(dns_type, f"TYPE{dns_type}")


# ---------------------------------------------------------------------------
# HTTP Parsing
# ---------------------------------------------------------------------------

def parse_http(filepath: str) -> list[HTTPRequest]:
    """Stream-parse the PCAP and extract HTTP request metadata.

    Args:
        filepath: Path to a validated PCAP file.

    Returns:
        List of ``HTTPRequest`` objects.
    """
    requests: list[HTTPRequest] = []

    try:
        with PcapReader(filepath) as reader:
            for pkt in reader:
                try:
                    if not pkt.haslayer(TCP):
                        continue
                    if not pkt.haslayer(Raw):
                        continue

                    payload = bytes(pkt[Raw].load)
                    # Quick check: does it look like an HTTP request line?
                    if not _is_http_request(payload):
                        continue

                    ts = datetime.fromtimestamp(float(pkt.time))
                    req = _parse_http_request_payload(payload, pkt, ts)
                    if req is not None:
                        requests.append(req)

                except Exception as exc:
                    logger.debug("HTTP parse error: %s", exc)
                    continue

    except Exception as exc:
        logger.error("Failed to open PCAP for HTTP parsing: %s", exc)

    logger.info("Parsed %d HTTP requests", len(requests))
    return requests


def _is_http_request(data: bytes) -> bool:
    """Heuristic: does *data* start with an HTTP method token?"""
    methods = (b"GET ", b"POST ", b"PUT ", b"DELETE ", b"HEAD ",
               b"OPTIONS ", b"PATCH ", b"CONNECT ", b"TRACE ")
    return any(data.startswith(m) for m in methods)


def _parse_http_request_payload(
    data: bytes, pkt, ts: datetime
) -> Optional[HTTPRequest]:
    """Parse raw bytes into an ``HTTPRequest``."""
    try:
        text = data.decode("utf-8", errors="replace")
        lines = text.split("\r\n")
        if not lines:
            return None

        # Request line: METHOD URI HTTP/x.y
        parts = lines[0].split(" ", 2)
        if len(parts) < 3:
            return None
        method, uri, _ = parts[0], parts[1], parts[2]

        headers: dict[str, str] = {}
        for line in lines[1:]:
            if not line.strip():
                break
            if ": " in line:
                k, v = line.split(": ", 1)
                headers[k.strip()] = v.strip()

        src_ip = dst_ip = ""
        src_port = dst_port = 0
        if pkt.haslayer(IP):
            src_ip = pkt[IP].src
            dst_ip = pkt[IP].dst
        if pkt.haslayer(TCP):
            src_port = pkt[TCP].sport
            dst_port = pkt[TCP].dport

        return HTTPRequest(
            method=method,
            uri=uri,
            host=headers.get("Host", ""),
            user_agent=headers.get("User-Agent", ""),
            content_type=headers.get("Content-Type", ""),
            content_length=int(headers.get("Content-Length", 0)),
            headers=headers,
            timestamp=ts,
            src_ip=src_ip,
            dst_ip=dst_ip,
            src_port=src_port,
            dst_port=dst_port,
        )
    except Exception as exc:
        logger.debug("HTTP request parse failure: %s", exc)
        return None


# ---------------------------------------------------------------------------
# TLS / JA3 Parsing
# ---------------------------------------------------------------------------

def parse_tls(filepath: str) -> list[TLSMetadata]:
    """Stream-parse TLS ClientHello and ServerHello messages.

    Extracts SNI, JA3 fingerprint, cipher suite, and certificate details.

    Args:
        filepath: Path to a validated PCAP file.

    Returns:
        List of ``TLSMetadata`` objects (one per observed TLS session).
    """
    sessions: dict[tuple, TLSMetadata] = {}

    try:
        with PcapReader(filepath) as reader:
            for pkt in reader:
                try:
                    if not pkt.haslayer(TLS):
                        continue

                    ts = datetime.fromtimestamp(float(pkt.time))
                    src_ip = dst_ip = ""
                    src_port = dst_port = 0
                    if pkt.haslayer(IP):
                        src_ip = pkt[IP].src
                        dst_ip = pkt[IP].dst
                    if pkt.haslayer(TCP):
                        src_port = pkt[TCP].sport
                        dst_port = pkt[TCP].dport

                    key = (src_ip, dst_ip, src_port, dst_port)

                    tls = pkt[TLS]
                    # ClientHello
                    if pkt.haslayer(TLSClientHello):
                        ch = pkt[TLSClientHello]
                        meta = sessions.setdefault(
                            key,
                            TLSMetadata(
                                src_ip=src_ip, dst_ip=dst_ip,
                                src_port=src_port, dst_port=dst_port,
                                timestamp=ts,
                            ),
                        )
                        # SNI extraction
                        sni_ext = ch.get_extension(0)  # server_name extension
                        if sni_ext is not None:
                            try:
                                meta.sni = sni_ext.server_names[0].name.decode(
                                    "utf-8", errors="replace"
                                )
                            except Exception:
                                pass

                        # JA3 fingerprint
                        meta.ja3 = _compute_ja3(ch)

                        # TLS version
                        meta.version = f"TLS {ch.version // 256}.{ch.version % 256}"

                        # Cipher suites
                        if hasattr(ch, "ciphers") and ch.ciphers:
                            meta.cipher_suite = ",".join(str(c) for c in ch.ciphers[:10])

                    # ServerHello
                    if pkt.haslayer(TLSServerHello):
                        sh = pkt[TLSServerHello]
                        meta = sessions.setdefault(
                            key,
                            TLSMetadata(
                                src_ip=src_ip, dst_ip=dst_ip,
                                src_port=src_port, dst_port=dst_port,
                                timestamp=ts,
                            ),
                        )
                        # JA3S
                        meta.ja3s = _compute_ja3s(sh)
                        if hasattr(sh, "cipher") and sh.cipher:
                            meta.cipher_suite = str(sh.cipher)

                except Exception as exc:
                    logger.debug("TLS parse error: %s", exc)
                    continue

    except Exception as exc:
        logger.error("Failed to open PCAP for TLS parsing: %s", exc)

    logger.info("Parsed %d TLS sessions", len(sessions))
    return list(sessions.values())


def _compute_ja3(ch: TLSClientHello) -> str:
    """Compute the JA3 fingerprint from a TLS ClientHello.

    JA3 = MD5(TLSVersion,Ciphers,Extensions,EllipticCurves,EllipticCurvePointFormats)
    """
    try:
        version = ch.version
        ciphers = "-".join(str(c) for c in (ch.ciphers or []))

        extensions = []
        elliptic_curves = []
        ec_point_formats = []

        for ext in (ch.extensions or []):
            eid = ext.type if hasattr(ext, "type") else 0
            extensions.append(str(eid))
            if eid == 10:  # supported_groups / elliptic_curves
                if hasattr(ext, "groups"):
                    elliptic_curves = [str(g) for g in ext.groups]
            elif eid == 11:  # ec_point_formats
                if hasattr(ext, "formats"):
                    ec_point_formats = [str(f) for f in ext.formats]

        ec_str = "-".join(elliptic_curves)
        ecpf_str = "-".join(ec_point_formats)

        raw = f"{version},{ciphers},{','.join(extensions)},{ec_str},{ecpf_str}"
        return hashlib.md5(raw.encode("utf-8")).hexdigest()
    except Exception:
        return ""


def _compute_ja3s(sh: TLSServerHello) -> str:
    """Compute the JA3S fingerprint from a TLS ServerHello.

    JA3S = MD5(TLSVersion,Cipher,Extensions)
    """
    try:
        version = sh.version
        cipher = sh.cipher if hasattr(sh, "cipher") else 0
        extensions = []
        for ext in (sh.extensions or []):
            eid = ext.type if hasattr(ext, "type") else 0
            extensions.append(str(eid))
        raw = f"{version},{cipher},{','.join(extensions)}"
        return hashlib.md5(raw.encode("utf-8")).hexdigest()
    except Exception:
        return ""


# ---------------------------------------------------------------------------
# Cleartext Credential Detection
# ---------------------------------------------------------------------------

def parse_credentials(filepath: str) -> list[CredentialArtifact]:
    """Scan raw packet payloads for cleartext credential patterns.

    Uses pre-compiled regexes from ``config.CREDENTIAL_PATTERNS`` against
    every ``Raw`` layer payload in the capture.

    Args:
        filepath: Path to a validated PCAP file.

    Returns:
        List of ``CredentialArtifact`` objects.
    """
    credentials: list[CredentialArtifact] = []

    try:
        with PcapReader(filepath) as reader:
            for pkt in reader:
                try:
                    if not pkt.haslayer(Raw):
                        continue

                    payload = bytes(pkt[Raw].load)
                    text = payload.decode("utf-8", errors="ignore")
                    if not text:
                        continue

                    for pattern in _CRED_RE:
                        match = pattern.search(text)
                        if match:
                            src_ip = dst_ip = ""
                            if pkt.haslayer(IP):
                                src_ip = pkt[IP].src
                                dst_ip = pkt[IP].dst
                            ts = datetime.fromtimestamp(float(pkt.time))

                            cred = CredentialArtifact(
                                protocol=_identify_cred_protocol(pkt),
                                raw_match=match.group(0)[:200],
                                src_ip=src_ip,
                                dst_ip=dst_ip,
                                timestamp=ts,
                            )
                            # Attempt to split key=value
                            kv = match.group(0)
                            if "=" in kv:
                                k, v = kv.split("=", 1)
                                k = k.strip().lower()
                                v = v.strip()
                                if "user" in k or "login" in k or "email" in k:
                                    cred.username = v
                                elif "pass" in k or "pwd" in k:
                                    cred.password = v
                                elif "authorization" in k:
                                    cred.auth_type = "Basic"
                                    # Decode base64
                                    import base64
                                    try:
                                        decoded = base64.b64decode(v).decode(
                                            "utf-8", errors="replace"
                                        )
                                        if ":" in decoded:
                                            cred.username, cred.password = decoded.split(":", 1)
                                    except Exception:
                                        cred.password = v
                                elif "api" in k or "token" in k or "secret" in k:
                                    cred.auth_type = "API Key"
                                    cred.password = v

                            credentials.append(cred)
                            logger.warning(
                                "Cleartext credential detected: %s from %s",
                                cred.raw_match[:60], src_ip,
                            )
                            break  # one match per packet is enough

                except Exception as exc:
                    logger.debug("Credential scan error: %s", exc)
                    continue

    except Exception as exc:
        logger.error("Failed to open PCAP for credential scanning: %s", exc)

    logger.info("Detected %d credential artefacts", len(credentials))
    return credentials


def _identify_cred_protocol(pkt) -> Protocol:
    """Guess the application protocol carrying the credential."""
    if pkt.haslayer(TCP):
        dport = pkt[TCP].dport
        sport = pkt[TCP].sport
        if dport == 80 or sport == 80:
            return Protocol.HTTP
        if dport == 443 or sport == 443:
            return Protocol.HTTPS
        if dport == 21 or sport == 21:
            return Protocol.FTP
        if dport == 25 or sport == 25 or dport == 587 or sport == 587:
            return Protocol.SMTP
        if dport == 22 or sport == 22:
            return Protocol.SSH
    if pkt.haslayer(UDP):
        dport = pkt[UDP].dport
        if dport == 53:
            return Protocol.DNS
    return Protocol.UNKNOWN
