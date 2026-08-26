"""
intelligence.py - IOC cross-referencing and threat-intelligence enrichment.

Provides a pluggable architecture for matching extracted IOCs (IPs, domains,
file hashes, JA3 fingerprints) against local blocklists and external threat-
intelligence APIs.  Includes rate-limited stubs for VirusTotal and AbuseIPDB
that can be activated by supplying the appropriate API keys via environment
variables.
"""

from __future__ import annotations

import json
import os
import time
from collections import defaultdict
from pathlib import Path
from typing import Optional

import requests  # type: ignore[import-untyped]

from . import config
from .models import (
    IOC,
    IOCType,
    IntelMatch,
    Severity,
    CarvedFile,
    DNSQuery,
    HTTPRequest,
    TLSMetadata,
    CredentialArtifact,
)
from .utils import get_logger

logger = get_logger("intelligence")


# ---------------------------------------------------------------------------
# Local Blocklist Loader
# ---------------------------------------------------------------------------

class LocalBlocklist:
    """In-memory set-based blocklist for fast IOC lookups."""

    def __init__(self) -> None:
        self.ips: set[str] = set()
        self.domains: set[str] = set()
        self.md5_hashes: set[str] = set()
        self.sha256_hashes: set[str] = set()
        self.ja3_hashes: set[str] = set()
        self.user_agents: set[str] = set()

    def load_from_file(self, path: Path) -> None:
        """Load IOCs from a JSON file with keys matching the attributes above.

        Expected format:
        {
            "ips": ["1.2.3.4", ...],
            "domains": ["evil.com", ...],
            "md5_hashes": ["abc...", ...],
            "sha256_hashes": ["def...", ...],
            "ja3_hashes": ["123...", ...],
            "user_agents": ["malicious-ua", ...]
        }
        """
        if not path.exists():
            logger.warning("Blocklist file not found: %s", path)
            return

        try:
            with open(path, "r", encoding="utf-8") as fh:
                data = json.load(fh)
            self.ips.update(data.get("ips", []))
            self.domains.update(data.get("domains", []))
            self.md5_hashes.update(h.lower() for h in data.get("md5_hashes", []))
            self.sha256_hashes.update(h.lower() for h in data.get("sha256_hashes", []))
            self.ja3_hashes.update(h.lower() for h in data.get("ja3_hashes", []))
            self.user_agents.update(data.get("user_agents", []))
            logger.info(
                "Loaded blocklist: %d IPs, %d domains, %d hashes",
                len(self.ips), len(self.domains),
                len(self.md5_hashes) + len(self.sha256_hashes),
            )
        except (json.JSONDecodeError, OSError) as exc:
            logger.error("Failed to load blocklist %s: %s", path, exc)

    def lookup(self, ioc: IOC) -> bool:
        """Return ``True`` if the IOC value is in the blocklist."""
        value_lower = ioc.value.lower()
        match_map = {
            IOCType.IP: self.ips,
            IOCType.DOMAIN: self.domains,
            IOCType.HASH_MD5: self.md5_hashes,
            IOCType.HASH_SHA256: self.sha256_hashes,
            IOCType.JA3: self.ja3_hashes,
            IOCType.USER_AGENT: self.user_agents,
        }
        store = match_map.get(ioc.ioc_type)
        if store is not None:
            return value_lower in store
        return False


# ---------------------------------------------------------------------------
# Rate-Limited API Client
# ---------------------------------------------------------------------------

class _RateLimiter:
    """Simple token-bucket rate limiter for API calls."""

    def __init__(self, max_calls: int, period_seconds: float) -> None:
        self.max_calls = max_calls
        self.period = period_seconds
        self._timestamps: list[float] = []

    def wait(self) -> None:
        """Block until an API call is permitted."""
        now = time.monotonic()
        self._timestamps = [t for t in self._timestamps if now - t < self.period]
        if len(self._timestamps) >= self.max_calls:
            sleep_for = self.period - (now - self._timestamps[0]) + 0.1
            if sleep_for > 0:
                logger.debug("Rate limiter sleeping %.1fs", sleep_for)
                time.sleep(sleep_for)
        self._timestamps.append(time.monotonic())


# ---------------------------------------------------------------------------
# External API Clients (stubs)
# ---------------------------------------------------------------------------

class VirusTotalClient:
    """Rate-limited VirusTotal API v3 client.

    Requires the ``VIRUSTOTAL_API_KEY`` environment variable to be set.
    """

    BASE_URL = "https://www.virustotal.com/api/v3"

    def __init__(self) -> None:
        self.api_key = os.environ.get(config.VT_API_KEY_ENV, "")
        self.enabled = bool(self.api_key)
        self._limiter = _RateLimiter(
            config.INTEL_RATE_LIMIT_RPM, 60.0,
        )

    def lookup_hash(self, hash_value: str) -> Optional[dict]:
        """Look up a file hash on VirusTotal."""
        if not self.enabled:
            logger.debug("VirusTotal API key not set; skipping hash lookup.")
            return None
        self._limiter.wait()
        url = f"{self.BASE_URL}/files/{hash_value}"
        headers = {"x-apikey": self.api_key}
        try:
            resp = requests.get(url, headers=headers, timeout=config.INTEL_REQUEST_TIMEOUT)
            if resp.status_code == 200:
                data = resp.json().get("data", {}).get("attributes", {})
                stats = data.get("last_analysis_stats", {})
                malicious = stats.get("malicious", 0)
                return {
                    "malicious": malicious,
                    "total": sum(stats.values()),
                    "reputation": data.get("reputation", 0),
                    "names": data.get("names", [])[:5],
                }
            elif resp.status_code == 404:
                return {"malicious": 0, "total": 0, "reputation": 0}
            else:
                logger.warning("VT API returned %d for hash %s", resp.status_code, hash_value)
                return None
        except requests.RequestException as exc:
            logger.error("VirusTotal API error: %s", exc)
            return None

    def lookup_ip(self, ip_address: str) -> Optional[dict]:
        """Look up an IP address on VirusTotal."""
        if not self.enabled:
            return None
        self._limiter.wait()
        url = f"{self.BASE_URL}/ip_addresses/{ip_address}"
        headers = {"x-apikey": self.api_key}
        try:
            resp = requests.get(url, headers=headers, timeout=config.INTEL_REQUEST_TIMEOUT)
            if resp.status_code == 200:
                data = resp.json().get("data", {}).get("attributes", {})
                stats = data.get("last_analysis_stats", {})
                return {
                    "malicious": stats.get("malicious", 0),
                    "total": sum(stats.values()),
                    "reputation": data.get("reputation", 0),
                    "country": data.get("country", ""),
                    "as_owner": data.get("as_owner", ""),
                }
            return None
        except requests.RequestException as exc:
            logger.error("VirusTotal API error: %s", exc)
            return None

    def lookup_domain(self, domain: str) -> Optional[dict]:
        """Look up a domain on VirusTotal."""
        if not self.enabled:
            return None
        self._limiter.wait()
        url = f"{self.BASE_URL}/domains/{domain}"
        headers = {"x-apikey": self.api_key}
        try:
            resp = requests.get(url, headers=headers, timeout=config.INTEL_REQUEST_TIMEOUT)
            if resp.status_code == 200:
                data = resp.json().get("data", {}).get("attributes", {})
                stats = data.get("last_analysis_stats", {})
                return {
                    "malicious": stats.get("malicious", 0),
                    "total": sum(stats.values()),
                    "reputation": data.get("reputation", 0),
                }
            return None
        except requests.RequestException as exc:
            logger.error("VirusTotal API error: %s", exc)
            return None


class AbuseIPDBClient:
    """Rate-limited AbuseIPDB API client.

    Requires the ``ABUSEIPDB_API_KEY`` environment variable to be set.
    """

    BASE_URL = "https://api.abuseipdb.com/api/v2"

    def __init__(self) -> None:
        self.api_key = os.environ.get(config.ABUSEIPDB_API_KEY_ENV, "")
        self.enabled = bool(self.api_key)
        self._limiter = _RateLimiter(
            config.INTEL_RATE_LIMIT_RPM, 60.0,
        )

    def lookup_ip(self, ip_address: str) -> Optional[dict]:
        """Look up an IP address on AbuseIPDB."""
        if not self.enabled:
            logger.debug("AbuseIPDB API key not set; skipping IP lookup.")
            return None
        self._limiter.wait()
        url = f"{self.BASE_URL}/check"
        headers = {"Key": self.api_key, "Accept": "application/json"}
        params = {"ipAddress": ip_address, "maxAgeInDays": 90}
        try:
            resp = requests.get(
                url, headers=headers, params=params,
                timeout=config.INTEL_REQUEST_TIMEOUT,
            )
            if resp.status_code == 200:
                data = resp.json().get("data", {})
                return {
                    "abuse_confidence_score": data.get("abuseConfidenceScore", 0),
                    "total_reports": data.get("totalReports", 0),
                    "country_code": data.get("countryCode", ""),
                    "isp": data.get("isp", ""),
                    "usage_type": data.get("usageType", ""),
                }
            else:
                logger.warning(
                    "AbuseIPDB returned %d for %s", resp.status_code, ip_address,
                )
                return None
        except requests.RequestException as exc:
            logger.error("AbuseIPDB API error: %s", exc)
            return None


# ---------------------------------------------------------------------------
# Intelligence Engine (orchestrator)
# ---------------------------------------------------------------------------

class IntelligenceEngine:
    """Cross-references extracted IOCs against local and external intelligence.

    Usage::

        engine = IntelligenceEngine()
        engine.load_blocklist(Path("blocklist.json"))
        matches = engine.analyze(
            dns_queries=dns_list,
            carved_files=files_list,
            tls_sessions=tls_list,
            http_requests=http_list,
        )
    """

    def __init__(self) -> None:
        self.blocklist = LocalBlocklist()
        self.vt_client = VirusTotalClient()
        self.abuseipdb = AbuseIPDBClient()
        self._all_iocs: list[IOC] = []

    def load_blocklist(self, path: Path) -> None:
        """Load a local JSON blocklist from disk."""
        self.blocklist.load_from_file(path)

    def load_default_blocklists(self) -> None:
        """Load any blocklist files found in the project's quarantine/ data dir."""
        data_dir = config.PROJECT_ROOT / "data"
        if data_dir.exists():
            for f in data_dir.glob("*.json"):
                self.load_blocklist(f)

    def extract_iocs(
        self,
        dns_queries: list[DNSQuery] | None = None,
        http_requests: list[HTTPRequest] | None = None,
        tls_sessions: list[TLSMetadata] | None = None,
        carved_files: list[CarvedFile] | None = None,
        credentials: list[CredentialArtifact] | None = None,
    ) -> list[IOC]:
        """Collect all IOCs from parsed artefacts into a unified list."""
        iocs: list[IOC] = []

        if dns_queries:
            for dq in dns_queries:
                if dq.src_ip:
                    iocs.append(IOC(
                        value=dq.src_ip, ioc_type=IOCType.IP,
                        source="dns_query",
                    ))
                iocs.append(IOC(
                    value=dq.query_name, ioc_type=IOCType.DOMAIN,
                    source="dns_query",
                ))
                if dq.possible_dga:
                    iocs[-1].severity = Severity.HIGH
                    iocs[-1].description = "Possible DGA-generated domain"

        if http_requests:
            for hr in http_requests:
                if hr.src_ip:
                    iocs.append(IOC(
                        value=hr.src_ip, ioc_type=IOCType.IP,
                        source="http_request",
                    ))
                if hr.user_agent:
                    iocs.append(IOC(
                        value=hr.user_agent.lower(), ioc_type=IOCType.USER_AGENT,
                        source="http_request",
                    ))

        if tls_sessions:
            for tls in tls_sessions:
                if tls.sni:
                    iocs.append(IOC(
                        value=tls.sni, ioc_type=IOCType.DOMAIN,
                        source="tls_sni",
                    ))
                if tls.ja3:
                    iocs.append(IOC(
                        value=tls.ja3.lower(), ioc_type=IOCType.JA3,
                        source="tls_ja3",
                    ))

        if carved_files:
            for cf in carved_files:
                iocs.append(IOC(
                    value=cf.md5, ioc_type=IOCType.HASH_MD5,
                    source="carved_file",
                ))
                iocs.append(IOC(
                    value=cf.sha256, ioc_type=IOCType.HASH_SHA256,
                    source="carved_file",
                ))

        # Deduplicate by (value, ioc_type)
        seen: set[tuple[str, IOCType]] = set()
        unique: list[IOC] = []
        for ioc in iocs:
            key = (ioc.value, ioc.ioc_type)
            if key not in seen:
                seen.add(key)
                unique.append(ioc)

        self._all_iocs = unique
        logger.info("Extracted %d unique IOCs for intelligence matching", len(unique))
        return unique

    def match_local(self, iocs: list[IOC] | None = None) -> list[IntelMatch]:
        """Cross-reference IOCs against the local blocklist."""
        targets = iocs if iocs is not None else self._all_iocs
        matches: list[IntelMatch] = []

        for ioc in targets:
            if self.blocklist.lookup(ioc):
                match = IntelMatch(
                    ioc=ioc,
                    matched=True,
                    threat_name="BLOCKLIST_MATCH",
                    threat_category="blocklist",
                    confidence=1.0,
                    details=f"IOC '{ioc.value}' found in local blocklist",
                    source="local_blocklist",
                )
                matches.append(match)
                logger.warning(
                    "Blocklist hit: %s=%s", ioc.ioc_type.value, ioc.value,
                )

        logger.info("Local blocklist: %d matches out of %d IOCs", len(matches), len(targets))
        return matches

    def enrich_external(self, iocs: list[IOC] | None = None) -> list[IntelMatch]:
        """Query external APIs for additional context (rate-limited).

        Only queries APIs whose keys are available in environment variables.
        """
        targets = iocs if iocs is not None else self._all_iocs
        matches: list[IntelMatch] = []

        for ioc in targets:
            # --- VirusTotal ---
            if ioc.ioc_type == IOCType.HASH_SHA256:
                result = self.vt_client.lookup_hash(ioc.value)
                if result and result.get("malicious", 0) > 0:
                    matches.append(IntelMatch(
                        ioc=ioc, matched=True,
                        threat_name=f"VT_detection_{result['malicious']}/{result['total']}",
                        threat_category="malware",
                        confidence=min(result["malicious"] / max(result["total"], 1), 1.0),
                        details=f"Flagged by {result['malicious']}/{result['total']} engines",
                        source="virustotal",
                    ))

            elif ioc.ioc_type == IOCType.HASH_MD5:
                result = self.vt_client.lookup_hash(ioc.value)
                if result and result.get("malicious", 0) > 0:
                    matches.append(IntelMatch(
                        ioc=ioc, matched=True,
                        threat_name=f"VT_detection_{result['malicious']}/{result['total']}",
                        threat_category="malware",
                        confidence=min(result["malicious"] / max(result["total"], 1), 1.0),
                        details=f"Flagged by {result['malicious']}/{result['total']} engines",
                        source="virustotal",
                    ))

            elif ioc.ioc_type == IOCType.IP:
                vt_result = self.vt_client.lookup_ip(ioc.value)
                abuse_result = self.abuseipdb.lookup_ip(ioc.value)

                malicious_score = 0
                details_parts = []
                if vt_result and vt_result.get("malicious", 0) > 0:
                    malicious_score += vt_result["malicious"]
                    details_parts.append(
                        f"VT: {vt_result['malicious']}/{vt_result['total']} detections"
                    )
                if abuse_result and abuse_result.get("abuse_confidence_score", 0) > 50:
                    malicious_score += 1
                    details_parts.append(
                        f"AbuseIPDB score: {abuse_result['abuse_confidence_score']}"
                    )

                if malicious_score > 0:
                    matches.append(IntelMatch(
                        ioc=ioc, matched=True,
                        threat_name=f"IP_threat_score_{malicious_score}",
                        threat_category="malicious_ip",
                        confidence=min(malicious_score / 3.0, 1.0),
                        details="; ".join(details_parts),
                        source="virustotal+abuseipdb",
                    ))

            elif ioc.ioc_type == IOCType.DOMAIN:
                result = self.vt_client.lookup_domain(ioc.value)
                if result and result.get("malicious", 0) > 0:
                    matches.append(IntelMatch(
                        ioc=ioc, matched=True,
                        threat_name=f"VT_domain_{result['malicious']}/{result['total']}",
                        threat_category="malicious_domain",
                        confidence=min(result["malicious"] / max(result["total"], 1), 1.0),
                        details=f"Flagged by {result['malicious']}/{result['total']} engines",
                        source="virustotal",
                    ))

        logger.info("External enrichment: %d matches found", len(matches))
        return matches

    def full_analysis(
        self,
        dns_queries: list[DNSQuery] | None = None,
        http_requests: list[HTTPRequest] | None = None,
        tls_sessions: list[TLSMetadata] | None = None,
        carved_files: list[CarvedFile] | None = None,
        credentials: list[CredentialArtifact] | None = None,
    ) -> list[IntelMatch]:
        """Run the complete intelligence pipeline: extract, local match, enrich."""
        iocs = self.extract_iocs(
            dns_queries=dns_queries,
            http_requests=http_requests,
            tls_sessions=tls_sessions,
            carved_files=carved_files,
            credentials=credentials,
        )
        local_matches = self.match_local(iocs)
        external_matches = self.enrich_external(iocs)

        # Merge, dedup by IOC value
        seen_values: set[str] = set()
        combined: list[IntelMatch] = []
        for m in local_matches + external_matches:
            key = m.ioc.value
            if key not in seen_values:
                seen_values.add(key)
                combined.append(m)
            else:
                # Merge details
                for existing in combined:
                    if existing.ioc.value == key:
                        existing.details += f" | {m.details}"
                        existing.confidence = max(existing.confidence, m.confidence)
                        break

        logger.info("Total unique intelligence matches: %d", len(combined))
        return combined
