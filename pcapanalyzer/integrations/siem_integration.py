"""
siem_integration.py - SIEM integration for alert forwarding and IOC export.

Provides connectors for Elasticsearch, Splunk, and STIX/TAXII formats
for seamless integration with enterprise security operations.
"""

from __future__ import annotations

import json
from datetime import datetime
from typing import Any, Optional

from ..utils import get_logger

logger = get_logger("siem_integration")


class ElasticsearchIntegration:
    """Push alerts, IOCs, and events to Elasticsearch/OpenSearch."""

    def __init__(self, hosts: list[str], index_prefix: str = "xpredator", api_key: Optional[str] = None):
        self.hosts = hosts
        self.index_prefix = index_prefix
        self.api_key = api_key
        self._client = None

    def connect(self) -> bool:
        try:
            from elasticsearch import Elasticsearch
            kwargs: dict[str, Any] = {"hosts": self.hosts}
            if self.api_key:
                kwargs["api_key"] = self.api_key
            self._client = Elasticsearch(**kwargs)
            self._client.ping()
            logger.info("Connected to Elasticsearch: %s", self.hosts)
            return True
        except Exception as exc:
            logger.error("Elasticsearch connection failed: %s", exc)
            return False

    def index_alert(self, alert: dict) -> bool:
        if not self._client:
            return False
        try:
            index = f"{self.index_prefix}-alerts-{datetime.now().strftime('%Y.%m')}"
            self._client.index(index=index, document=alert)
            return True
        except Exception as exc:
            logger.error("Failed to index alert: %s", exc)
            return False

    def bulk_index(self, documents: list[dict]) -> bool:
        if not self._client:
            return False
        try:
            index = f"{self.index_prefix}-alerts-{datetime.now().strftime('%Y.%m')}"
            actions = []
            for doc in documents:
                actions.append({"index": {"_index": index}})
                actions.append(doc)
            self._client.bulk(operations=actions)
            return True
        except Exception as exc:
            logger.error("Bulk index failed: %s", exc)
            return False

    def push_analysis_result(self, result) -> int:
        """Push complete analysis result to Elasticsearch. Returns indexed count."""
        if not self._client:
            return 0
        count = 0
        for alert in result.alerts:
            doc = {
                "timestamp": alert.timestamp.isoformat() if alert.timestamp else datetime.now().isoformat(),
                "alert_id": alert.alert_id,
                "severity": alert.severity.value,
                "title": alert.title,
                "description": alert.description,
                "source": alert.source,
                "src_ip": alert.src_ip,
                "dst_ip": alert.dst_ip,
                "mitre_technique": alert.mitre_technique,
                "tool": "xPREDATOR-EYE",
            }
            if self.index_alert(doc):
                count += 1
        return count


class SplunkIntegration:
    """Forward events to Splunk via HTTP Event Collector (HEC)."""

    def __init__(self, hec_url: str, hec_token: str, source: str = "xpredator"):
        self.hec_url = hec_url.rstrip("/")
        self.hec_token = hec_token
        self.source = source

    def send_event(self, event: dict) -> bool:
        import requests
        headers = {"Authorization": f"Splunk {self.hec_token}", "Content-Type": "application/json"}
        payload = {"event": event, "source": self.source, "sourcetype": "json", "time": datetime.now().timestamp()}
        try:
            resp = requests.post(f"{self.hec_url}/services/collector/event", headers=headers, json=payload, timeout=10)
            return resp.status_code == 200
        except Exception as exc:
            logger.error("Splunk HEC error: %s", exc)
            return False

    def send_batch(self, events: list[dict]) -> int:
        import requests
        headers = {"Authorization": f"Splunk {self.hec_token}", "Content-Type": "application/json"}
        payload = "\n".join([json.dumps({"event": e, "source": self.source, "sourcetype": "json"}) for e in events])
        try:
            resp = requests.post(f"{self.hec_url}/services/collector/event", headers=headers, data=payload, timeout=30)
            return len(events) if resp.status_code == 200 else 0
        except Exception as exc:
            logger.error("Splunk batch send error: %s", exc)
            return 0


class STIXExporter:
    """Export IOCs as STIX 2.1 bundles for threat intelligence sharing."""

    def export_iocs(self, ioc_matches: list, bundle_name: str = "xPREDATOR IOCs") -> dict:
        """Convert IntelMatches to a STIX 2.1 bundle."""
        stix_objects = []
        for match in ioc_matches:
            ioc = match.ioc
            stix_type_map = {
                "ip": ("ipv4-addr", "value"),
                "domain": ("domain-name", "value"),
                "hash_md5": ("file", "hashes.MD5"),
                "hash_sha256": ("file", "hashes.SHA-256"),
                "url": ("url", "value"),
            }
            mapped = stix_type_map.get(ioc.ioc_type.value)
            if mapped:
                obj_type, prop = mapped
                indicator = {
                    "type": "indicator",
                    "spec_version": "2.1",
                    "id": f"indicator--{ioc.value[:36].replace('.', '-').replace(':', '-')}",
                    "created": datetime.now().strftime("%Y-%m-%dT%H:%M:%SZ"),
                    "modified": datetime.now().strftime("%Y-%m-%dT%H:%M:%SZ"),
                    "name": f"{ioc.ioc_type.value}: {ioc.value}",
                    "pattern": f"[{obj_type}:{prop} = '{ioc.value}']",
                    "pattern_type": "stix",
                    "valid_from": datetime.now().strftime("%Y-%m-%dT%H:%M:%SZ"),
                    "confidence": int(match.confidence * 100),
                    "labels": [match.threat_category] if match.threat_category else ["unknown"],
                }
                stix_objects.append(indicator)

        return {
            "type": "bundle",
            "id": f"bundle--xpredator-{datetime.now().strftime('%Y%m%d%H%M%S')}",
            "objects": stix_objects,
        }

    def save_bundle(self, bundle: dict, output_path) -> None:
        from ..utils import ensure_directory
        from pathlib import Path
        path = Path(output_path)
        ensure_directory(path.parent)
        with open(path, "w", encoding="utf-8") as f:
            json.dump(bundle, f, indent=2)
        logger.info("STIX bundle saved: %s (%d objects)", path, len(bundle.get("objects", [])))
