"""
damage_assessor.py - Impact and damage assessment engine.

Evaluates the scope of compromise: blast radius, lateral movement paths,
data exfiltration potential, integrity/availability impact, and financial
risk estimation.
"""

from __future__ import annotations

from collections import defaultdict
from datetime import datetime
from typing import Optional

from .. import config
from ..models import (
    DamageAssessment, DamageVector, LateralMovement, DataExfiltration,
    BehaviorEvent, BehaviorPattern, BehavioralProfile,
    ProcessSnapshot, SystemEvent, Severity,
    KillChainPhase, MITRETactic,
)
from ..utils import get_logger

logger = get_logger("damage_assessor")


class DamageAssessor:
    """Evaluates overall damage from observed threats.

    Usage::

        assessor = DamageAssessor()
        assessment = assessor.assess(behavioral_profile, events)
    """

    def __init__(self) -> None:
        self._assessment: Optional[DamageAssessment] = None

    def assess(
        self,
        profile: Optional[BehavioralProfile] = None,
        events: Optional[list[BehaviorEvent]] = None,
        system_events: Optional[list[SystemEvent]] = None,
        process_snapshots: Optional[list[ProcessSnapshot]] = None,
    ) -> DamageAssessment:
        """Perform a comprehensive damage assessment."""
        assessment = DamageAssessment()

        # 1. Confidentiality Impact
        confidentiality = self._assess_confidentiality(events, system_events, process_snapshots)
        assessment.vectors.append(confidentiality)

        # 2. Integrity Impact
        integrity = self._assess_integrity(events, system_events)
        assessment.vectors.append(integrity)

        # 3. Availability Impact
        availability = self._assess_availability(events, system_events, process_snapshots)
        assessment.vectors.append(availability)

        # 4. Financial Impact
        financial = self._assess_financial(profile, confidentiality, integrity, availability)
        assessment.vectors.append(financial)

        # 5. Lateral Movement Assessment
        assessment.lateral_movements = self._assess_lateral_movement(events, system_events)

        # 6. Data Exfiltration Assessment
        assessment.data_exfiltrations = self._assess_exfiltration(events, system_events)

        # 7. Compute Overall Score
        scores = [v.score for v in assessment.vectors]
        assessment.overall_score = sum(scores) / max(len(scores), 1)

        # 8. Map score to severity
        if assessment.overall_score >= config.DAMAGE_SCORE_CRITICAL:
            assessment.severity = Severity.CRITICAL
        elif assessment.overall_score >= config.DAMAGE_SCORE_HIGH:
            assessment.severity = Severity.HIGH
        elif assessment.overall_score >= config.DAMAGE_SCORE_MEDIUM:
            assessment.severity = Severity.MEDIUM
        elif assessment.overall_score >= config.DAMAGE_SCORE_LOW:
            assessment.severity = Severity.LOW
        else:
            assessment.severity = Severity.INFO

        # 9. Compute blast radius
        assessment.blast_radius = self._compute_blast_radius(events, system_events)

        # 10. Generate summary
        assessment.summary = self._generate_summary(assessment)

        self._assessment = assessment
        logger.info(
            "Damage assessment complete: score=%.1f, severity=%s, blast_radius=%d",
            assessment.overall_score, assessment.severity.value, assessment.blast_radius,
        )
        return assessment

    def _assess_confidentiality(
        self, events, system_events, process_snapshots,
    ) -> DamageVector:
        score = 0.0
        evidence = []

        if events:
            cred_events = [e for e in events if "credential" in e.event_type.lower()]
            if cred_events:
                score += 3.0
                evidence.append(f"{len(cred_events)} credential access events detected")

            dns_queries = [e for e in events if e.event_type == "dns_query"]
            if len(dns_queries) > 100:
                score += 1.0
                evidence.append(f"High DNS query volume ({len(dns_queries)})")

        if process_snapshots:
            suspicious = [p for p in process_snapshots if p.suspicious_score > 0.6]
            if suspicious:
                score += min(len(suspicious) * 0.5, 3.0)
                evidence.append(f"{len(suspicious)} suspicious processes with elevated scores")

        if system_events:
            cred_events = [e for e in system_events if "credential" in e.event_type.lower()]
            if cred_events:
                score += 2.0
                evidence.append(f"{len(cred_events)} system credential events")

        score = min(score, 10.0)
        return DamageVector(
            vector_name="Confidentiality",
            score=score,
            description="Data exposure risk from credential theft, eavesdropping, or data access",
            evidence=evidence,
            estimated_impact="HIGH" if score > 7 else "MEDIUM" if score > 4 else "LOW",
        )

    def _assess_integrity(self, events, system_events) -> DamageVector:
        score = 0.0
        evidence = []

        if events:
            file_mods = [e for e in events if "file_modified" in e.event_type or "file_created" in e.event_type]
            if file_mods:
                score += min(len(file_mods) * 0.5, 4.0)
                evidence.append(f"{len(file_mods)} file modification/creation events")

            persistence = [e for e in events if e.mitre_tactic == MITRETactic.PERSISTENCE]
            if persistence:
                score += 3.0
                evidence.append(f"{len(persistence)} persistence mechanism detections")

        if system_events:
            file_events = [e for e in system_events if "file_" in e.event_type]
            if file_events:
                score += min(len(file_events) * 0.3, 3.0)
                evidence.append(f"{len(file_events)} file system changes at system level")

        score = min(score, 10.0)
        return DamageVector(
            vector_name="Integrity",
            score=score,
            description="System integrity impact from file modifications, persistence, or tampering",
            evidence=evidence,
            estimated_impact="HIGH" if score > 7 else "MEDIUM" if score > 4 else "LOW",
        )

    def _assess_availability(self, events, system_events, process_snapshots) -> DamageVector:
        score = 0.0
        evidence = []

        if events:
            ransomware_indicators = [e for e in events
                                     if any(k in str(e.raw_data).lower()
                                            for k in ["encrypt", "ransom", "locked"])]
            if ransomware_indicators:
                score += 8.0
                evidence.append("Ransomware activity detected - encryption in progress")

            resource_abuse = [e for e in events if e.event_type == "process_start"
                              and e.raw_data.get("score", 0) > 0.8]
            if resource_abuse:
                score += min(len(resource_abuse) * 1.0, 3.0)
                evidence.append(f"{len(resource_abuse)} high-resource processes")

        if process_snapshots:
            high_cpu = [p for p in process_snapshots if p.cpu_percent > 90]
            if high_cpu:
                score += min(len(high_cpu) * 1.0, 3.0)
                evidence.append(f"{len(high_cpu)} processes consuming >90% CPU")

        score = min(score, 10.0)
        return DamageVector(
            vector_name="Availability",
            score=score,
            description="System availability impact from resource exhaustion, ransomware, or DoS",
            evidence=evidence,
            estimated_impact="HIGH" if score > 7 else "MEDIUM" if score > 4 else "LOW",
        )

    def _assess_financial(self, profile, conf, integ, avail) -> DamageVector:
        score = 0.0
        evidence = []

        # Base score from other vectors
        base = (conf.score + integ.score + avail.score) / 3.0
        score = base

        if profile and profile.behavioral_score > 0.7:
            score += 2.0
            evidence.append("High behavioral threat score increases financial risk")

        if conf.score > 7:
            evidence.append("Data breach potential: regulatory fines, reputational damage")
            score += 1.0

        if avail.score > 7:
            evidence.append("Business disruption: downtime costs, SLA violations")
            score += 1.0

        score = min(score, 10.0)
        impact_map = {
            (8, 10): "CRITICAL - potential six/multi-figure losses",
            (5, 8): "HIGH - significant operational and financial impact",
            (2, 5): "MEDIUM - moderate impact requiring investigation",
            (0, 2): "LOW - minimal direct financial impact",
        }
        impact = "UNKNOWN"
        for (low, high), desc in impact_map.items():
            if low <= score < high:
                impact = desc
                break

        return DamageVector(
            vector_name="Financial",
            score=score,
            description="Estimated financial impact including direct costs and regulatory exposure",
            evidence=evidence,
            estimated_impact=impact,
        )

    def _assess_lateral_movement(self, events, system_events) -> list[LateralMovement]:
        movements: list[LateralMovement] = []

        if events:
            net_connects = [e for e in events if e.event_type == "network_connect"
                            and e.dst_ip and e.src_ip and e.dst_ip != e.src_ip]
            # Group by unique source-destination pairs
            seen_pairs = set()
            for e in net_connects:
                pair = (e.src_ip, e.dst_ip)
                if pair not in seen_pairs:
                    seen_pairs.add(pair)
                    movements.append(LateralMovement(
                        source_host=e.src_ip,
                        destination_host=e.dst_ip,
                        method="network",
                        timestamp=e.timestamp,
                    ))

        if system_events:
            for se in system_events:
                if se.event_type == "network_connect":
                    details = se.details if isinstance(se.details, dict) else {}
                    movements.append(LateralMovement(
                        source_host=details.get("process", "unknown"),
                        destination_host=details.get("remote", "unknown"),
                        method="detected",
                        timestamp=se.timestamp,
                    ))

        return movements

    def _assess_exfiltration(self, events, system_events) -> list[DataExfiltration]:
        exfils: list[DataExfiltration] = []

        if events:
            # Detect potential exfiltration: large outbound traffic after staging
            outbound = [e for e in events if e.event_type in ("network_connect", "network_packet")
                        and e.dst_ip and e.src_ip]
            file_events = [e for e in events if "file_" in e.event_type]

            if outbound and file_events:
                for e in outbound[:10]:
                    exfils.append(DataExfiltration(
                        source_ip=e.src_ip,
                        destination_ip=e.dst_ip,
                        protocol="detected",
                        timestamp=e.timestamp,
                        confidence=0.5,
                    ))

        return exfils

    def _compute_blast_radius(self, events, system_events) -> int:
        """Count unique hosts involved in the incident."""
        hosts = set()
        if events:
            for e in events:
                if e.src_ip:
                    hosts.add(e.src_ip)
                if e.dst_ip:
                    hosts.add(e.dst_ip)
        if system_events:
            for se in system_events:
                details = se.details if isinstance(se.details, dict) else {}
                if "process" in details:
                    hosts.add(str(details["process"]))
        return len(hosts)

    def _generate_summary(self, assessment: DamageAssessment) -> str:
        parts = [
            f"Overall Damage Score: {assessment.overall_score:.1f}/100",
            f"Severity: {assessment.severity.value.upper()}",
            f"Blast Radius: {assessment.blast_radius} host(s)",
            f"Vectors assessed: {len(assessment.vectors)}",
        ]
        if assessment.lateral_movements:
            parts.append(f"Lateral movements: {len(assessment.lateral_movements)} path(s)")
        if assessment.data_exfiltrations:
            parts.append(f"Data exfiltration events: {len(assessment.data_exfiltrations)}")

        high_vectors = [v for v in assessment.vectors if v.score > 7]
        if high_vectors:
            parts.append(f"HIGH IMPACT: {', '.join(v.vector_name for v in high_vectors)}")

        return " | ".join(parts)
