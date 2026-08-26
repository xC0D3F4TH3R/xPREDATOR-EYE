"""
threat_actor.py - Threat actor profiling and campaign tracking.

Aggregates behavioral patterns, TTPs, and IOCs into threat actor profiles.
Maps observed activity to known attack campaigns and estimates attribution.
"""

from __future__ import annotations

from collections import Counter, defaultdict
from datetime import datetime
from typing import Optional

from .. import config
from ..models import (
    ThreatActor, CampaignProfile, BehaviorPattern, BehavioralProfile,
    IntelMatch, IOC, KillChainPhase, MITRETactic, Severity,
)
from ..utils import get_logger

logger = get_logger("threat_actor")


# ═══════════════════════════════════════════════════════════════════════════
# Known Threat Actor TTP Signatures (simplified fingerprints)
# ═══════════════════════════════════════════════════════════════════════════

KNOWN_ACTOR_FINGERPRINTS: list[dict] = [
    {
        "name": "APT28 (Fancy Bear)",
        "aliases": ["Fancy Bear", "Sofacy", "Pawn Storm", "STRONTIUM"],
        "motivation": "espionage",
        "sophistication": "expert",
        "mitre_tactics": ["TA0001", "TA0002", "TA0003", "TA0005", "TA0006", "TA0011"],
        "techniques": ["T1566", "T1059", "T1053", "T1547", "T1003", "T1071"],
        "indicators": ["X-Agent", "X-Tunnel", "Koadic", "credential_dumping"],
    },
    {
        "name": "APT29 (Cozy Bear)",
        "aliases": ["Cozy Bear", "The Dukes", "YTTRIUM"],
        "motivation": "espionage",
        "sophistication": "expert",
        "mitre_tactics": ["TA0001", "TA0002", "TA0003", "TA0005", "TA0006", "TA0011"],
        "techniques": ["T1566", "T1105", "T1059", "T1053", "T1003", "T1140"],
        "indicators": ["WellMess", "SUNBURST", "Hammer Toss"],
    },
    {
        "name": "Lazarus Group",
        "aliases": ["Lazarus", "HIDDEN COBRA", "Zinc"],
        "motivation": "financial",
        "sophistication": "advanced",
        "mitre_tactics": ["TA0001", "TA0002", "TA0003", "TA0005", "TA0010", "TA0040"],
        "techniques": ["T1566", "T1059", "T1053", "T1486", "T1490"],
        "indicators": ["BRONZE BUTLER", "FALLCHILL", "Manuscrypt"],
    },
    {
        "name": "Ransomware Operator (Generic)",
        "aliases": ["REvil", "Conti", "LockBit", "BlackCat"],
        "motivation": "financial",
        "sophistication": "advanced",
        "mitre_tactics": ["TA0001", "TA0002", "TA0003", "TA0006", "TA0008", "TA0040"],
        "techniques": ["T1486", "T1490", "T1003", "T1059", "T1021", "T1489"],
        "indicators": ["ransom", "encrypt", ".locked", "README.txt", "bitcoin", "tor"],
    },
    {
        "name": "Crypto Miner",
        "aliases": ["CoinMiner", "Cryptoloot", "Coinhive"],
        "motivation": "financial",
        "sophistication": "intermediate",
        "mitre_tactics": ["TA0002", "TA0011"],
        "techniques": ["T1496", "T1059"],
        "indicators": ["stratum+tcp", "mining", "xmr", "coinhive", "cryptonight"],
    },
    {
        "name": "APT41 (Double Dragon)",
        "aliases": ["Double Dragon", "Winnti", "Barium", "Wicked Panda"],
        "motivation": "espionage",
        "sophistication": "expert",
        "mitre_tactics": ["TA0001", "TA0002", "TA0003", "TA0005", "TA0006", "TA0010"],
        "techniques": ["T1195", "T1059", "T1547", "T1003", "T1041", "T1560"],
        "indicators": ["ShadowPad", "PlugX", "CrossWalk", "lowkey"],
    },
    {
        "name": "APT40 (Leviathan)",
        "aliases": ["Leviathan", "Moses Staff", "GADOLINIUM"],
        "motivation": "espionage",
        "sophistication": "advanced",
        "mitre_tactics": ["TA0001", "TA0002", "TA0003", "TA0006", "TA0010"],
        "techniques": ["T1566", "T1059", "T1003", "T1041", "T1505"],
        "indicators": ["CHARTON", "RETEFE", "webshell"],
    },
    {
        "name": "FIN7 (Carbanak)",
        "aliases": ["Carbanak", "Navigator", "Anunak"],
        "motivation": "financial",
        "sophistication": "advanced",
        "mitre_tactics": ["TA0001", "TA0002", "TA0003", "TA0006", "TA0008"],
        "techniques": ["T1566", "T1059", "T1053", "T1003", "T1021", "T1055"],
        "indicators": ["Carbanak", "Dridex", "Cobalt Strike"],
    },
    {
        "name": "Sandworm Team",
        "aliases": "Voodoo Bear",
        "motivation": "destructive",
        "sophistication": "expert",
        "mitre_tactics": ["TA0001", "TA0002", "TA0003", "TA0005", "TA0040"],
        "techniques": ["T1190", "T1059", "T1486", "T1489", "T1498"],
        "indicators": ["NotPetya", "Industroyer", "CaddyWiper", "Cyclops Blink"],
    },
    {
        "name": "Turla (Snake/Uroburos)",
        "aliases": ["Snake", "Uroburos", "Venomous Bear", "Waterbug"],
        "motivation": "espionage",
        "sophistication": "innovator",
        "mitre_tactics": ["TA0001", "TA0002", "TA0003", "TA0005", "TA0006", "TA0007"],
        "techniques": ["T1566", "T1059", "T1003", "T1048", "T1071", "T1082"],
        "indicators": ["Snake", "Mosquito", "VPNFilter", "CompuTrace"],
    },
    {
        "name": "OilRig (APT34)",
        "aliases": ["APT34", "Hazel Sand", "Cobalt Gypsy"],
        "motivation": "espionage",
        "sophistication": "advanced",
        "mitre_tactics": ["TA0001", "TA0002", "TA0003", "TA0006", "TA0010"],
        "techniques": ["T1566", "T1059", "T1053", "T1505", "T1041"],
        "indicators": ["ThreeDollars", "QUADAGENT", "Helminth"],
    },
    {
        "name": "Equation Group",
        "aliases": ["EQGRP", "The Equation Group"],
        "motivation": "espionage",
        "sophistication": "innovator",
        "mitre_tactics": ["TA0001", "TA0002", "TA0003", "TA0005", "TA0006"],
        "techniques": ["T1190", "T1059", "T1003", "T1547", "T1027"],
        "indicators": ["EternalBlue", "DoublePulsar", "FANNY", "EquationDrug"],
    },
    {
        "name": "Kimsuky",
        "aliases": ["Thallium", "Velvet Chollima"],
        "motivation": "espionage",
        "sophistication": "advanced",
        "mitre_tactics": ["TA0001", "TA0002", "TA0003", "TA0006", "TA0007"],
        "techniques": ["T1566", "T1059", "T1003", "T1071", "T1083"],
        "indicators": ["GoldDragon", "BabyShark", "AppleSeed"],
    },
    {
        "name": "Volt Typhoon",
        "aliases": ["Bronze Silhouette", "Insidious Taurus"],
        "motivation": "espionage",
        "sophistication": "advanced",
        "mitre_tactics": ["TA0001", "TA0002", "TA0003", "TA0005", "TA0007", "TA0008"],
        "techniques": ["T1133", "T1059", "T1021", "T1003", "T1046", "T1572"],
        "indicators": ["living_off_the_land", "FOXSHELL", "SOCKS5 proxy"],
    },
]


class ThreatActorProfiler:
    """Builds threat actor profiles from observed TTPs and IOCs.

    Usage::

        profiler = ThreatActorProfiler()
        actor = profiler.profile_from_behavior(behavioral_profile)
        profiler.correlate_iocs(intel_matches)
    """

    def __init__(self) -> None:
        self._actors: list[ThreatActor] = []
        self._campaigns: list[CampaignProfile] = []
        self._all_iocs: list[str] = []

    def profile_from_behavior(
        self,
        profile: BehavioralProfile,
        iocs: Optional[list[str]] = None,
    ) -> Optional[ThreatActor]:
        """Create or update a threat actor profile from behavioral analysis.

        Compares observed TTPs against known actor fingerprints to estimate
        attribution confidence.
        """
        if not profile.patterns:
            logger.info("No patterns to profile")
            return None

        observed_tactics = set(t.value for t in profile.mitre_coverage)
        observed_techniques = set(profile.ttps)
        observed_phases = [p.value for p in profile.kill_chain_progression]

        best_match: Optional[dict] = None
        best_score = 0.0

        for fingerprint in KNOWN_ACTOR_FINGERPRINTS:
            fp_tactics = set(fingerprint["mitre_tactics"])
            fp_techniques = set(fingerprint["techniques"])

            tactic_overlap = len(observed_tactics & fp_tactics) / max(len(fp_tactics), 1)
            technique_overlap = len(observed_techniques & fp_techniques) / max(len(fp_techniques), 1)
            combined = tactic_overlap * 0.5 + technique_overlap * 0.5

            if combined > best_score and combined >= config.ACTOR_CONFIDENCE_LOW:
                best_score = combined
                best_match = fingerprint

        actor = ThreatActor(
            aliases=[],
            attribution_confidence=best_score,
            ttps=profile.ttps,
            mitre_tactics=profile.mitre_coverage,
            kill_chain_phases=profile.kill_chain_progression,
            iocs=iocs or [],
            first_seen=datetime.now(),
            last_seen=datetime.now(),
            activity_log=[],
        )

        if best_match:
            actor.aliases = best_match["aliases"]
            actor.motivation = best_match["motivation"]
            actor.sophistication = best_match["sophistication"]
            actor.associated_groups = [best_match["name"]]
            logger.info(
                "Attributed to %s (confidence=%.2f)",
                best_match["name"], best_score,
            )
        else:
            actor.aliases = ["Unknown Actor"]
            actor.sophistication = "unknown"
            actor.motivation = "unknown"
            logger.info("No attribution match - unknown actor profiled")

        self._actors.append(actor)
        return actor

    def correlate_iocs(self, matches: list[IntelMatch]) -> None:
        """Cross-reference IOC matches to refine actor profiles."""
        ioc_values = [m.ioc.value for m in matches if m.matched]
        self._all_iocs.extend(ioc_values)

        for actor in self._actors:
            actor.iocs = list(set(actor.iocs + ioc_values))

    def build_campaign(self, actors: Optional[list[ThreatActor]] = None) -> CampaignProfile:
        """Aggregate actor profiles into a broader campaign view."""
        target_actors = actors or self._actors
        campaign = CampaignProfile(
            name="Detected Campaign",
            actors=[a.actor_id for a in target_actors],
        )

        all_tactics = []
        all_techniques = []
        all_phases = []
        for a in target_actors:
            all_tactics.extend(a.mitre_tactics)
            all_techniques.extend(a.ttps)
            all_phases.extend(a.kill_chain_phases)

        campaign.ttps = list(set(all_techniques))
        campaign.infrastructure = list(set(
            infra for a in target_actors for infra in a.infrastructure
        ))

        # Determine severity based on kill chain progression
        if KillChainPhase.ACTIONS_ON_OBJECTIVES in all_phases:
            campaign.severity = Severity.CRITICAL
        elif KillChainPhase.COMMAND_AND_CONTROL in all_phases:
            campaign.severity = Severity.HIGH
        elif KillChainPhase.EXPLOITATION in all_phases:
            campaign.severity = Severity.MEDIUM
        else:
            campaign.severity = Severity.LOW

        # Determine objectives from TTPs
        objectives = set()
        tactic_values = [t.value for t in all_tactics]
        if any(tv.startswith("T148") for tv in tactic_values):
            objectives.add("Data Destruction")
        if any(tv.startswith("T104") for tv in tactic_values):
            objectives.add("Data Exfiltration")
        if any(tv.startswith("T100") for tv in tactic_values):
            objectives.add("Credential Theft")
        if any(tv.startswith("T102") for tv in tactic_values):
            objectives.add("Lateral Movement")
        campaign.objectives = list(objectives)

        campaign.description = (
            f"Campaign involving {len(target_actors)} actor(s) with "
            f"{len(campaign.ttps)} unique TTPs. "
            f"Objectives: {', '.join(campaign.objectives) or 'Unknown'}."
        )

        self._campaigns.append(campaign)
        logger.info(
            "Campaign profile built: %d actors, %d TTPs, severity=%s",
            len(target_actors), len(campaign.ttps), campaign.severity.value,
        )
        return campaign

    def get_actors(self) -> list[ThreatActor]:
        return list(self._actors)

    def get_campaigns(self) -> list[CampaignProfile]:
        return list(self._campaigns)

    def get_summary(self) -> dict:
        """Return a summary of all profiling results."""
        return {
            "actor_count": len(self._actors),
            "campaign_count": len(self._campaigns),
            "total_iocs": len(self._all_iocs),
            "top_attribution": (
                self._actors[0].aliases[0] if self._actors and self._actors[0].aliases
                else "None"
            ),
            "max_confidence": max(
                (a.attribution_confidence for a in self._actors), default=0.0
            ),
        }
