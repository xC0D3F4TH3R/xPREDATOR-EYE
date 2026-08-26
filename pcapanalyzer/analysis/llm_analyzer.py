"""
llm_analyzer.py - LLM-powered security analysis and report generation.

Uses local LLMs (Ollama) for malware explanation, IOC context generation,
executive summary writing, and automated threat narrative generation.
"""

from __future__ import annotations

import json
from typing import Optional

from ..utils import get_logger

logger = get_logger("llm_analyzer")

try:
    import ollama as _ollama
    OLLAMA_AVAILABLE = True
except ImportError:
    OLLAMA_AVAILABLE = False
    _ollama = None  # type: ignore[assignment]


class SecurityLLMAnalyzer:
    """LLM-powered security analysis using local models via Ollama.

    Usage::

        analyzer = SecurityLLMAnalyzer(model="llama3.2:3b")
        analysis = analyzer.analyze_malware(file_info, yara_matches, network_events)
    """

    def __init__(self, model: str = "llama3.2:3b") -> None:
        self.model = model
        self._client = None
        if OLLAMA_AVAILABLE:
            try:
                self._client = _ollama.Client()
                self._client.list()
                logger.info("Ollama connected, model: %s", model)
            except Exception as exc:
                logger.warning("Ollama not available: %s", exc)
                self._client = None

    def _generate(self, prompt: str, system: str = "", temperature: float = 0.3) -> str:
        if not self._client:
            return "[LLM unavailable - install ollama and pull the model]"
        try:
            response = self._client.generate(
                model=self.model,
                prompt=prompt,
                system=system,
                options={"temperature": temperature, "num_predict": 1024},
            )
            return response.get("response", "")
        except Exception as exc:
            logger.error("LLM generation error: %s", exc)
            return f"[LLM error: {exc}]"

    def analyze_malware(self, file_info: dict, yara_matches: list, network_events: list) -> str:
        system = "You are an expert cybersecurity analyst specializing in malware analysis and threat intelligence. Provide detailed, technical analysis suitable for security professionals."
        prompt = f"""Analyze this potential malware sample:

File Information:
{json.dumps(file_info, indent=2, default=str)}

YARA Rule Matches:
{json.dumps(yara_matches[:5], indent=2, default=str)}

Network Activity (sample):
{json.dumps(network_events[:10], indent=2, default=str)}

Provide:
1. Malware family classification (if identifiable)
2. Behavioral analysis summary
3. Key Indicators of Compromise (IOCs)
4. MITRE ATT&CK mapping
5. Risk assessment (1-10)
6. Recommended mitigation steps"""
        return self._generate(prompt, system)

    def generate_executive_summary(self, analysis_data: dict) -> str:
        system = "You are a senior security analyst writing executive summaries for C-level leadership. Be concise, clear, and focus on business impact."
        prompt = f"""Generate an executive summary for this security analysis:

{json.dumps(analysis_data, indent=2, default=str)}

Write a 2-3 paragraph executive summary covering:
1. Overall threat level and business impact
2. Key findings and affected systems
3. Recommended immediate actions"""
        return self._generate(prompt, system)

    def explain_ioc(self, ioc_value: str, ioc_type: str, context: str = "") -> str:
        system = "You are a threat intelligence analyst. Explain IOCs in clear, actionable language for security teams."
        prompt = f"""Explain this Indicator of Compromise:

Type: {ioc_type}
Value: {ioc_value}
Context: {context}

Provide:
1. What this IOC indicates about the threat
2. Common attack scenarios using this IOC
3. Detection and blocking recommendations
4. False positive considerations"""
        return self._generate(prompt, system)

    def generate_remediation_plan(self, assessment: dict) -> str:
        system = "You are a senior incident responder creating remediation plans. Be specific, prioritized, and actionable."
        prompt = f"""Create a detailed remediation plan for this security incident:

{json.dumps(assessment, indent=2, default=str)}

Provide:
1. Immediate containment steps (0-1 hour)
2. Short-term remediation (1-24 hours)
3. Long-term hardening (1-4 weeks)
4. Verification steps for each phase"""
        return self._generate(prompt, system)

    def classify_threat_actor(self, ttps: list[str], iocs: list[str]) -> str:
        system = "You are a threat intelligence analyst specializing in threat actor attribution."
        prompt = f"""Based on these observed TTPs and IOCs, assess potential threat actor attribution:

TTPs: {', '.join(ttps[:20])}
IOCs: {', '.join(iocs[:10])}

Provide:
1. Most likely threat actor group(s)
2. Confidence level (low/medium/high)
3. Reasoning based on TTP overlap
4. Known campaigns with similar patterns
5. Caveats and limitations of attribution"""
        return self._generate(prompt, system)

    @property
    def is_available(self) -> bool:
        return self._client is not None
