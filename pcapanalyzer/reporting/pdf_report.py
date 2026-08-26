"""
pdf_report.py - Government-grade PDF report generation.

Generates professional PDF reports using WeasyPrint + Jinja2 with
classification banners, MITRE ATT&CK heat maps, compliance mapping,
and executive/technical summaries.
"""

from __future__ import annotations

import json
from datetime import datetime
from pathlib import Path
from typing import Any, Optional

from ..utils import get_logger, ensure_directory

logger = get_logger("pdf_report")

try:
    from weasyprint import HTML
    from jinja2 import Template
    PDF_AVAILABLE = True
except ImportError as exc:
    PDF_AVAILABLE = False
    HTML = None  # type: ignore[assignment]
    Template = None  # type: ignore[assignment]
    logger.warning("PDF generation unavailable (weasyprint/jinja2): %s", exc)


EXECUTIVE_TEMPLATE = """<!DOCTYPE html>
<html>
<head>
<meta charset="UTF-8">
<style>
@page {
    size: A4;
    margin: 2cm;
    @top-center { content: "CLASSIFICATION: {{ classification }}"; font-size: 10pt; color: red; font-weight: bold; }
    @bottom-center { content: "Page " counter(page) " of " counter(pages); font-size: 9pt; }
    @bottom-left { content: "xPREDATOR-EYE v{{ version }}"; font-size: 8pt; color: #666; }
}
body { font-family: 'Helvetica', 'Arial', sans-serif; font-size: 11pt; line-height: 1.6; color: #333; }
.classification-banner { background-color: #cc0000; color: white; text-align: center; padding: 8px; font-weight: bold; font-size: 12pt; margin-bottom: 20px; }
.cover-page { page-break-after: always; text-align: center; padding-top: 150px; }
.cover-title { font-size: 32pt; font-weight: bold; color: #1a237e; margin-bottom: 10px; }
.cover-subtitle { font-size: 16pt; color: #455a64; margin-bottom: 40px; }
.cover-meta { font-size: 11pt; color: #666; margin-top: 60px; }
.cover-meta p { margin: 5px 0; }
h1 { font-size: 20pt; border-bottom: 3px solid #1a237e; padding-bottom: 8px; color: #1a237e; page-break-after: avoid; margin-top: 30px; }
h2 { font-size: 15pt; color: #283593; margin-top: 25px; page-break-after: avoid; }
h3 { font-size: 12pt; color: #3949ab; margin-top: 20px; }
.executive-summary { background-color: #e8eaf6; padding: 15px 20px; border-left: 5px solid #1a237e; margin: 20px 0; border-radius: 0 4px 4px 0; }
.metric-grid { display: flex; flex-wrap: wrap; gap: 10px; margin: 15px 0; }
.metric-box { border: 1px solid #cfd8dc; padding: 12px 16px; background: #f5f5f5; border-radius: 4px; min-width: 120px; text-align: center; }
.metric-value { font-size: 24pt; font-weight: bold; color: #1a237e; }
.metric-label { font-size: 9pt; color: #666; text-transform: uppercase; }
.risk-critical { color: #b71c1c; font-weight: bold; }
.risk-high { color: #d32f2f; font-weight: bold; }
.risk-medium { color: #f57c00; font-weight: bold; }
.risk-low { color: #388e3c; font-weight: bold; }
table { width: 100%%; border-collapse: collapse; margin: 15px 0; font-size: 10pt; }
th, td { border: 1px solid #cfd8dc; padding: 8px 10px; text-align: left; }
th { background-color: #e8eaf6; font-weight: bold; color: #1a237e; }
tr:nth-child(even) { background-color: #f5f5f5; }
.code-block { background-color: #263238; color: #aed581; padding: 10px 15px; font-family: 'Consolas', 'Monaco', monospace; font-size: 9pt; border-radius: 4px; overflow-wrap: break-word; white-space: pre-wrap; margin: 10px 0; }
.ioc-table td { font-family: monospace; font-size: 9pt; }
.severity-badge { display: inline-block; padding: 2px 8px; border-radius: 3px; color: white; font-size: 9pt; font-weight: bold; }
.sev-critical { background-color: #b71c1c; }
.sev-high { background-color: #d32f2f; }
.sev-medium { background-color: #f57c00; }
.sev-low { background-color: #388e3c; }
.sev-info { background-color: #1976d2; }
.recommendation { margin: 8px 0; padding: 8px 12px; border-left: 3px solid #1a237e; background: #f5f5f5; }
.recommendation.critical { border-left-color: #b71c1c; background: #ffebee; }
.recommendation.high { border-left-color: #d32f2f; background: #fff3e0; }
.page-break { page-break-before: always; }
.footer-note { font-size: 8pt; color: #999; margin-top: 40px; border-top: 1px solid #ddd; padding-top: 10px; }
</style>
</head>
<body>
<div class="classification-banner">{{ classification }}</div>

<div class="cover-page">
    <div class="cover-title">xPREDATOR-EYE</div>
    <div class="cover-subtitle">Threat Intelligence Analysis Report</div>
    <div class="cover-meta">
        <p><strong>Report ID:</strong> {{ report_id }}</p>
        <p><strong>Generated:</strong> {{ report_date }}</p>
        <p><strong>Analyst:</strong> {{ analyst }}</p>
        <p><strong>Classification:</strong> {{ classification }}</p>
        <p><strong>Tool Version:</strong> {{ version }}</p>
    </div>
</div>

<h1>1. Executive Summary</h1>
<div class="executive-summary">
{{ executive_summary }}
</div>

<h1>2. Analysis Overview</h1>
<div class="metric-grid">
    <div class="metric-box"><div class="metric-value risk-{{ overall_risk|lower }}">{{ overall_risk }}</div><div class="metric-label">Overall Risk</div></div>
    <div class="metric-box"><div class="metric-value">{{ alert_count }}</div><div class="metric-label">Total Alerts</div></div>
    <div class="metric-box"><div class="metric-value">{{ ioc_count }}</div><div class="metric-label">IOCs Identified</div></div>
    <div class="metric-box"><div class="metric-value">{{ threat_actor_count }}</div><div class="metric-label">Threat Actors</div></div>
    <div class="metric-box"><div class="metric-value">{{ damage_score }}</div><div class="metric-label">Damage Score</div></div>
    <div class="metric-box"><div class="metric-value">{{ behavioral_score }}</div><div class="metric-label">Behavioral Score</div></div>
</div>

<h1>3. Threat Assessment</h1>
<h2>3.1 Damage Assessment</h2>
<table>
<tr><th>Vector</th><th>Score</th><th>Impact</th><th>Evidence</th></tr>
{% for v in damage_vectors %}
<tr><td>{{ v.name }}</td><td>{{ v.score }}/10</td><td>{{ v.impact }}</td><td>{{ v.evidence }}</td></tr>
{% endfor %}
</table>

<h2>3.2 Behavioral Analysis</h2>
<p><strong>Behavioral Score:</strong> {{ behavioral_score }}/1.0</p>
<p><strong>Anomaly Score:</strong> {{ anomaly_score }}/1.0</p>
<p><strong>Patterns Detected:</strong> {{ pattern_count }}</p>
<table>
<tr><th>Pattern</th><th>Severity</th><th>Confidence</th><th>MITRE Tactics</th></tr>
{% for p in patterns %}
<tr><td>{{ p.name }}</td><td><span class="severity-badge sev-{{ p.severity }}">{{ p.severity|upper }}</span></td><td>{{ p.confidence }}%%</td><td>{{ p.mitre }}</td></tr>
{% endfor %}
</table>

<h2>3.3 Threat Actor Attribution</h2>
<table>
<tr><th>Actor</th><th>Confidence</th><th>Motivation</th><th>Sophistication</th><th>TTPs</th></tr>
{% for a in threat_actors %}
<tr><td>{{ a.name }}</td><td>{{ a.confidence }}%%</td><td>{{ a.motivation }}</td><td>{{ a.sophistication }}</td><td>{{ a.ttps }}</td></tr>
{% endfor %}
</table>

<div class="page-break"></div>
<h1>4. Technical Findings</h1>

<h2>4.1 Network Analysis</h2>
<table>
<tr><th>Metric</th><th>Value</th></tr>
<tr><td>Total Flows</td><td>{{ flow_count }}</td></tr>
<tr><td>DNS Queries</td><td>{{ dns_count }}</td></tr>
<tr><td>HTTP Requests</td><td>{{ http_count }}</td></tr>
<tr><td>TLS Sessions</td><td>{{ tls_count }}</td></tr>
<tr><td>Credentials Detected</td><td>{{ cred_count }}</td></tr>
<tr><td>Carved Files</td><td>{{ file_count }}</td></tr>
</table>

{% if dns_queries %}
<h2>4.2 DNS Analysis</h2>
<table class="ioc-table"><tr><th>Query</th><th>Type</th><th>Source</th><th>Flags</th></tr>
{% for dq in dns_queries[:50] %}
<tr><td>{{ dq.query }}</td><td>{{ dq.type }}</td><td>{{ dq.src }}</td><td>{{ dq.flags }}</td></tr>
{% endfor %}
</table>
{% endif %}

{% if tls_sessions %}
<h2>4.3 TLS Analysis</h2>
<table class="ioc-table"><tr><th>SNI</th><th>JA3</th><th>Version</th><th>Src-Dst</th></tr>
{% for t in tls_sessions[:50] %}
<tr><td>{{ t.sni }}</td><td>{{ t.ja3 }}</td><td>{{ t.version }}</td><td>{{ t.connection }}</td></tr>
{% endfor %}
</table>
{% endif %}

<div class="page-break"></div>
<h1>5. Indicators of Compromise</h1>
<table class="ioc-table"><tr><th>Type</th><th>Value</th><th>Severity</th><th>Source</th></tr>
{% for ioc in iocs[:100] %}
<tr><td>{{ ioc.type }}</td><td>{{ ioc.value }}</td><td><span class="severity-badge sev-{{ ioc.severity }}">{{ ioc.severity|upper }}</span></td><td>{{ ioc.source }}</td></tr>
{% endfor %}
</table>

<div class="page-break"></div>
<h1>6. Recommendations</h1>
{% for rec in recommendations %}
<div class="recommendation {{ rec.priority }}">
<strong>[{{ rec.priority|upper }}]</strong> {{ rec.action }}
</div>
{% endfor %}

<h1>7. MITRE ATT&CK Coverage</h1>
<table>
<tr><th>Tactic</th><th>Technique</th><th>Description</th></tr>
{% for t in mitre_mappings %}
<tr><td>{{ t.tactic }}</td><td>{{ t.technique }}</td><td>{{ t.description }}</td></tr>
{% endfor %}
</table>

<div class="page-break"></div>
<h1>Appendix A: Methodology</h1>
<p>This analysis was performed using xPREDATOR-EYE v{{ version }}, an enterprise-grade threat intelligence suite. The analysis pipeline includes:</p>
<ul>
    <li>PCAP ingestion and flow extraction</li>
    <li>Deep protocol parsing (DNS, HTTP, TLS, Credentials)</li>
    <li>File carving and hash computation</li>
    <li>YARA rule matching against {{ yara_rule_count }} rules</li>
    <li>Behavioral analysis with {{ detection_rule_count }} detection rules</li>
    <li>MITRE ATT&CK mapping and threat actor profiling</li>
    <li>Damage assessment and blast radius computation</li>
</ul>

<h1>Appendix B: Compliance Mapping</h1>
<table>
<tr><th>Finding</th><th>NIST CSF</th><th>ISO 27001</th><th>SOC 2</th></tr>
{% for c in compliance_mappings %}
<tr><td>{{ c.finding }}</td><td>{{ c.nist }}</td><td>{{ c.iso }}</td><td>{{ c.soc2 }}</td></tr>
{% endfor %}
</table>

<div class="classification-banner">{{ classification }}</div>
<div class="footer-note">Generated by xPREDATOR-EYE v{{ version }} | {{ report_date }} | Classification: {{ classification }}</div>
</body>
</html>"""


class PDFReportGenerator:
    """Generates government-grade PDF reports from analysis results."""

    def __init__(self, template_dir: Optional[Path] = None) -> None:
        self.template_dir = template_dir
        if not PDF_AVAILABLE:
            logger.warning("weasyprint/jinja2 not installed. PDF generation disabled.")

    def generate(
        self,
        result,
        output_path: Path,
        classification: str = "UNCLASSIFIED // FOR OFFICIAL USE ONLY",
        analyst: str = "xPREDATOR-EYE Automated Analysis",
        include_yara_rules: int = 52,
        include_detection_rules: int = 30,
    ) -> Optional[Path]:
        """Generate a comprehensive PDF report from an AnalysisResult."""
        if not PDF_AVAILABLE:
            logger.error("PDF generation not available - install weasyprint and jinja2")
            return None

        ensure_directory(output_path.parent)
        report_id = f"XPE-{datetime.now().strftime('%Y%m%d-%H%M%S')}"
        data = self._prepare_data(result, report_id, classification, analyst, include_yara_rules, include_detection_rules)

        try:
            template = Template(EXECUTIVE_TEMPLATE)
            html_content = template.render(**data)
            HTML(string=html_content).write_pdf(str(output_path))
            logger.info("PDF report generated: %s", output_path)
            return output_path
        except Exception as exc:
            logger.error("PDF generation failed: %s", exc)
            return None

    def _prepare_data(self, result, report_id: str, classification: str, analyst: str, yara_count: int, detection_count: int) -> dict:
        from .. import __version__

        damage_vectors = []
        if result.damage_assessment:
            for v in result.damage_assessment.vectors:
                damage_vectors.append({"name": v.vector_name, "score": f"{v.score:.1f}", "impact": v.estimated_impact, "evidence": "; ".join(v.evidence[:3]) or "None"})

        patterns = []
        if result.behavioral_profile:
            for p in result.behavioral_profile.patterns:
                patterns.append({"name": p.name, "severity": p.severity.value, "confidence": f"{p.confidence:.0%}", "mitre": ", ".join(t.value for t in p.mitre_tactics[:3])})

        threat_actors = []
        for a in result.threat_actors:
            threat_actors.append({"name": ", ".join(a.aliases), "confidence": f"{a.attribution_confidence:.0%}", "motivation": a.motivation, "sophistication": a.sophistication, "ttps": ", ".join(a.ttps[:5])})

        iocs = []
        for m in result.ioc_matches:
            iocs.append({"type": m.ioc.ioc_type.value, "value": m.ioc.value, "severity": m.ioc.severity.value, "source": m.source})

        dns_queries = [{"query": dq.query_name, "type": dq.query_type, "src": dq.src_ip or "", "flags": "DGA" if dq.possible_dga else ("HIGH_ENT" if dq.high_entropy else "")} for dq in result.dns_queries[:50]]
        tls_sessions = [{"sni": t.sni or "", "ja3": (t.ja3 or "")[:16], "version": t.version, "connection": f"{t.src_ip}:{t.src_port} -> {t.dst_ip}:{t.dst_port}"} for t in result.tls_sessions[:50]]

        recommendations = self._generate_recommendations(result)

        overall_risk = "LOW"
        if result.damage_assessment:
            if result.damage_assessment.overall_score >= 70: overall_risk = "CRITICAL"
            elif result.damage_assessment.overall_score >= 45: overall_risk = "HIGH"
            elif result.damage_assessment.overall_score >= 20: overall_risk = "MEDIUM"

        executive_summary = self._generate_executive_summary(result, overall_risk)

        mitre_mappings = []
        if result.behavioral_profile:
            for t in result.behavioral_profile.ttps[:20]:
                mitre_mappings.append({"tactic": t, "technique": t, "description": f"MITRE technique {t} observed"})

        compliance_mappings = [
            {"finding": "Network monitoring active", "nist": "DE.CM-1", "iso": "A.8.16", "soc2": "CC7.2"},
            {"finding": "IOCs identified and cataloged", "nist": "DE.AE-3", "iso": "A.8.12", "soc2": "CC7.3"},
            {"finding": "Automated response recommended", "nist": "RS.MA-1", "iso": "A.5.24", "soc2": "CC7.5"},
        ]

        return {
            "classification": classification,
            "version": __version__,
            "report_id": report_id,
            "report_date": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
            "analyst": analyst,
            "executive_summary": executive_summary,
            "overall_risk": overall_risk,
            "alert_count": len(result.alerts),
            "ioc_count": len(result.ioc_matches),
            "threat_actor_count": len(result.threat_actors),
            "damage_score": f"{result.damage_assessment.overall_score:.1f}" if result.damage_assessment else "0.0",
            "behavioral_score": f"{result.behavioral_profile.behavioral_score:.2f}" if result.behavioral_profile else "0.0",
            "anomaly_score": f"{result.behavioral_profile.anomaly_score:.2f}" if result.behavioral_profile else "0.0",
            "pattern_count": len(patterns),
            "damage_vectors": damage_vectors,
            "patterns": patterns,
            "threat_actors": threat_actors,
            "flow_count": len(result.flows),
            "dns_count": len(result.dns_queries),
            "http_count": len(result.http_requests),
            "tls_count": len(result.tls_sessions),
            "cred_count": len(result.credentials),
            "file_count": len(result.carved_files),
            "dns_queries": dns_queries,
            "tls_sessions": tls_sessions,
            "iocs": iocs,
            "recommendations": recommendations,
            "mitre_mappings": mitre_mappings,
            "compliance_mappings": compliance_mappings,
            "yara_rule_count": yara_count,
            "detection_rule_count": detection_count,
        }

    def _generate_executive_summary(self, result, risk: str) -> str:
        parts = [
            f"This report presents the findings of an automated threat analysis performed by xPREDATOR-EYE.",
            f"\n\nOverall Risk Level: {risk}.",
        ]
        if result.damage_assessment:
            parts.append(f" The damage assessment yielded a score of {result.damage_assessment.overall_score:.1f}/100 with {result.damage_assessment.blast_radius} host(s) affected.")
        if result.behavioral_profile:
            parts.append(f" Behavioral analysis identified {len(result.behavioral_profile.patterns)} suspicious patterns with a threat score of {result.behavioral_profile.behavioral_score:.2f}.")
        if result.threat_actors:
            actor = result.threat_actors[0]
            parts.append(f" Threat attribution suggests {', '.join(actor.aliases)} with {actor.attribution_confidence:.0%} confidence.")
        if result.alerts:
            critical = sum(1 for a in result.alerts if a.severity.value == "critical")
            high = sum(1 for a in result.alerts if a.severity.value == "high")
            parts.append(f" A total of {len(result.alerts)} alerts were generated ({critical} critical, {high} high).")
        return "".join(parts)

    def _generate_recommendations(self, result) -> list[dict]:
        recs = []
        if result.damage_assessment and result.damage_assessment.overall_score >= 70:
            recs.append({"priority": "critical", "action": "Immediately isolate affected hosts from the network."})
            recs.append({"priority": "critical", "action": "Conduct full forensic memory acquisition on compromised systems."})
        if result.ioc_matches:
            recs.append({"priority": "high", "action": f"Block {len(result.ioc_matches)} identified IOCs at network perimeter."})
        if result.dns_queries:
            dga_count = sum(1 for dq in result.dns_queries if dq.possible_dga)
            if dga_count:
                recs.append({"priority": "high", "action": f"Investigate {dga_count} suspicious DGA-generated domains."})
        if result.credentials:
            recs.append({"priority": "critical", "action": f"Rotate {len(result.credentials)} potentially compromised credentials immediately."})
        if result.behavioral_profile and result.behavioral_profile.behavioral_score > 0.7:
            recs.append({"priority": "high", "action": "Conduct threat hunt based on identified TTPs and MITRE ATT&CK techniques."})
        recs.append({"priority": "medium", "action": "Update detection signatures based on observed IOCs and behavioral patterns."})
        recs.append({"priority": "medium", "action": "Review and update incident response procedures."})
        return recs
