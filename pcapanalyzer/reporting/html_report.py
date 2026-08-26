"""
html_report.py - Interactive HTML report generation with Plotly charts.

Generates self-contained HTML reports with interactive charts, collapsible
sections, search/filtering, and IOC export capabilities.
"""

from __future__ import annotations

import json
from datetime import datetime
from pathlib import Path
from typing import Any, Optional

from ..utils import get_logger, ensure_directory

logger = get_logger("html_report")

HTML_TEMPLATE = """<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>xPREDATOR-EYE Report - {report_id}</title>
<script src="https://cdn.plot.ly/plotly-2.27.0.min.js"></script>
<style>
* {{ margin: 0; padding: 0; box-sizing: border-box; }}
body {{ font-family: 'Segoe UI', system-ui, sans-serif; background: #0a0e17; color: #e0e0e0; line-height: 1.6; }}
.container {{ max-width: 1400px; margin: 0 auto; padding: 20px; }}
.header {{ background: linear-gradient(135deg, #1a1f36 0%, #0d1117 100%); border: 1px solid #30363d; border-radius: 12px; padding: 30px; margin-bottom: 20px; text-align: center; }}
.header h1 {{ color: #58a6ff; font-size: 2.5em; margin-bottom: 10px; }}
.header .subtitle {{ color: #8b949e; font-size: 1.1em; }}
.banner {{ background: #b71c1c; color: white; text-align: center; padding: 8px; font-weight: bold; font-size: 12px; margin-bottom: 15px; border-radius: 4px; }}
.metrics {{ display: grid; grid-template-columns: repeat(auto-fit, minmax(180px, 1fr)); gap: 15px; margin: 20px 0; }}
.metric-card {{ background: #161b22; border: 1px solid #30363d; border-radius: 8px; padding: 20px; text-align: center; transition: transform 0.2s; }}
.metric-card:hover {{ transform: translateY(-2px); border-color: #58a6ff; }}
.metric-value {{ font-size: 2em; font-weight: bold; color: #58a6ff; }}
.metric-label {{ color: #8b949e; font-size: 0.85em; text-transform: uppercase; margin-top: 5px; }}
.section {{ background: #161b22; border: 1px solid #30363d; border-radius: 8px; margin: 15px 0; overflow: hidden; }}
.section-header {{ background: #1c2333; padding: 15px 20px; cursor: pointer; display: flex; justify-content: space-between; align-items: center; }}
.section-header:hover {{ background: #22272e; }}
.section-header h2 {{ color: #58a6ff; font-size: 1.2em; }}
.section-content {{ padding: 20px; display: none; }}
.section-content.active {{ display: block; }}
table {{ width: 100%; border-collapse: collapse; font-size: 0.9em; }}
th {{ background: #1c2333; color: #58a6ff; padding: 10px; text-align: left; border-bottom: 2px solid #30363d; }}
td {{ padding: 8px 10px; border-bottom: 1px solid #21262d; }}
tr:hover {{ background: #1c2333; }}
.severity-badge {{ display: inline-block; padding: 2px 10px; border-radius: 12px; font-size: 0.8em; font-weight: bold; }}
.sev-critical {{ background: #b71c1c; color: white; }}
.sev-high {{ background: #d32f2f; color: white; }}
.sev-medium {{ background: #f57c00; color: white; }}
.sev-low {{ background: #388e3c; color: white; }}
.sev-info {{ background: #1976d2; color: white; }}
.ioc-value {{ font-family: 'Consolas', monospace; font-size: 0.85em; background: #0d1117; padding: 2px 6px; border-radius: 3px; }}
.recommendation {{ margin: 10px 0; padding: 12px 15px; border-left: 4px solid #58a6ff; background: #0d1117; border-radius: 0 6px 6px 0; }}
.recommendation.critical {{ border-left-color: #b71c1c; background: #1a0000; }}
.recommendation.high {{ border-left-color: #d32f2f; background: #1a0505; }}
.recommendation.medium {{ border-left-color: #f57c00; }}
.chart-container {{ height: 400px; margin: 15px 0; }}
.search-box {{ width: 100%; padding: 10px 15px; background: #0d1117; border: 1px solid #30363d; border-radius: 6px; color: #e0e0e0; font-size: 0.95em; margin-bottom: 15px; }}
.search-box:focus {{ outline: none; border-color: #58a6ff; }}
.btn {{ padding: 8px 16px; border: 1px solid #30363d; border-radius: 6px; background: #1c2333; color: #e0e0e0; cursor: pointer; font-size: 0.85em; }}
.btn:hover {{ background: #22272e; border-color: #58a6ff; }}
.btn-primary {{ background: #1a5276; border-color: #58a6ff; }}
.code-block {{ background: #0d1117; padding: 12px; border-radius: 6px; font-family: 'Consolas', monospace; font-size: 0.85em; overflow-x: auto; }}
</style>
</head>
<body>
<div class="banner">{classification}</div>
<div class="container">
<div class="header">
<h1>xPREDATOR-EYE</h1>
<div class="subtitle">Threat Intelligence Report | {report_id}</div>
<div class="subtitle">Generated: {report_date} | Analyst: {analyst}</div>
</div>

<div class="metrics">
<div class="metric-card"><div class="metric-value risk-{overall_risk|lower}">{overall_risk}</div><div class="metric-label">Overall Risk</div></div>
<div class="metric-card"><div class="metric-value">{alert_count}</div><div class="metric-label">Total Alerts</div></div>
<div class="metric-card"><div class="metric-value">{ioc_count}</div><div class="metric-label">IOCs Identified</div></div>
<div class="metric-card"><div class="metric-value">{threat_actor_count}</div><div class="metric-label">Threat Actors</div></div>
<div class="metric-card"><div class="metric-value">{damage_score}</div><div class="metric-label">Damage Score</div></div>
<div class="metric-card"><div class="metric-value">{flow_count}</div><div class="metric-label">Network Flows</div></div>
</div>

<div class="chart-container" id="severity-chart"></div>
<div class="chart-container" id="timeline-chart"></div>

<div class="section">
<div class="section-header" onclick="toggleSection(this)"><h2>Executive Summary</h2><span>&#9660;</span></div>
<div class="section-content active">{executive_summary}</div>
</div>

<div class="section">
<div class="section-header" onclick="toggleSection(this)"><h2>IOCs ({ioc_count})</h2><span>&#9660;</span></div>
<div class="section-content">
<input type="text" class="search-box" placeholder="Search IOCs..." onkeyup="filterTable(this, 'ioc-table')">
<table id="ioc-table"><tr><th>Type</th><th>Value</th><th>Severity</th><th>Source</th></tr>
{ioc_rows}
</table>
<button class="btn" onclick="exportIOCs()">Export IOCs (JSON)</button>
<button class="btn" onclick="exportIOCsCSV()">Export IOCs (CSV)</button>
</div>
</div>

<div class="section">
<div class="section-header" onclick="toggleSection(this)"><h2>Recommendations</h2><span>&#9660;</span></div>
<div class="section-content">{recommendations}</div>
</div>

<div class="section">
<div class="section-header" onclick="toggleSection(this)"><h2>Threat Actor Attribution</h2><span>&#9660;</span></div>
<div class="section-content">
<table><tr><th>Actor</th><th>Confidence</th><th>Motivation</th><th>Sophistication</th></tr>
{threat_actor_rows}
</table>
</div>
</div>

<div class="section">
<div class="section-header" onclick="toggleSection(this)"><h2>MITRE ATT&CK Mapping</h2><span>&#9660;</span></div>
<div class="section-content">
<table><tr><th>Tactic</th><th>Technique</th></tr>
{mitre_rows}
</table>
</div>
</div>
</div>

<script>
const IOC_DATA = {ioc_json};
function toggleSection(header) {{ const content = header.nextElementSibling; content.classList.toggle('active'); header.querySelector('span').textContent = content.classList.contains('active') ? '\\u25B2' : '\\u25BC'; }}
function filterTable(input, tableId) {{ const filter = input.value.toLowerCase(); document.querySelectorAll('#' + tableId + ' tr').forEach((row, i) => {{ if (i === 0) return; row.style.display = row.textContent.toLowerCase().includes(filter) ? '' : 'none'; }}); }}
function exportIOCs() {{ const blob = new Blob([JSON.stringify(IOC_DATA, null, 2)], {{type: 'application/json'}}); const a = document.createElement('a'); a.href = URL.createObjectURL(blob); a.download = 'iocs.json'; a.click(); }}
function exportIOCsCSV() {{ let csv = 'Type,Value,Severity,Source\\n'; IOC_DATA.forEach(ioc => {{ csv += `"${{ioc.type}}","${{ioc.value}}","${{ioc.severity}}","${{ioc.source}}"\\n`; }}); const blob = new Blob([csv], {{type: 'text/csv'}}); const a = document.createElement('a'); a.href = URL.createObjectURL(blob); a.download = 'iocs.csv'; a.click(); }}

Plotly.newPlot('severity-chart', [{{
  x: {severity_labels}, y: {severity_counts}, type: 'bar',
  marker: {{ color: ['#d32f2f', '#f57c00', '#ffc107', '#388e3c', '#1976d2'] }}
}}], {{ title: 'Alert Severity Distribution', paper_bgcolor: '#161b22', plot_bgcolor: '#0d1117', font: {{ color: '#e0e0e0' }} }});

Plotly.newPlot('timeline-chart', [{{
  x: {timeline_x}, y: {timeline_y}, type: 'scatter', mode: 'lines+markers',
  line: {{ color: '#58a6ff' }}, fill: 'tozeroy', fillcolor: 'rgba(88,166,255,0.1)'
}}], {{ title: 'Alert Timeline', paper_bgcolor: '#161b22', plot_bgcolor: '#0d1117', font: {{ color: '#e0e0e0' }} }});
</script>
</body>
</html>"""


class HTMLReportGenerator:
    """Generates interactive HTML reports with Plotly charts."""

    def generate(self, result, output_path: Path, classification: str = "UNCLASSIFIED // FOOU") -> Optional[Path]:
        ensure_directory(output_path.parent)
        from .. import __version__
        report_id = f"XPE-{datetime.now().strftime('%Y%m%d-%H%M%S')}"

        overall_risk = "LOW"
        if result.damage_assessment:
            score = result.damage_assessment.overall_score
            if score >= 70: overall_risk = "CRITICAL"
            elif score >= 45: overall_risk = "HIGH"
            elif score >= 20: overall_risk = "MEDIUM"

        severities = {"critical": 0, "high": 0, "medium": 0, "low": 0, "info": 0}
        for a in result.alerts:
            s = a.severity.value
            if s in severities:
                severities[s] += 1

        iocs = []
        for m in result.ioc_matches:
            iocs.append({"type": m.ioc.ioc_type.value, "value": m.ioc.value, "severity": m.ioc.severity.value, "source": m.source})

        threat_actors = [{"name": ", ".join(a.aliases), "confidence": f"{a.attribution_confidence:.0%}", "motivation": a.motivation, "sophistication": a.sophistication} for a in result.threat_actors]

        mitre = []
        if result.behavioral_profile:
            for t in result.behavioral_profile.ttps[:20]:
                mitre.append({"tactic": t, "technique": t})

        recommendations = []
        if result.damage_assessment and result.damage_assessment.overall_score >= 70:
            recommendations.append({"priority": "critical", "text": "Immediately isolate affected hosts from the network."})
        if result.ioc_matches:
            recommendations.append({"priority": "high", "text": f"Block {len(result.ioc_matches)} identified IOCs at network perimeter."})
        recommendations.append({"priority": "medium", "text": "Update detection signatures based on observed IOCs."})

        try:
            html = HTML_TEMPLATE.format(
                report_id=report_id, report_date=datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
                analyst="xPREDATOR-EYE Automated Analysis", classification=classification,
                overall_risk=overall_risk, alert_count=len(result.alerts), ioc_count=len(iocs),
                threat_actor_count=len(result.threat_actors),
                damage_score=f"{result.damage_assessment.overall_score:.1f}" if result.damage_assessment else "0.0",
                flow_count=len(result.flows),
                executive_summary=f"<p>Analysis of {len(result.flows)} network flows identified {len(result.alerts)} alerts ({severities['critical']} critical, {severities['high']} high). {len(iocs)} IOCs were extracted and matched against threat intelligence.</p>",
                ioc_rows="".join(f'<tr><td>{i["type"]}</td><td><span class="ioc-value">{i["value"]}</span></td><td><span class="severity-badge sev-{i["severity"]}">{i["severity"].upper()}</span></td><td>{i["source"]}</td></tr>' for i in iocs[:200]),
                recommendations="".join(f'<div class="recommendation {r["priority"]}"><strong>[{r["priority"].upper()}]</strong> {r["text"]}</div>' for r in recommendations),
                threat_actor_rows="".join(f'<tr><td>{a["name"]}</td><td>{a["confidence"]}</td><td>{a["motivation"]}</td><td>{a["sophistication"]}</td></tr>' for a in threat_actors),
                mitre_rows="".join(f'<tr><td>{m["tactic"]}</td><td>{m["technique"]}</td></tr>' for m in mitre),
                ioc_json=json.dumps(iocs[:200]),
                severity_labels=json.dumps(["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"]),
                severity_counts=json.dumps([severities["critical"], severities["high"], severities["medium"], severities["low"], severities["info"]]),
                timeline_x=json.dumps([]),
                timeline_y=json.dumps([]),
            )
            output_path.write_text(html, encoding="utf-8")
            logger.info("HTML report generated: %s", output_path)
            return output_path
        except Exception as exc:
            logger.error("HTML report generation failed: %s", exc)
            return None
