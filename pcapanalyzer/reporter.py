"""
reporter.py - Comprehensive report generation for the Threat Intelligence Suite.

Generates:
  1. Structured JSON for machine consumption / SIEM ingestion
  2. Rich terminal dashboard for interactive review
  3. Executive summary panels
"""

from __future__ import annotations

import json
from datetime import datetime
from pathlib import Path
from typing import Any, Optional

from rich.console import Console
from rich.table import Table
from rich.panel import Panel
from rich.text import Text
from rich.tree import Tree
from rich import box

from . import config
from .models import (
    AnalysisResult, BehaviorPattern, BehavioralProfile, CampaignProfile,
    CarvedFile, CredentialArtifact, DamageAssessment, DNSQuery,
    HTTPRequest, IntelMatch, IOC, PcapMetadata, Severity,
    ThreatActor, TLSMetadata, Alert, AlertGroup, ResponsePlan,
)
from .utils import get_logger, bytes_to_human_readable, ensure_directory

logger = get_logger("reporter")
console = Console()


def _serialize(obj: Any) -> Any:
    if obj is None:
        return None
    if isinstance(obj, datetime):
        return obj.isoformat()
    slots = getattr(type(obj), "__slots__", None)
    if slots:
        return {k: getattr(obj, k) for k in slots if not k.startswith("_")}
    if hasattr(obj, "__dict__"):
        return {k: v for k, v in obj.__dict__.items() if not k.startswith("_")}
    if isinstance(obj, (set, frozenset)):
        return sorted(obj)
    if hasattr(obj, "value"):
        return obj.value
    return str(obj)


def generate_json_report(result: AnalysisResult, output_path: Path) -> Path:
    """Write a comprehensive JSON report."""
    ensure_directory(output_path.parent)

    report: dict[str, Any] = {
        "report_metadata": {
            "tool": "xPREDATOR-EYE",
            "version": "2.0.0",
            "generated_at": datetime.now().isoformat(),
            "elapsed_seconds": result.elapsed_seconds,
        },
        "pcap_summary": _serialize(result.pcap_metadata) if result.pcap_metadata else None,
        "monitor_session": _serialize(result.monitor_session) if result.monitor_session else None,
        "flow_count": len(result.flows),
        "dns_queries": [_serialize(d) for d in result.dns_queries],
        "http_requests": [_serialize(h) for h in result.http_requests],
        "tls_sessions": [_serialize(t) for t in result.tls_sessions],
        "credentials_detected": [_serialize(c) for c in result.credentials],
        "carved_files": [_serialize(c) for c in result.carved_files],
        "ioc_matches": [_serialize(m) for m in result.ioc_matches],
        "behavioral_profile": _serialize(result.behavioral_profile) if result.behavioral_profile else None,
        "threat_actors": [_serialize(a) for a in result.threat_actors],
        "campaigns": [_serialize(c) for c in result.campaigns],
        "damage_assessment": _serialize(result.damage_assessment) if result.damage_assessment else None,
        "alerts": [_serialize(a) for a in result.alerts],
        "alert_groups": [_serialize(g) for g in result.alert_groups],
        "response_plan": _serialize(result.response_plan) if result.response_plan else None,
        "errors": result.errors,
    }

    with open(output_path, "w", encoding="utf-8") as fh:
        json.dump(report, fh, indent=config.JSON_INDENT, default=_serialize, ensure_ascii=False)

    logger.info("JSON report written: %s", output_path)
    return output_path


def render_terminal_report(result: AnalysisResult) -> None:
    """Render the complete terminal dashboard."""
    console.print()
    console.print(Panel.fit(
        "[bold cyan]PcapMalAnalyzer[/] v1.0.0  --  Threat Intelligence Report",
        border_style="cyan",
    ))

    # PCAP / Session Overview
    _render_overview(result)

    # Behavioral Profile
    if result.behavioral_profile:
        _render_behavioral(result.behavioral_profile)

    # Threat Actors
    if result.threat_actors:
        _render_threat_actors(result.threat_actors)

    # Damage Assessment
    if result.damage_assessment:
        _render_damage(result.damage_assessment)

    # DNS Queries
    if result.dns_queries:
        _render_dns(result.dns_queries)

    # HTTP Requests
    if result.http_requests:
        _render_http(result.http_requests)

    # TLS Sessions
    if result.tls_sessions:
        _render_tls(result.tls_sessions)

    # Credentials
    if result.credentials:
        _render_credentials(result.credentials)

    # Carved Files
    if result.carved_files:
        _render_files(result.carved_files)

    # Intelligence Matches
    if result.ioc_matches:
        _render_intel(result.ioc_matches)

    # Alerts
    if result.alerts:
        _render_alerts(result.alerts)

    # Alert Groups
    if result.alert_groups:
        _render_alert_groups(result.alert_groups)

    # Response Plan
    if result.response_plan:
        _render_response_plan(result.response_plan)

    # Footer
    console.print(Panel(
        f"[green]Analysis complete[/] in [bold]{result.elapsed_seconds:.1f}s[/]\n"
        f"DNS: {len(result.dns_queries)} | HTTP: {len(result.http_requests)} | "
        f"TLS: {len(result.tls_sessions)} | Creds: {len(result.credentials)} | "
        f"Files: {len(result.carved_files)} | IOCs: {len(result.ioc_matches)} | "
        f"Alerts: {len(result.alerts)} | Actors: {len(result.threat_actors)}",
        title="[bold]Pipeline Summary[/]", border_style="green",
    ))
    console.print()


def _render_overview(result: AnalysisResult) -> None:
    tree = Tree("[bold]Analysis Overview[/]")
    if result.pcap_metadata:
        m = result.pcap_metadata
        tree.add(f"File: [cyan]{m.filename}[/] ({bytes_to_human_readable(m.file_size)})")
        tree.add(f"Packets: [cyan]{m.packet_count:,}[/] | Duration: [cyan]{m.capture_duration:.2f}s[/]")
        tree.add(f"TCP: {m.tcp_packet_count:,} | UDP: {m.udp_packet_count:,}")
        tree.add(f"DNS: {m.dns_packet_count} | HTTP: {m.http_packet_count} | TLS: {m.tls_packet_count}")
    if result.monitor_session:
        s = result.monitor_session
        tree.add(f"Session: [cyan]{s.session_id}[/] | Platform: [cyan]{s.platform.value}[/]")
        tree.add(f"Packets: {s.packet_count:,} | Events: {s.event_count:,} | Alerts: {s.alert_count}")
    console.print(Panel(tree, title="[bold]Overview[/]", border_style="blue"))


def _render_behavioral(profile: BehavioralProfile) -> None:
    score_color = "green" if profile.behavioral_score < 0.3 else "yellow" if profile.behavioral_score < 0.6 else "red"
    tree = Tree("[bold]Behavioral Analysis[/]")
    tree.add(f"Behavioral Score: [{score_color}]{profile.behavioral_score:.2f}[/]")
    tree.add(f"Anomaly Score: [cyan]{profile.anomaly_score:.2f}[/]")
    tree.add(f"Total Events: [cyan]{profile.total_events}[/]")
    tree.add(f"Patterns Detected: [yellow]{len(profile.patterns)}[/]")
    tree.add(f"TTPs: [cyan]{', '.join(profile.ttps[:10])}[/]")

    if profile.kill_chain_progression:
        kc_tree = tree.add("[bold]Kill Chain Progression[/]")
        for phase in profile.kill_chain_progression:
            kc_tree.add(f"[red]{phase.value}[/]")

    if profile.mitre_coverage:
        mt_tree = tree.add("[bold]MITRE ATT&CK Tactics[/]")
        for tactic in profile.mitre_coverage:
            mt_tree.add(f"[yellow]{tactic.value}[/] - {tactic.name}")

    console.print(Panel(tree, title="[bold]Behavioral Profile[/]", border_style="yellow"))


def _render_threat_actors(actors: list[ThreatActor]) -> None:
    for actor in actors:
        conf_color = "green" if actor.attribution_confidence > 0.7 else "yellow" if actor.attribution_confidence > 0.4 else "red"
        tree = Tree(f"[bold]Threat Actor: {', '.join(actor.aliases)}[/]")
        tree.add(f"Attribution Confidence: [{conf_color}]{actor.attribution_confidence:.0%}[/]")
        tree.add(f"Motivation: [cyan]{actor.motivation}[/]")
        tree.add(f"Sophistication: [cyan]{actor.sophistication}[/]")
        tree.add(f"Associated Groups: {', '.join(actor.associated_groups) if actor.associated_groups else 'Unknown'}")
        tree.add(f"TTPs: {', '.join(actor.ttps[:8])}")
        if actor.iocs:
            ioc_tree = tree.add(f"[bold]IOCs ({len(actor.iocs)})[/]")
            for ioc in actor.iocs[:10]:
                ioc_tree.add(f"[red]{ioc}[/]")
        console.print(Panel(tree, title="[bold]Threat Actor Profile[/]", border_style="red"))


def _render_damage(assessment: DamageAssessment) -> None:
    sev_color = {"critical": "red", "high": "red", "medium": "yellow", "low": "green", "info": "blue"}
    tree = Tree("[bold]Damage Assessment[/]")
    tree.add(f"Overall Score: [bold]{assessment.overall_score:.1f}/100[/]")
    tree.add(f"Severity: [{sev_color.get(assessment.severity.value, 'white')}]{assessment.severity.value.upper()}[/]")
    tree.add(f"Blast Radius: [cyan]{assessment.blast_radius}[/] host(s)")

    for vec in assessment.vectors:
        vec_tree = tree.add(f"[bold]{vec.vector_name}[/] - Score: {vec.score:.1f}/10")
        if vec.evidence:
            for ev in vec.evidence[:3]:
                vec_tree.add(f"  {ev}")

    if assessment.lateral_movements:
        lm_tree = tree.add(f"[bold]Lateral Movements ({len(assessment.lateral_movements)})[/]")
        for lm in assessment.lateral_movements[:5]:
            lm_tree.add(f"{lm.source_host} -> {lm.destination_host} via {lm.method}")

    if assessment.data_exfiltrations:
        de_tree = tree.add(f"[bold]Data Exfiltration ({len(assessment.data_exfiltrations)})[/]")
        for de in assessment.data_exfiltrations[:5]:
            de_tree.add(f"{de.source_ip} -> {de.destination_ip} ({de.protocol})")

    console.print(Panel(tree, title="[bold]Damage Assessment[/]", border_style="red" if assessment.overall_score > 70 else "yellow"))


def _render_dns(queries: list[DNSQuery]) -> None:
    table = Table(title="DNS Queries", box=box.SIMPLE_HEAVY, show_lines=True, title_style="bold magenta")
    table.add_column("#", style="dim", width=4)
    table.add_column("Query", max_width=40, style="cyan")
    table.add_column("Type", width=6)
    table.add_column("Source", width=15)
    table.add_column("Resolved", max_width=25)
    table.add_column("Flags", width=12)

    for i, dq in enumerate(queries[:100], 1):
        flags = []
        if dq.possible_dga:
            flags.append("[red]DGA[/]")
        if dq.high_entropy:
            flags.append("[yellow]HIGH_ENT[/]")
        table.add_row(str(i), dq.query_name[:40], dq.query_type,
                      dq.src_ip or "—", ", ".join(dq.resolved_ips[:3]) or "—",
                      " ".join(flags) if flags else "—")
    console.print(table)


def _render_http(requests: list[HTTPRequest]) -> None:
    table = Table(title="HTTP Requests", box=box.SIMPLE_HEAVY, show_lines=True, title_style="bold magenta")
    table.add_column("#", style="dim", width=4)
    table.add_column("Method", width=7)
    table.add_column("Host", max_width=25, style="cyan")
    table.add_column("URI", max_width=35)
    table.add_column("User-Agent", max_width=25)
    table.add_column("Source", width=15)

    for i, hr in enumerate(requests[:100], 1):
        ua = hr.user_agent[:25] + "..." if len(hr.user_agent) > 25 else (hr.user_agent or "—")
        table.add_row(str(i), hr.method, hr.host or "—", hr.uri[:35], ua, hr.src_ip or "—")
    console.print(table)


def _render_tls(sessions: list[TLSMetadata]) -> None:
    table = Table(title="TLS Sessions", box=box.SIMPLE_HEAVY, show_lines=True, title_style="bold magenta")
    table.add_column("#", style="dim", width=4)
    table.add_column("SNI", max_width=30, style="cyan")
    table.add_column("JA3", max_width=28)
    table.add_column("Version", width=10)
    table.add_column("Src -> Dst", max_width=30)

    for i, tls in enumerate(sessions[:100], 1):
        table.add_row(str(i), tls.sni or "—", tls.ja3[:28] if tls.ja3 else "—",
                      tls.version or "—",
                      f"{tls.src_ip}:{tls.src_port} -> {tls.dst_ip}:{tls.dst_port}")
    console.print(table)


def _render_credentials(creds: list[CredentialArtifact]) -> None:
    table = Table(title="Cleartext Credentials Detected", box=box.SIMPLE_HEAVY,
                  show_lines=True, title_style="bold red")
    table.add_column("#", style="dim", width=4)
    table.add_column("Protocol", width=10)
    table.add_column("Username", max_width=20, style="yellow")
    table.add_column("Password", max_width=20, style="red")
    table.add_column("Source", width=15)

    for i, c in enumerate(creds[:50], 1):
        table.add_row(str(i), c.protocol.value.upper(), c.username or "—",
                      c.password[:20] + "..." if len(c.password) > 20 else (c.password or "—"),
                      c.src_ip or "—")
    console.print(table)


def _render_files(files: list[CarvedFile]) -> None:
    table = Table(title="Carved Files", box=box.SIMPLE_HEAVY, show_lines=True, title_style="bold magenta")
    table.add_column("#", style="dim", width=4)
    table.add_column("File", max_width=18, style="cyan")
    table.add_column("Type", width=10)
    table.add_column("Size", width=8)
    table.add_column("MD5", max_width=16)
    table.add_column("SHA-256", max_width=20)

    for i, cf in enumerate(files[:50], 1):
        table.add_row(str(i), cf.filename, cf.file_type.value,
                      bytes_to_human_readable(cf.size), cf.md5[:16], cf.sha256[:20])
    console.print(table)


def _render_intel(matches: list[IntelMatch]) -> None:
    table = Table(title="Threat Intelligence Matches", box=box.SIMPLE_HEAVY,
                  show_lines=True, title_style="bold red")
    table.add_column("#", style="dim", width=4)
    table.add_column("IOC Type", width=12)
    table.add_column("Value", max_width=35, style="yellow")
    table.add_column("Threat", max_width=20, style="red")
    table.add_column("Confidence", width=10)
    table.add_column("Source", width=12)

    for i, m in enumerate(matches[:50], 1):
        table.add_row(str(i), m.ioc.ioc_type.value, m.ioc.value[:35],
                      m.threat_name[:20], f"{m.confidence:.0%}", m.source)
    console.print(table)


def _render_alerts(alerts: list[Alert]) -> None:
    table = Table(title="Alerts", box=box.SIMPLE_HEAVY, show_lines=True, title_style="bold red")
    table.add_column("Time", width=8, style="dim")
    table.add_column("Priority", width=10)
    table.add_column("Title", max_width=30)
    table.add_column("Source", width=12)
    table.add_column("Host", width=15)

    for alert in sorted(alerts, key=lambda a: a.timestamp or datetime.min, reverse=True)[:30]:
        pri_color = "red" if alert.priority.value >= 4 else "yellow" if alert.priority.value >= 3 else "white"
        time_str = alert.timestamp.strftime("%H:%M:%S") if alert.timestamp else "—"
        table.add_row(time_str, Text(alert.priority.name, style=pri_color),
                      alert.title[:30], alert.source, alert.host or "—")
    console.print(table)


def _render_alert_groups(groups: list[AlertGroup]) -> None:
    tree = Tree("[bold]Incident Clusters[/]")
    for g in groups:
        sev_color = {"critical": "red", "high": "red", "medium": "yellow", "low": "green"}.get(g.severity.value, "white")
        g_tree = tree.add(f"[{sev_color}]{g.name}[/] ({len(g.alerts)} alerts, conf={g.confidence:.0%})")
        for alert in g.alerts[:5]:
            g_tree.add(f"  {alert.title}")
    console.print(Panel(tree, title="[bold]Alert Correlation[/]", border_style="yellow"))


def _render_response_plan(plan: ResponsePlan) -> None:
    tree = Tree(f"[bold]Response Plan[/] ({len(plan.commands)} commands)")
    for i, cmd in enumerate(plan.commands, 1):
        status_color = "green" if cmd.execution_status == "dry_run" else "red" if cmd.execution_status == "failed" else "yellow"
        cmd_tree = tree.add(f"[{status_color}]{i}. {cmd.action.value}[/] - {cmd.description}")
        cmd_tree.add(f"Platform: {cmd.platform.value}")
        cmd_tree.add(f"Command: [dim]{cmd.command_str[:80]}[/]")
    console.print(Panel(tree, title="[bold]Automated Response[/]", border_style="cyan"))
