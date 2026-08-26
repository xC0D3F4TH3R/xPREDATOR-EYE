"""
cli.py - Full CLI for the PcapMalAnalyzer Threat Intelligence Suite.

Supports two primary modes:
  - ``live``  : Real-time monitoring, behavioral analysis, and response
  - ``analyze``: Static PCAP file analysis (offline forensic mode)
"""

from __future__ import annotations

import argparse
import logging
import sys
import time
from datetime import datetime
from pathlib import Path
from typing import Optional

from . import __version__, config
from .utils import setup_logging, get_logger

logger = get_logger("cli")


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="pcapanalyzer",
        description=(
            "PcapMalAnalyzer v%s - Enterprise Threat Intelligence Suite\n"
            "Real-time monitoring, behavioral analysis, threat actor profiling,\n"
            "damage assessment, and automated response.\n"
        ) % __version__,
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=(
            "Modes:\n"
            "  live      Real-time network + process + file monitoring\n"
            "  analyze   Static PCAP file offline forensic analysis\n"
            "\n"
            "Examples:\n"
            "  python -m pcapanalyzer live --interface Ethernet\n"
            "  python -m pcapanalyzer live --filter 'tcp port 443' -o results/\n"
            "  python -m pcapanalyzer analyze capture.pcap\n"
            "  python -m pcapanalyzer analyze capture.pcap --blocklist bl.json --respond\n"
        ),
    )

    subparsers = parser.add_subparsers(dest="mode", help="Operating mode")

    # ── live mode ──────────────────────────────────────────────────────
    live_parser = subparsers.add_parser("live", help="Real-time monitoring mode")
    live_parser.add_argument("-i", "--interface", type=str, default=None,
                             help="Network interface to capture on (auto-detect if omitted)")
    live_parser.add_argument("-f", "--filter", type=str, default="",
                             help="BPF capture filter (e.g. 'tcp port 443')")
    live_parser.add_argument("-o", "--output-dir", type=str,
                             default=str(config.DEFAULT_OUTPUT_DIR))
    live_parser.add_argument("-b", "--blocklist", type=str, default=None,
                             help="Path to local JSON blocklist")
    live_parser.add_argument("--watch-paths", nargs="*", default=None,
                             help="Additional filesystem paths to monitor")
    live_parser.add_argument("--respond", action="store_true",
                             help="Enable automated response (CAUTION: disables dry-run)")
    live_parser.add_argument("--no-intel", action="store_true",
                             help="Skip external API enrichment")
    live_parser.add_argument("--duration", type=int, default=0,
                             help="Monitoring duration in seconds (0 = indefinite)")
    live_parser.add_argument("--interfaces", action="store_true",
                             help="List available network interfaces and exit")
    live_parser.add_argument("-v", "--verbose", action="store_true")
    live_parser.add_argument("-q", "--quiet", action="store_true")

    # ── analyze mode ───────────────────────────────────────────────────
    analyze_parser = subparsers.add_parser("analyze", help="Static PCAP analysis mode")
    analyze_parser.add_argument("pcap_file", type=str, help="Path to the PCAP file")
    analyze_parser.add_argument("-o", "--output-dir", type=str,
                                default=str(config.DEFAULT_OUTPUT_DIR))
    analyze_parser.add_argument("-b", "--blocklist", type=str, default=None)
    analyze_parser.add_argument("--no-intel", action="store_true")
    analyze_parser.add_argument("--respond", action="store_true",
                                help="Generate response commands for detected threats")
    analyze_parser.add_argument("--json-only", action="store_true")
    analyze_parser.add_argument("-v", "--verbose", action="store_true")
    analyze_parser.add_argument("-q", "--quiet", action="store_true")

    parser.add_argument("--version", action="version", version=f"PcapMalAnalyzer {__version__}")
    return parser


def main(argv: list[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)

    if not args.mode:
        parser.print_help()
        return 0

    log_level = logging.DEBUG if args.verbose else logging.INFO
    setup_logging(log_level)
    log = get_logger("cli")
    log.info("PcapMalAnalyzer v%s starting (mode=%s)", __version__, args.mode)

    if args.mode == "live":
        return _run_live(args, log)
    elif args.mode == "analyze":
        return _run_analyze(args, log)
    return 0


def _run_live(args: argparse.Namespace, log: logging.Logger) -> int:
    """Execute live monitoring mode."""
    from .core.orchestrator import Orchestrator

    if hasattr(args, "interfaces") and args.interfaces:
        from .capture.live_capture import LiveCaptureEngine
        engine = LiveCaptureEngine()
        ifaces = engine.list_interfaces()
        for iface in ifaces:
            print(f"  {iface}")
        return 0

    output_dir = Path(args.output_dir)
    output_dir.mkdir(parents=True, exist_ok=True)

    orch = Orchestrator(
        interface=args.interface,
        capture_filter=args.filter,
        watch_paths=args.watch_paths,
        blocklist_path=Path(args.blocklist) if args.blocklist else None,
        dry_run=not args.respond,
        output_dir=output_dir,
    )

    if args.respond:
        log.warning("*** AUTOMATED RESPONSE ENABLED - commands will be executed ***")
        log.warning("Press Ctrl+C at any time to stop safely")

    try:
        if args.duration > 0:
            import threading
            timer = threading.Timer(args.duration, lambda: orch.stop())
            timer.daemon = True
            timer.start()
        orch.start()
    except KeyboardInterrupt:
        log.info("Interrupted - generating final report...")
    finally:
        orch.stop()

    result = orch.get_result()
    _print_live_summary(result, log)
    return 0


def _run_analyze(args: argparse.Namespace, log: logging.Logger) -> int:
    """Execute static PCAP analysis mode."""
    start_time = time.monotonic()

    from .ingestion import validate_pcap, extract_metadata, generate_flows
    from .parser import parse_dns, parse_http, parse_tls, parse_credentials
    from .extractor import carve_files
    from .intelligence import IntelligenceEngine
    from .reporter import generate_json_report, render_terminal_report
    from .analysis.behavior_engine import BehaviorEngine
    from .analysis.threat_actor import ThreatActorProfiler
    from .analysis.damage_assessor import DamageAssessor
    from .core.alert_system import AlertSystem
    from .response.response_engine import ResponseEngine
    from .models import AnalysisResult, IngestionError

    output_dir = Path(args.output_dir)
    quarantine_dir = output_dir / "quarantine"
    report_dir = output_dir / "reports"
    quarantine_dir.mkdir(parents=True, exist_ok=True)
    report_dir.mkdir(parents=True, exist_ok=True)

    result = AnalysisResult(analysis_start=datetime.now())

    # Stage 1: Ingestion
    log.info("=== Stage 1: Ingestion ===")
    try:
        pcap_path = validate_pcap(args.pcap_file)
        result.pcap_metadata = extract_metadata(pcap_path)
        result.flows = list(generate_flows(pcap_path))
        log.info("Collected %d flows", len(result.flows))
    except IngestionError as exc:
        log.error("Ingestion failed: %s", exc)
        result.errors.append(f"Ingestion: {exc}")
        return 1

    # Stage 2: Protocol Parsing
    log.info("=== Stage 2: Protocol Parsing ===")
    try:
        result.dns_queries = parse_dns(str(pcap_path))
        result.http_requests = parse_http(str(pcap_path))
        result.tls_sessions = parse_tls(str(pcap_path))
        result.credentials = parse_credentials(str(pcap_path))
    except Exception as exc:
        log.error("Parsing error: %s", exc)
        result.errors.append(f"Parse: {exc}")

    # Stage 3: File Carving
    log.info("=== Stage 3: File Extraction ===")
    try:
        result.carved_files = carve_files(str(pcap_path), quarantine_dir)
    except Exception as exc:
        log.error("Extraction error: %s", exc)
        result.errors.append(f"Extract: {exc}")

    # Stage 4: Intelligence
    log.info("=== Stage 4: Intelligence ===")
    intel = IntelligenceEngine()
    if args.blocklist:
        intel.load_blocklist(Path(args.blocklist))
    try:
        if not args.no_intel:
            result.ioc_matches = intel.full_analysis(
                dns_queries=result.dns_queries,
                http_requests=result.http_requests,
                tls_sessions=result.tls_sessions,
                carved_files=result.carved_files,
                credentials=result.credentials,
            )
        else:
            intel.extract_iocs(
                dns_queries=result.dns_queries,
                http_requests=result.http_requests,
                tls_sessions=result.tls_sessions,
                carved_files=result.carved_files,
                credentials=result.credentials,
            )
            result.ioc_matches = intel.match_local()
    except Exception as exc:
        log.error("Intelligence error: %s", exc)
        result.errors.append(f"Intel: {exc}")

    # Stage 5: Behavioral Analysis (from parsed artifacts)
    log.info("=== Stage 5: Behavioral Analysis ===")
    beh_engine = BehaviorEngine()
    for dq in result.dns_queries:
        sev_type = "dns_query"
        be = __import__("pcapanalyzer.models", fromlist=["BehaviorEvent"]).BehaviorEvent(
            timestamp=dq.timestamp, event_type=sev_type, target=dq.query_name,
            src_ip=dq.src_ip or "",
        )
        beh_engine.ingest_event(be)
    for hr in result.http_requests:
        be = __import__("pcapanalyzer.models", fromlist=["BehaviorEvent"]).BehaviorEvent(
            timestamp=hr.timestamp, event_type="http_request",
            src_ip=hr.src_ip or "", dst_ip=hr.dst_ip or "",
            target=hr.host,
        )
        beh_engine.ingest_event(be)
    result.behavioral_profile = beh_engine.analyze()

    # Stage 6: Threat Actor Profiling
    log.info("=== Stage 6: Threat Actor Profiling ===")
    profiler = ThreatActorProfiler()
    if result.behavioral_profile and result.behavioral_profile.patterns:
        actor = profiler.profile_from_behavior(result.behavioral_profile)
        if actor:
            result.threat_actors = profiler.get_actors()
        profiler.correlate_iocs(result.ioc_matches)
        profiler.build_campaign()
        result.campaigns = profiler.get_campaigns()

    # Stage 7: Damage Assessment
    log.info("=== Stage 7: Damage Assessment ===")
    assessor = DamageAssessor()
    result.damage_assessment = assessor.assess(
        profile=result.behavioral_profile,
    )

    # Stage 8: Alerts
    log.info("=== Stage 8: Alert Generation ===")
    alert_sys = AlertSystem(output_dir=output_dir)
    for match in result.ioc_matches:
        alert = alert_sys.alert_from_intel_match(match)
        alert_sys.raise_alert(alert)
    if result.behavioral_profile:
        for pattern in result.behavioral_profile.patterns:
            alert = alert_sys.alert_from_pattern(pattern)
            alert_sys.raise_alert(alert)
    result.alerts = alert_sys.get_alerts()
    result.alert_groups = alert_sys.correlate()

    # Stage 9: Response Plan
    if args.respond:
        log.info("=== Stage 9: Response Plan Generation ===")
        resp_engine = ResponseEngine(dry_run=True)
        critical_alerts = [a for a in result.alerts if a.severity.numeric >= Severity.HIGH.numeric]
        if critical_alerts:
            result.response_plan = resp_engine.generate_plan(
                critical_alerts, result.damage_assessment,
            )
            log.warning("Response plan: %d commands generated", len(result.response_plan.commands))

    # Finalize
    elapsed = time.monotonic() - start_time
    result.elapsed_seconds = elapsed
    result.analysis_end = datetime.now()

    ts = datetime.now().strftime("%Y%m%d_%H%M%S")
    json_path = report_dir / f"pcapanalysis_{ts}.json"
    try:
        generate_json_report(result, json_path)
    except Exception as exc:
        log.error("Report error: %s", exc)

    if not args.quiet:
        render_terminal_report(result)

    log.info("Analysis complete in %.1fs. Report: %s", elapsed, json_path)
    return 0


def _print_live_summary(result, log):
    """Print a summary after live monitoring stops."""
    from rich.console import Console
    from rich.panel import Panel
    console = Console()

    console.print()
    console.print(Panel(
        f"[bold cyan]Live Monitoring Session Complete[/]\n\n"
        f"Duration: {result.elapsed_seconds:.0f}s\n"
        f"Packets: {result.monitor_session.packet_count if result.monitor_session else 0:,}\n"
        f"Events: {result.monitor_session.event_count if result.monitor_session else 0:,}\n"
        f"Alerts: {result.monitor_session.alert_count if result.monitor_session else 0}\n"
        f"Threat Actors: {len(result.threat_actors)}\n"
        f"Damage Score: {result.damage_assessment.overall_score:.1f}/100" if result.damage_assessment else "N/A",
        title="[bold]Summary[/]",
        border_style="green",
    ))
