"""
cli.py - Full CLI for xPREDATOR-EYE Threat Intelligence Suite.

Supports two primary modes:
  - ``live``  : Real-time monitoring, behavioral analysis, and response
  - ``analyze``: Static PCAP file analysis (offline forensic mode)

With AI/ML integration, YARA scanning, professional report generation,
SIEM integration, and LLM-powered analysis.
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
from .models import BehaviorEvent
from .utils import setup_logging, get_logger

logger = get_logger("cli")


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="xpredator-eye",
        description=(
            "xPREDATOR-EYE v%s - Enterprise AI-Powered Threat Intelligence Suite\n"
            "Real-time monitoring, behavioral analysis, YARA scanning, ML classification,\n"
            "LLM analysis, threat actor profiling, and automated response.\n"
        ) % __version__,
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=(
            "Modes:\n"
            "  live      Real-time network + process + file monitoring\n"
            "  analyze   Static PCAP file offline forensic analysis\n"
            "\n"
            "Examples:\n"
            "  xpredator-eye live --interface Ethernet\n"
            "  xpredator-eye live --filter 'tcp port 443' -o results/\n"
            "  xpredator-eye analyze capture.pcap\n"
            "  xpredator-eye analyze capture.pcap --blocklist bl.json --respond\n"
            "  xpredator-eye analyze capture.pcap --yara-rules rules/ --pdf report.pdf\n"
            "  xpredator-eye analyze capture.pcap --llm --html report.html\n"
        ),
    )

    subparsers = parser.add_subparsers(dest="mode", help="Operating mode")

    # ── live mode ──────────────────────────────────────────────────────
    live_parser = subparsers.add_parser("live", help="Real-time monitoring and response")
    live_parser.add_argument("--interface", "-i", help="Network interface to capture on")
    live_parser.add_argument("--filter", "-f", default="", help="Capture filter (BPF syntax)")
    live_parser.add_argument("--output", "-o", type=Path, help="Output directory")
    live_parser.add_argument("--duration", type=int, default=0,
                             help="Stop capture after N seconds (0 = run until Ctrl+C)")
    live_parser.add_argument("--interfaces", "-I", action="store_true",
                             help="List available network interfaces and exit")
    live_parser.add_argument("--watch-paths", nargs="*", help="Directories to watch")
    live_parser.add_argument("--blocklist", type=Path, help="IOC blocklist JSON")
    live_parser.add_argument("--respond", action="store_true", help="Enable automated response")
    live_parser.add_argument("--dry-run", action="store_true", default=True, help="Dry-run responses")
    live_parser.add_argument("--quiet", action="store_true", help="Suppress output")
    live_parser.add_argument("--verbose", "-v", action="store_true", help="Verbose output")
    live_parser.add_argument("--yara-rules", type=Path, help="YARA rules path")
    live_parser.add_argument("--pdf", type=Path, help="PDF report on exit")

    # ── analyze mode ───────────────────────────────────────────────────
    analyze_parser = subparsers.add_parser("analyze", help="Static PCAP analysis")
    analyze_parser.add_argument("pcap_file", help="Path to PCAP/PCAPNG file")
    analyze_parser.add_argument("--output", "-o", dest="output_dir", help="Output directory")
    analyze_parser.add_argument("--blocklist", "-b", help="IOC blocklist JSON")
    analyze_parser.add_argument("--json-only", action="store_true", dest="json_only",
                                help="Write JSON report without the terminal dashboard")
    analyze_parser.add_argument("--respond", action="store_true", help="Generate response plan")
    analyze_parser.add_argument("--respond-execute", action="store_true", help="Execute responses")
    analyze_parser.add_argument("--quiet", "-q", action="store_true", help="Suppress output")
    analyze_parser.add_argument("--verbose", "-v", action="store_true", help="Verbose output")
    analyze_parser.add_argument("--yara-rules", type=Path, help="YARA rules path")
    analyze_parser.add_argument("--ml-model", type=Path, help="Pre-trained ML model")
    analyze_parser.add_argument("--pdf", type=Path, help="Generate PDF report")
    analyze_parser.add_argument("--html", type=Path, help="Generate HTML report")
    analyze_parser.add_argument("--stix", type=Path, help="Export IOCs as STIX bundle")
    analyze_parser.add_argument("--siem-url", help="Elasticsearch URL for SIEM push")
    analyze_parser.add_argument("--siem-token", help="Splunk HEC token (with --siem-url pointing at Splunk)")
    analyze_parser.add_argument("--llm", action="store_true", help="Enable LLM analysis")
    analyze_parser.add_argument("--llm-model", default=config.LLM_MODEL, help="Ollama model")
    analyze_parser.add_argument("--classification", default=config.DEFAULT_CLASSIFICATION)

    subparsers.add_parser("version", help="Show version")
    return parser


def _run_analyze(args: argparse.Namespace) -> int:
    from rich.console import Console
    from rich.table import Table
    from rich import box

    from .ingestion import validate_pcap, extract_metadata, generate_flows
    from .parser import parse_dns, parse_http, parse_tls, parse_credentials
    from .extractor import carve_files
    from .intelligence import IntelligenceEngine
    from .analysis.behavior_engine import BehaviorEngine
    from .analysis.threat_actor import ThreatActorProfiler
    from .analysis.damage_assessor import DamageAssessor
    from .core.alert_system import AlertSystem
    from .response.response_engine import ResponseEngine
    from .reporter import render_terminal_report, _serialize
    from .models import AnalysisResult, Severity, Alert

    console = Console()
    log = logger
    if args.quiet:
        log = logging.getLogger("pcapanalyzer.quiet")
        log.setLevel(logging.WARNING)

    output_dir = Path(args.output_dir or config.DEFAULT_OUTPUT_DIR)
    output_dir.mkdir(parents=True, exist_ok=True)

    result = AnalysisResult(analysis_start=datetime.now())

    with console.status("[bold green]Analyzing PCAP..."):
        try:
            pcap_path = validate_pcap(args.pcap_file)
        except Exception as exc:
            console.print(f"[bold red]Error:[/] {exc}")
            return 1

        # Stage 1: Ingestion
        log.info("=== Stage 1: PCAP Ingestion ===")
        result.pcap_metadata = extract_metadata(pcap_path)
        for flow_meta in generate_flows(pcap_path):
            result.flows.append(flow_meta)

        # Stage 2: Protocol Parsing
        log.info("=== Stage 2: Protocol Parsing ===")
        result.dns_queries = parse_dns(str(pcap_path))
        result.http_requests = parse_http(str(pcap_path))
        result.tls_sessions = parse_tls(str(pcap_path))
        result.credentials = parse_credentials(str(pcap_path))

        # Stage 3: File Carving
        log.info("=== Stage 3: File Carving ===")
        carved_dir = output_dir / "carved"
        carved_dir.mkdir(parents=True, exist_ok=True)
        for crafted in carve_files(str(pcap_path), carved_dir):
            result.carved_files.append(crafted)

        # Stage 4: Intelligence
        log.info("=== Stage 4: Intelligence ===")
        intel = IntelligenceEngine()
        if args.blocklist:
            intel.load_blocklist(Path(args.blocklist))
        else:
            intel.load_default_blocklists()
        result.ioc_matches = intel.full_analysis(
            result.dns_queries, result.http_requests,
            result.tls_sessions, result.carved_files, result.credentials,
        )

        # Stage 5: YARA Scanning
        yara_matches_all = []
        rules_paths = [args.yara_rules] if args.yara_rules else []
        if not rules_paths:
            packaged = config.PROJECT_ROOT / "detection" / "rules"
            if packaged.exists():
                rules_paths.append(packaged)
            if config.YARA_RULES_DIR.exists():
                rules_paths.append(config.YARA_RULES_DIR)
        if rules_paths:
            log.info("=== Stage 5A: YARA Scanning ===")
            try:
                from .detection.yara_scanner import YaraScanner
                yara_scanner = YaraScanner()
                for rp in rules_paths:
                    yara_scanner.load_rules(rp)
                for cf in result.carved_files:
                    if cf.quarantine_path:
                        matches = yara_scanner.scan_file(cf.quarantine_path)
                        for m in matches:
                            m["file"] = cf.filename
                            yara_matches_all.append(m)
                if yara_matches_all:
                    console.print(f"  [yellow]YARA: {len(yara_matches_all)} matches[/]")
            except ImportError:
                console.print("  [dim]yara-python not installed[/]")

        # Stage 6: Behavioral Analysis
        log.info("=== Stage 5B: Behavioral Analysis ===")
        beh_engine = BehaviorEngine()
        for dq in result.dns_queries:
            beh_engine.ingest_event(BehaviorEvent(
                timestamp=dq.timestamp, event_type="dns_query",
                target=dq.query_name, src_ip=dq.src_ip or "",
            ))
        for hr in result.http_requests:
            beh_engine.ingest_event(BehaviorEvent(
                timestamp=hr.timestamp, event_type="http_request",
                src_ip=hr.src_ip or "", dst_ip=hr.dst_ip or "", target=hr.host,
            ))
        for tls in result.tls_sessions:
            beh_engine.ingest_event(BehaviorEvent(
                timestamp=tls.timestamp, event_type="tls_connection",
                src_ip=tls.src_ip or "", dst_ip=tls.dst_ip or "", target=tls.sni,
            ))
        for cred in result.credentials:
            beh_engine.ingest_event(BehaviorEvent(
                timestamp=cred.timestamp, event_type="credential_access",
                src_ip=cred.src_ip or "", dst_ip=cred.dst_ip or "",
                target=cred.username or cred.auth_type,
            ))
        for cf in result.carved_files:
            beh_engine.ingest_event(BehaviorEvent(
                event_type="file_created", target=cf.filename,
                src_ip=cf.src_ip or "", dst_ip=cf.dst_ip or "",
            ))
        result.behavioral_profile = beh_engine.analyze()

        # Stage 7: Threat Actor Profiling
        log.info("=== Stage 6: Threat Actor Profiling ===")
        profiler = ThreatActorProfiler()
        actor = profiler.profile_from_behavior(result.behavioral_profile)
        if actor:
            result.threat_actors = [actor]

        # Stage 8: Damage Assessment
        log.info("=== Stage 7: Damage Assessment ===")
        assessor = DamageAssessor()
        result.damage_assessment = assessor.assess(result.behavioral_profile, beh_engine._events)

        # Stage 9: Alert Generation
        log.info("=== Stage 8: Alert Generation ===")
        alert_system = AlertSystem(output_dir=output_dir)
        if result.damage_assessment:
            for vector in result.damage_assessment.vectors:
                if vector.score >= 5.0:
                    alert_system.raise_alert(Alert(
                        title=f"{vector.vector_name} Impact Detected",
                        description=f"Score: {vector.score:.1f}/10. {vector.estimated_impact}",
                        severity=Severity.HIGH if vector.score >= 7.0 else Severity.MEDIUM,
                    ))
        result.alerts = alert_system._alerts

        # Stage 10: ML Classification
        ml_result = None
        log.info("=== Stage 8A: ML Classification ===")
        try:
            from .ml.feature_extractor import FeatureExtractor
            from .ml.classifier import NetworkClassifier
            ext_ml = FeatureExtractor()
            classifier = NetworkClassifier()
            model_path = args.ml_model or (
                config.ML_MODEL_PATH if config.ML_MODEL_PATH.exists() else None
            )
            model_loaded = bool(model_path) and classifier.load_model(model_path)
            flow_vectors = [
                ff.to_vector()
                for ff in ext_ml.extract_from_flows(
                    result.flows, result.dns_queries, result.http_requests, result.tls_sessions,
                )
            ]
            if flow_vectors:
                per_flow = classifier.analyze_flows(flow_vectors)
                anomalous = [r for r in per_flow if r.get("is_anomaly")]
                ml_result = {
                    "flows_analyzed": len(per_flow),
                    "anomalous_flows": len(anomalous),
                    "model_source": "pretrained" if model_loaded else "unsupervised",
                }
                if anomalous:
                    console.print(
                        f"  [bold yellow]ML: {len(anomalous)}/{len(per_flow)} flows "
                        f"flagged anomalous[/]"
                    )
                elif per_flow:
                    console.print(f"  [dim]ML: analyzed {len(per_flow)} flows, no anomalies[/]")
            else:
                features = ext_ml.extract_from_pcap_metadata(result.pcap_metadata)
                classifier.train([features], [0])
                ml_result = classifier.predict(features)
                if ml_result and ml_result.get("is_anomaly"):
                    console.print(
                        f"  [bold red]ML ANOMALY: score={ml_result.get('anomaly_score', 0):.2f}[/]"
                    )
        except ImportError:
            console.print("  [dim]ML libraries not installed[/]")
        except Exception as exc:
            log.debug("ML classification skipped: %s", exc)
            console.print(f"  [dim]ML classification unavailable: {exc}[/]")

        # Stage 11: LLM Analysis
        llm_analysis = None
        if args.llm or config.LLM_ENABLED:
            log.info("=== Stage 8B: LLM Analysis ===")
            try:
                from .analysis.llm_analyzer import SecurityLLMAnalyzer
                llm = SecurityLLMAnalyzer(model=args.llm_model)
                if llm.is_available:
                    llm_analysis = llm.generate_executive_summary({
                        "flows": len(result.flows), "alerts": len(result.alerts),
                        "iocs": len(result.ioc_matches),
                        "damage_score": result.damage_assessment.overall_score if result.damage_assessment else 0,
                    })
                    console.print("  [green]LLM analysis complete[/]")
            except ImportError:
                console.print("  [dim]ollama not installed[/]")

        # Stage 12: Response Plan
        if args.respond or args.respond_execute:
            log.info("=== Stage 9: Response Plan ===")
            response_engine = ResponseEngine()
            result.response_plan = response_engine.generate_plan(
                result.alerts, result.damage_assessment,
            )
            if args.respond_execute and result.response_plan:
                executed = response_engine.execute_plan(result.response_plan)
                console.print(f"  [yellow]Executed {executed} response commands[/]")

        # Stage 13: Reports
        log.info("=== Stage 10: Report Generation ===")
        if not args.json_only:
            render_terminal_report(result)

        if args.pdf:
            try:
                from .reporting.pdf_report import PDFReportGenerator
                PDFReportGenerator().generate(result, args.pdf, classification=args.classification)
                console.print(f"  [green]PDF: {args.pdf}[/]")
            except Exception as exc:
                console.print(f"  [dim]PDF report failed: {exc}[/]")

        if args.html:
            try:
                from .reporting.html_report import HTMLReportGenerator
                HTMLReportGenerator().generate(result, args.html, classification=args.classification)
                console.print(f"  [green]HTML: {args.html}[/]")
            except Exception as exc:
                console.print(f"  [dim]HTML report failed: {exc}[/]")

        if args.stix:
            try:
                from .integrations.siem_integration import STIXExporter
                stix = STIXExporter()
                bundle = stix.export_iocs(result.ioc_matches)
                stix.save_bundle(bundle, args.stix)
                console.print(f"  [green]STIX: {args.stix}[/]")
            except Exception as exc:
                console.print(f"  [dim]STIX failed: {exc}[/]")

        siem_urls = [args.siem_url] if args.siem_url else []
        if not siem_urls and config.SIEM_ELASTICSEARCH_ENABLED:
            siem_urls = config.SIEM_ELASTICSEARCH_HOSTS
        if siem_urls:
            try:
                from .integrations.siem_integration import ElasticsearchIntegration
                es = ElasticsearchIntegration(siem_urls)
                if es.connect():
                    indexed = es.push_analysis_result(result)
                    console.print(f"  [green]Pushed {indexed} alerts to ES[/]")
            except ImportError:
                console.print("  [dim]elasticsearch not installed[/]")

        # Splunk HEC push
        splunk_url = args.siem_url if (args.siem_url and args.siem_token) else None
        if not splunk_url and config.SIEM_SPLUNK_ENABLED and config.SIEM_SPLUNK_HEC_URL:
            splunk_url = config.SIEM_SPLUNK_HEC_URL
        if splunk_url:
            try:
                from .integrations.siem_integration import SplunkIntegration
                token = args.siem_token or config.SIEM_SPLUNK_HEC_TOKEN
                splunk = SplunkIntegration(
                    hec_url=splunk_url, hec_token=token, source=config.SIEM_SPLUNK_SOURCE,
                )
                events = []
                for alert in result.alerts:
                    events.append({
                        "id": getattr(alert, "alert_id", ""), "title": alert.title,
                        "severity": alert.severity.value, "description": alert.description,
                    })
                events.append({"type": "analysis_complete", "packets": result.pcap_metadata.packet_count if result.pcap_metadata else 0})
                sent = splunk.send_batch(events)
                console.print(f"  [green]Splunk HEC: sent {sent} events[/]")
            except ImportError:
                console.print("  [dim]requests not installed[/]")

        # JSON report
        json_path = output_dir / "analysis_report.json"
        try:
            import json as json_mod
            report_data = {
                "version": __version__, "timestamp": datetime.now().isoformat(),
                "pcap_file": str(pcap_path), "flows": len(result.flows),
                "dns": len(result.dns_queries), "http": len(result.http_requests),
                "tls": len(result.tls_sessions), "creds": len(result.credentials),
                "files": len(result.carved_files), "iocs": len(result.ioc_matches),
                "alerts": len(result.alerts), "actors": len(result.threat_actors),
                "damage": result.damage_assessment.overall_score if result.damage_assessment else 0,
                "behavioral": result.behavioral_profile.behavioral_score if result.behavioral_profile else 0,
                "yara_matches": len(yara_matches_all), "ml": ml_result, "llm": llm_analysis,
            }
            with open(json_path, "w", encoding="utf-8") as f:
                json_mod.dump(report_data, f, indent=2, default=_serialize)
            console.print(f"\n  [dim]Report: {json_path}[/]")
        except Exception as exc:
            console.print(f"  [dim]JSON error: {exc}[/]")

    result.analysis_end = datetime.now()

    summary = Table(title="xPREDATOR-EYE Complete", box=box.DOUBLE_EDGE, border_style="cyan")
    summary.add_column("Metric", style="bold")
    summary.add_column("Value", style="green")
    summary.add_row("Flows", str(len(result.flows)))
    summary.add_row("DNS Queries", str(len(result.dns_queries)))
    summary.add_row("HTTP Requests", str(len(result.http_requests)))
    summary.add_row("TLS Sessions", str(len(result.tls_sessions)))
    summary.add_row("Credentials", str(len(result.credentials)))
    summary.add_row("Carved Files", str(len(result.carved_files)))
    summary.add_row("IOCs", str(len(result.ioc_matches)))
    summary.add_row("Alerts", str(len(result.alerts)))
    summary.add_row("Actors", str(len(result.threat_actors)))
    if yara_matches_all:
        summary.add_row("YARA Matches", str(len(yara_matches_all)))
    if isinstance(ml_result, dict) and "flows_analyzed" in ml_result:
        summary.add_row(
            "ML Analysis",
            f"{ml_result['flows_analyzed']} flows | {ml_result['anomalous_flows']} anomalous",
        )
    elif ml_result and ml_result.get("class"):
        summary.add_row("ML Class", ml_result.get("class", "?"))
    if result.damage_assessment:
        summary.add_row("Damage", f"{result.damage_assessment.overall_score:.1f}/100")
    if result.behavioral_profile:
        summary.add_row("Behavioral", f"{result.behavioral_profile.behavioral_score:.2f}")
    console.print(summary)
    return 0


def _run_live(args: argparse.Namespace) -> int:
    from rich.console import Console
    from rich.panel import Panel

    from .core.orchestrator import Orchestrator
    from .reporter import render_terminal_report

    console = Console()
    output_dir = args.output or config.DEFAULT_OUTPUT_DIR

    if getattr(args, "interfaces", False):
        from .capture.live_capture import LiveCaptureEngine
        interfaces = LiveCaptureEngine().list_interfaces()
        if not interfaces:
            console.print("[yellow]No interfaces detected (check tshark)[/]")
        for iface in interfaces:
            console.print(iface)
        return 0

    console.print(Panel.fit(
        f"[bold cyan]xPREDATOR-EYE[/] v{__version__} - Real-Time Threat Monitoring",
        border_style="cyan",
    ))

    orch = Orchestrator(
        interface=args.interface,
        capture_filter=args.filter,
        watch_paths=args.watch_paths,
        blocklist_path=args.blocklist,
        dry_run=args.dry_run,
        output_dir=output_dir,
        yara_rules=args.yara_rules,
    )

    try:
        orch.start()
        if not args.quiet:
            console.print("[green]Monitoring started. Ctrl+C to stop.[/]")
        duration = getattr(args, "duration", 0) or 0
        start_time = time.monotonic()
        while True:
            if duration > 0 and (time.monotonic() - start_time) >= duration:
                console.print(f"[green]Duration {duration}s elapsed, stopping.[/]")
                break
            time.sleep(1)
    except KeyboardInterrupt:
        pass
    finally:
        orch.stop()

    result = orch.get_result()
    render_terminal_report(result)
    if args.pdf:
        try:
            from .reporting.pdf_report import PDFReportGenerator
            PDFReportGenerator().generate(result, args.pdf, classification=config.DEFAULT_CLASSIFICATION)
            console.print(f"  [green]PDF: {args.pdf}[/]")
        except ImportError:
            console.print("  [dim]PDF generation unavailable[/]")
        except Exception as exc:
            console.print(f"  [dim]PDF report failed: {exc}[/]")
    return 0


def main() -> None:
    setup_logging(getattr(config, "LOG_LEVEL", logging.INFO))
    parser = build_parser()
    args = parser.parse_args()

    if not args.mode:
        parser.print_help()
        return

    if args.mode == "version":
        print(f"xPREDATOR-EYE v{__version__}")
        return

    rc = _run_analyze(args) if args.mode == "analyze" else _run_live(args) if args.mode == "live" else 1
    sys.exit(rc or 0)


if __name__ == "__main__":
    main()
