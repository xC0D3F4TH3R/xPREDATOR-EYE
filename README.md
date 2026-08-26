# xPREDATOR-EYE

![Version](https://img.shields.io/badge/version-3.0.0-blue)
![Python](https://img.shields.io/badge/python-3.10%2B-green)
![License](https://img.shields.io/badge/license-MIT-yellow)
![Status](https://img.shields.io/badge/status-Production%20Ready-brightgreen)

**Enterprise AI-Powered Threat Intelligence Suite for Network Security, Malware Analysis, and Incident Response**

xPREDATOR-EYE is a production-grade, open-source security analysis platform designed for SOC analysts, incident responders, threat hunters, and digital forensics professionals. It combines real-time monitoring, deep packet inspection, behavioral analysis, ML classification, YARA scanning, LLM-powered analysis, and automated response — all in a single extensible toolkit.

## Key Capabilities

| Capability | Description |
|------------|-------------|
| **PCAP Forensics** | 9-stage pipeline: ingestion → protocol parsing (DNS/HTTP/TLS/Credentials) → file carving → intelligence → behavioral analysis → threat actor profiling → damage assessment → alerting → response |
| **Real-Time Monitoring** | Live packet capture (tshark), process monitoring (psutil), file integrity monitoring with cross-platform support |
| **Behavioral Analysis** | 30+ detection rules mapping to MITRE ATT&CK, sequence correlation, kill chain mapping |
| **Threat Actor Attribution** | 14 APT/group profiles (APT28, APT29, Lazarus, APT41, Sandworm, Turla, OilRig, Equation Group, Kimsuky, Volt Typhoon, FIN7, etc.) |
| **YARA Scanning** | 15 default malware rules + custom rule support for carved files and memory artifacts |
| **ML Classification** | XGBoost/Random Forest for traffic classification + Isolation Forest anomaly detection |
| **LLM Analysis** | Local Ollama integration for malware explanation, executive summaries, remediation guidance |
| **Professional Reports** | Government-grade PDF (classification banners, MITRE heatmaps, NIST/ISO mapping) + Interactive HTML (Plotly charts, IOC export) |
| **SIEM Integration** | Elasticsearch, Splunk HEC, STIX 2.1/TAXII, MISP export |
| **Zeek/Suricata** | Native log parsing (conn.log, dns.log, http.log, ssl.log, EVE.json) |

## Installation

```bash
# Core dependencies
pip install -e .

# With optional features
pip install -e ".[yara,ml,pdf,siem,llm,stix,config]"

# All features
pip install -e ".[all]"

# Development
pip install -e ".[dev]"
```

### System Requirements

- **Python 3.10+**
- **libpcap/Npcap** (for live capture)
- **GTK/Pango** (for WeasyPrint PDF generation, optional)
- **Ollama** (for LLM features, optional)

```bash
# Ubuntu/Debian
sudo apt install libpcap-dev libgirepository1.0-dev libcairo2-dev libpango1.0-dev

# Windows (via Chocolatey)
choco install npcap

# macOS
brew install libpcap cairo pango gobject-introspection
```

## Quick Start

### Offline PCAP Analysis

```bash
# Basic analysis
xpredator-eye analyze capture.pcap

# Full analysis with all features
xpredator-eye analyze malware.pcap \
  --yara-rules detection/rules/malware.yar \
  --pdf report.pdf \
  --html report.html \
  --stix iocs.stix \
  --llm \
  --siem-url http://elasticsearch:9200 \
  --classification "CONFIDENTIAL // INTERNAL USE ONLY"
```

### Real-Time Monitoring

```bash
# Live monitoring with all sensors
xpredator-eye live --interface Ethernet \
  --yara-rules detection/rules/ \
  --pdf exit_report.pdf \
  --respond --dry-run

# Monitor specific directories
xpredator-eye live --watch-paths /tmp /var/tmp /home/user/Downloads \
  --blocklist iocs.json
```

## CLI Reference

### `analyze` Mode

```bash
xpredator-eye analyze <pcap_file> [options]

Options:
  -o, --output PATH         Output directory (default: ~/.xpredator-eye/output)
  --blocklist PATH          IOC blocklist JSON file
  --respond                 Generate automated response plan
  --respond-execute         Execute response commands (requires confirmation)
  --quiet                   Suppress output except final summary
  --yara-rules PATH         YARA rules file or directory
  --ml-model PATH           Pre-trained ML model (.pkl)
  --pdf PATH                Generate PDF report
  --html PATH               Generate interactive HTML report
  --stix PATH               Export IOCs as STIX 2.1 bundle
  --siem-url URL            Elasticsearch URL for SIEM push
  --llm                     Enable LLM-powered analysis
  --llm-model NAME          Ollama model (default: llama3.2:3b)
  --classification STR      Report classification banner
```

### `live` Mode

```bash
xpredator-eye live [options]

Options:
  -i, --interface NAME      Network interface to capture on
  -f, --filter BPF          Capture filter (BPF syntax)
  -o, --output PATH         Output directory
  --watch-paths DIRS        Directories to watch for file changes
  --blocklist PATH          IOC blocklist JSON
  --respond                 Enable automated response
  --dry-run                 Dry-run response actions (default: true)
  --quiet                   Suppress dashboard output
  --yara-rules PATH         YARA rules for live scanning
  --pdf PATH                Generate PDF report on exit
```

## Architecture

```
xPREDATOR-EYE/
├── pcapanalyzer/
│   ├── cli.py                 # Main entry point
│   ├── config.py              # Configuration constants
│   ├── models.py              # Domain models (dataclasses)
│   ├── utils.py               # Logging, helpers
│   ├── ingestion.py           # PCAP validation, flow extraction
│   ├── parser.py              # DNS, HTTP, TLS, credential parsing
│   ├── extractor.py           # File carving from streams
│   ├── intelligence.py        # IOC extraction + threat intel
│   ├── reporter.py            # Terminal/JSON reporting
│   ├── detection/
│   │   ├── yara_scanner.py    # YARA rule compilation/scanning
│   │   └── rules/malware.yar  # 15 default malware rules
│   ├── ml/
│   │   ├── feature_extractor.py  # 22 network flow features
│   │   └── classifier.py         # XGBoost + Isolation Forest
│   ├── reporting/
│   │   ├── pdf_report.py      # WeasyPrint PDF generation
│   │   └── html_report.py     # Plotly interactive HTML
│   ├── integrations/
│   │   ├── siem_integration.py # Elasticsearch, Splunk, STIX
│   │   ├── zeek_parser.py     # Zeek log parsing
│   │   └── suricata_parser.py # Suricata EVE.json
│   ├── analysis/
│   │   ├── behavior_engine.py # 30+ sequence rules
│   │   ├── threat_actor.py    # 14 APT profiles
│   │   ├── damage_assessor.py # 4-vector damage scoring
│   │   └── llm_analyzer.py    # Ollama LLM integration
│   ├── core/
│   │   ├── orchestrator.py    # Live mode coordinator
│   │   ├── alert_system.py    # Alerting with dedup/rate-limit
│   │   └── health_monitor.py  # Engine health checks
│   ├── capture/
│   │   ├── live_capture.py    # tshark wrapper
│   │   ├── process_monitor.py # psutil process tracking
│   │   └── file_monitor.py    # File integrity monitoring
│   └── response/
│       └── response_engine.py # Safe command generation/execution
├── config.yaml                # Runtime configuration
├── pyproject.toml             # Package metadata + optional deps
└── requirements.txt           # Core dependencies
```

## Configuration

Copy `config.yaml` to `~/.xpredator-eye/config.yaml` and customize:

```yaml
general:
  log_level: INFO
  output_dir: ~/.xpredator-eye/output

capture:
  snaplen: 65535
  buffer_size: 134217728

behavioral:
  sequence_window: 300
  suspicious_threshold: 0.4

ml:
  model_path: ~/.xpredator-eye/models/classifier.pkl

yara:
  rules_dir: ~/.xpredator-eye/rules

llm:
  enabled: false
  model: llama3.2:3b
  ollama_url: http://localhost:11434

siem:
  elasticsearch:
    enabled: false
    hosts: ["http://localhost:9200"]
```

## MITRE ATT&CK Coverage

xPREDATOR-EYE detects patterns across all 14 MITRE tactics:

| Tactic | Techniques Detected |
|--------|---------------------|
| Initial Access | T1190, T1566 |
| Execution | T1059, T1059.001, T1218 |
| Persistence | T1053, T1547, T1547.001, T1574.002 |
| Privilege Escalation | T1068, T1055, T1068 |
| Defense Evasion | T1036, T1027, T1070, T1564, T1218 |
| Credential Access | T1003, T1003.001, T1558.003 |
| Discovery | T1046, T1018, T1087 |
| Lateral Movement | T1021, T1021.002, T1047, T1550.002 |
| Collection | T1074, T1074.001, T1560 |
| C2 | T1071, T1071.004, T1573, T1573.002 |
| Exfiltration | T1041, T1048.003 |
| Impact | T1486, T1490, T1496 |

## Threat Actor Profiles (14)

- **APT28 (Fancy Bear)** — Espionage, Expert
- **APT29 (Cozy Bear)** — Espionage, Expert  
- **Lazarus Group** — Financial, Advanced
- **APT41 (Double Dragon)** — Espionage, Expert
- **APT40 (Leviathan)** — Espionage, Advanced
- **FIN7 (Carbanak)** — Financial, Advanced
- **Sandworm Team** — Destructive, Expert
- **Turla (Snake/Uroburos)** — Espionage, Innovator
- **OilRig (APT34)** — Espionage, Advanced
- **Equation Group** — Espionage, Innovator
- **Kimsuky** — Espionage, Advanced
- **Volt Typhoon** — Espionage, Advanced
- **Ransomware Operator (Generic)** — Financial, Advanced
- **Crypto Miner** — Financial, Intermediate

## Output Formats

### Terminal Report
Real-time colored output with tables, severity summaries, and key findings.

### JSON Report (`analysis_report.json`)
Machine-readable complete analysis for automation pipelines.

### PDF Report (`--pdf`)
- Classification banners (UNCLASSIFIED, FOUO, CUI, CONFIDENTIAL, SECRET)
- Executive summary + technical details + appendices
- MITRE ATT&CK Navigator heatmap (SVG)
- NIST CSF 2.0 / ISO 27001 / SOC 2 / PCI DSS / HIPAA compliance mapping
- Severity distribution charts, timeline, kill chain progression

### HTML Report (`--html`)
- Self-contained single-file with embedded Plotly.js
- Interactive charts (click to filter, hover for details)
- Searchable/filterable IOC tables
- One-click JSON/CSV IOC export
- Collapsible sections, responsive design

### STIX 2.1 Bundle (`--stix`)
Standardized IOC export for MISP, TAXII, OpenCTI, ThreatConnect.

## SIEM Integration

### Elasticsearch
```bash
xpredator-eye analyze capture.pcap --siem-url http://es:9200
```
Pushes alerts, IOCs, behavioral events with pre-built index templates.

### Splunk HEC
```bash
xpredator-eye analyze capture.pcap --siem-url https://splunk:8088 --siem-token <HEC_TOKEN>
```
CIM-compliant events for Splunk Enterprise Security.

## LLM-Powered Analysis

Requires [Ollama](https://ollama.ai) running locally:

```bash
ollama pull llama3.2:3b
xpredator-eye analyze capture.pcap --llm --llm-model llama3.2:3b
```

Generates:
- Executive summary in plain language
- IOC context and threat actor context
- Prioritized remediation steps
- Custom YARA rule suggestions from observed patterns

## Response Engine Safety

All commands default to **dry-run mode**. Explicit `--respond-execute` required for actual execution.

```bash
# Dry-run (safe)
xpredator-eye analyze capture.pcap --respond

# Actual execution (requires confirmation)
xpredator-eye analyze capture.pcap --respond --respond-execute
```

Supported actions: `block_ip`, `block_domain`, `block_port`, `kill_process`, `quarantine_file`, `isolate_host`, `capture_forensics`, `notify_admin`, `enable_logging`.

## Development

```bash
# Run tests
pytest tests/ -v --cov=pcapanalyzer

# Lint
ruff check .

# Type check
mypy pcapanalyzer

# Security scan
bandit -r pcapanalyzer
```

## Contributing

See [CONTRIBUTING.md](CONTRIBUTING.md) for guidelines.

## License

MIT License — see [LICENSE](LICENSE) for details.

## Citation

If you use xPREDATOR-EYE in research or operations, please cite:

```
@software{xpredator-eye,
  author = {xC0D3F4TH3R},
  title = {xPREDATOR-EYE: Enterprise AI-Powered Threat Intelligence Suite},
  version = {3.0.0},
  url = {https://github.com/xC0D3F4TH3R/xPREDATOR-EYE},
  year = {2026}
}
```

## Support

- **Issues**: [GitHub Issues](https://github.com/xC0D3F4TH3R/xPREDATOR-EYE/issues)
- **Discussions**: [GitHub Discussions](https://github.com/xC0D3F4TH3R/xPREDATOR-EYE/discussions)
- **Security**: Report vulnerabilities privately via [security@xC0D3F4TH3R.dev](mailto:security@xC0D3F4TH3R.dev)

---

**Built for defenders, by defenders.** 🛡️