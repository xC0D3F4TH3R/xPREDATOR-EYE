<p align="center">
  <br>
  <img src="https://img.shields.io/badge/VERSION-2.0.0-blue?style=for-the-badge" alt="version"/>
  <img src="https://img.shields.io/badge/PYTHON-3.10+-yellow?style=for-the-badge&logo=python&logoColor=white" alt="python"/>
  <img src="https://img.shields.io/badge/LICENSE-MIT-green?style=for-the-badge" alt="license"/>
  <img src="https://img.shields.io/badge/STATUS-BETA-orange?style=for-the-badge" alt="status"/>
  <img src="https://img.shields.io/badge/PRs-WELCOME-pink?style=for-the-badge" alt="prs"/>
  <img src="https://img.shields.io/github/stars/xC0D3F4TH3R/xPREDATOR-EYE?style=for-the-badge&color=yellow" alt="stars"/>
  <img src="https://img.shields.io/github/forks/xC0D3F4TH3R/xPREDATOR-EYE?style=for-the-badge" alt="forks"/>
</p>

<h1 align="center">
  <br>
  <img src="https://img.shields.io/badge/%F0%9F%94%B4%20xPREDATOR--EYE-2.0-red?style=for-the-badge&labelColor=black" alt="xPREDATOR-EYE"/>
  <br>
  Enterprise Threat Intelligence Suite
  <br>
</h1>

<p align="center">
  Real-time network monitoring &bull; Behavioral analysis &bull; Threat actor profiling<br>
  Damage assessment &bull; Automated response &bull; MITRE ATT&CK mapping
</p>

<p align="center">
  <a href="#-features">Features</a> &bull;
  <a href="#-architecture">Architecture</a> &bull;
  <a href="#-quick-start">Quick Start</a> &bull;
  <a href="#-usage">Usage</a> &bull;
  <a href="#-detection">Detection</a> &bull;
  <a href="#-contributing">Contributing</a> &bull;
  <a href="#-license">License</a>
</p>

---

## Why xPREDATOR-EYE?

Most security tools do **one thing**. xPREDATOR-EYE does **everything** in a single, unified pipeline:

```
  NETWORK ──┐                    ┌── Behavioral Analysis
  PROCESS ──┼── Real-Time ──►    ├── Threat Actor Profiling
  FILE    ──┘    Capture         ├── Damage Assessment
                                 ├── Live Alert System
                                 ├── Automated Response
                                 └── Structured Reports
```

Built for **SOC analysts**, **incident responders**, **threat hunters**, and **malware analysts** who need a single tool that watches, thinks, predicts, and acts.

---

## Features

<table>
<tr>
<td width="50%">

### Live Monitoring
- Real-time packet capture via **tshark**
- Cross-platform **process monitoring** (psutil)
- **File integrity** baseline monitoring
- Auto-detection of network interfaces

</td>
<td width="50%">

### Behavioral Intelligence
- **8 detection rules** with event correlation
- **MITRE ATT&CK** tactic/technique mapping
- **Kill Chain** phase progression tracking
- Anomaly detection with scoring

</td>
</tr>
<tr>
<td>

### Threat Actor Profiling
- TTP-based **attribution engine**
- Known actor fingerprints: APT28, APT29, Lazarus, ransomware, cryptominers
- Campaign aggregation and tracking
- Confidence-scored attribution

</td>
<td>

### Damage Assessment
- **CIA triad** impact scoring
- Blast radius calculation
- Lateral movement detection
- Data exfiltration assessment
- Financial impact estimation

</td>
</tr>
<tr>
<td>

### Real-Time Alerts
- Rate-limited, deduplicated alerts
- JSONL persistence for SIEM ingestion
- Alert correlation into **incident clusters**
- Priority-based escalation

</td>
<td>

### Automated Response
- **10 containment actions** across Windows/Linux/macOS
- 4 pre-built **response playbooks**
- Dry-run safety (default)
- Forensic evidence capture

</td>
</tr>
</table>

---

## Architecture

```
xPREDATOR-EYE
│
├── capture/                          LIVE MONITORING ENGINES
│   ├── live_capture.py          ◄── tshark streaming integration
│   ├── process_monitor.py       ◄── psutil cross-platform process tracking
│   └── file_monitor.py          ◄── Baseline-diff file integrity monitoring
│
├── analysis/                         INTELLIGENCE ENGINES
│   ├── behavior_engine.py       ◄── Event correlation + MITRE/Kill Chain mapping
│   ├── threat_actor.py          ◄── TTP-based attribution + campaign tracking
│   └── damage_assessor.py       ◄── CIA impact + blast radius + exfil scoring
│
├── core/                             COORDINATION LAYER
│   ├── alert_system.py          ◄── Real-time alerting + dedup + correlation
│   ├── orchestrator.py          ◄── Master pipeline connecting all engines
│   └── response_engine.py       ◄── Platform-specific containment + playbooks
│
├── ui/
│   └── dashboard.py             ◄── Real-time Rich terminal dashboard
│
├── [offline analysis]                STATIC PCAP FORENSICS
│   ├── ingestion.py             ◄── PCAP validation + flow extraction
│   ├── parser.py                ◄── DNS/HTTP/TLS/credential parsing
│   ├── extractor.py             ◄── Stream reassembly + file carving
│   └── intelligence.py          ◄── IOC matching + VT/AbuseIPDB
│
└── reporter.py                       JSON + terminal report generation
```

**Data Flow:**

```
┌─────────────┐     ┌──────────────┐     ┌─────────────────┐
│  CAPTURE    │────▶│  BEHAVIOR    │────▶│  ALERT SYSTEM   │
│  (network,  │     │  ENGINE      │     │  (dedup, rate   │
│   process,  │     │  (correlate, │     │   limit, group) │
│   files)    │     │   score)     │     └────────┬────────┘
└─────────────┘     └──────┬───────┘              │
                           │                      ▼
                    ┌──────▼───────┐     ┌─────────────────┐
                    │  THREAT      │     │  RESPONSE       │
                    │  ACTOR       │     │  ENGINE         │
                    │  PROFILER    │     │  (contain,      │
                    └──────┬───────┘     │   respond)      │
                           │             └─────────────────┘
                    ┌──────▼───────┐
                    │  DAMAGE      │
                    │  ASSESSOR    │
                    └──────────────┘
```

---

## Quick Start

### Installation

```bash
# Clone the repository
git clone https://github.com/xC0D3F4TH3R/xPREDATOR-EYE.git
cd xPREDATOR-EYE

# Create virtual environment
python -m venv venv
source venv/bin/activate       # Linux/macOS
venv\Scripts\activate          # Windows

# Install
pip install -e .

# Or just install dependencies
pip install -r requirements.txt
```

### Docker

```bash
docker build -t xpredator-eye .
docker run -it xpredator-eye live --interface eth0
```

### First Run

```bash
# List available network interfaces
python -m pcapanalyzer live --interfaces

# Start live monitoring
python -m pcapanalyzer live

# Analyze a PCAP file
python -m pcapanalyzer analyze capture.pcap
```

---

## Usage

### Live Monitoring Mode

```bash
# Basic monitoring with auto-detected interface
python -m pcapanalyzer live

# Specific interface with BPF filter
python -m pcapanalyzer live -i "Ethernet" -f "tcp port 443"

# Monitor with file integrity watching
python -m pcapanalyzer live --watch-paths /etc /tmp /var/log

# Time-limited monitoring with verbose logging
python -m pcapanalyzer live --duration 300 -v

# Enable automated response (CAUTION: executes real commands)
python -m pcapanalyzer live --respond

# With local blocklist
python -m pcapanalyzer live -b blocklist.json
```

### Static PCAP Analysis

```bash
# Full 9-stage analysis pipeline
python -m pcapanalyzer analyze suspicious.pcap

# With response plan generation
python -m pcapanalyzer analyze suspicious.pcap --respond -o results/

# With external API enrichment
export VIRUSTOTAL_API_KEY=your_key
export ABUSEIPDB_API_KEY=your_key
python -m pcapanalyzer analyze suspicious.pcap

# JSON-only output for SIEM ingestion
python -m pcapanalyzer analyze suspicious.pcap --json-only -q
```

### CLI Reference

| Flag | Description |
|------|-------------|
| `live` | Enter real-time monitoring mode |
| `analyze` | Enter static PCAP analysis mode |
| `-i, --interface` | Network interface for live capture |
| `-f, --filter` | BPF capture filter expression |
| `-o, --output-dir` | Output directory |
| `-b, --blocklist` | Local JSON blocklist path |
| `--watch-paths` | Filesystem paths to monitor |
| `--respond` | Enable automated response |
| `--no-intel` | Skip external API enrichment |
| `--duration` | Monitoring duration (seconds) |
| `--json-only` | JSON report only |
| `--interfaces` | List network interfaces |
| `-v, --verbose` | DEBUG logging |
| `-q, --quiet` | Suppress terminal output |

---

## Detection Capabilities

### Behavioral Patterns

| Pattern | Kill Chain Phase | MITRE Tactic |
|---------|-----------------|--------------|
| Suspicious Process + Network Connection | Installation / C2 | Execution / C2 |
| Credential Access + Lateral Movement | Exploitation / Actions | Credential Access / Lateral Movement |
| File Write + Process Creation | Installation | Persistence / Execution |
| DNS Tunneling (rapid high-entropy queries) | C2 | C2 |
| Data Staging + Exfiltration | Actions on Objectives | Collection / Exfiltration |
| Reconnaissance Activity | Reconnaissance | Discovery |
| Binary Masquerading | Installation | Defense Evasion |
| Privilege Escalation Pattern | Exploitation | Privilege Escalation |

### Threat Actor Attribution

| Actor | Aliases | Motivation | Sophistication |
|-------|---------|------------|----------------|
| APT28 | Fancy Bear, Sofacy, Pawn Storm | Espionage | Expert |
| APT29 | Cozy Bear, The Dukes, YTTRIUM | Espionage | Expert |
| Lazarus Group | HIDDEN COBRA, Zinc | Financial | Advanced |
| Ransomware Operators | REvil, Conti, LockBit, BlackCat | Financial | Advanced |
| Crypto Miners | CoinMiner, Cryptoloot | Financial | Intermediate |

### Response Playbooks

| Playbook | Trigger | Actions |
|----------|---------|---------|
| Ransomware Response | ransomware, encryption | Isolate, Capture, Notify, Report |
| C2 Communication | c2, beacon | Capture, Enable Logging, Report |
| Credential Theft | credential, password, hash_dump | Capture, Reset, Enable Logging, Report |
| Data Exfiltration | exfiltration, data_loss | Block, Capture, Report |

---

## Output Formats

### JSON Report
```json
{
  "report_metadata": { "tool": "xPREDATOR-EYE", "version": "2.0.0" },
  "behavioral_profile": { "behavioral_score": 0.82, "patterns": [...] },
  "threat_actors": [{ "aliases": ["APT28"], "attribution_confidence": 0.73 }],
  "damage_assessment": { "overall_score": 65.0, "severity": "high" },
  "alerts": [...],
  "response_plan": { "commands": [...] }
}
```

### Terminal Dashboard
```
┌─────────────────────────────┬──────────────────────────────┐
│ Statistics                  │ Threat Scores                │
│ Packets: 142,847            │ Behavioral: ████████░░ 82%   │
│ Events:  3,291              │ Damage:    ██████░░░░ 65%    │
│ Alerts:  7 (2 CRITICAL)     │                              │
├─────────────────────────────┴──────────────────────────────┤
│ Recent Alerts                                             │
│ 14:32:01  CRITICAL  Suspicious Process + Network          │
│ 14:31:58  HIGH      Credential Access + Lateral Movement  │
│ 14:31:45  MEDIUM    DNS Tunneling Pattern                 │
└───────────────────────────────────────────────────────────┘
```

### Alert Log (JSONL for SIEM)
```json
{"alert_id":"a3f2c1","priority":"CRITICAL","title":"Suspicious Process + Network","src_ip":"10.0.1.50","dst_ip":"185.234.72.18"}
```

---

## Configuration

All thresholds and detection rules are centralized in `config.py`:

| Setting | Default | Description |
|---------|---------|-------------|
| `PROCESS_POLL_INTERVAL` | 2.0s | Process snapshot interval |
| `FILE_MONITOR_INTERVAL` | 5.0s | File integrity check interval |
| `BEHAVIOR_SEQUENCE_WINDOW` | 300s | Event correlation window |
| `BEHAVIOR_SCORE_SUSPICIOUS` | 0.4 | Threshold for suspicious alerts |
| `BEHAVIOR_SCORE_MALICIOUS` | 0.7 | Threshold for malicious alerts |
| `ALERT_MAX_PER_MINUTE` | 60 | Alert rate limit |
| `DNS_ENTROPY_THRESHOLD` | 3.5 | DGA detection threshold |
| `RESPONSE_DRY_RUN_DEFAULT` | True | Safe mode for response commands |

---

## Contributing

We welcome contributions! See [CONTRIBUTING.md](CONTRIBUTING.md) for:

- Development setup
- Adding detection rules
- Adding response playbooks
- PR guidelines and commit conventions

**Quick contribution ideas:**
- Add new MITRE ATT&CK detection patterns
- Create response playbooks for specific threat types
- Add threat actor fingerprints for your region/industry
- Improve platform-specific commands
- Write tests for any module
- Improve documentation

---

## Security

See [SECURITY.md](SECURITY.md) for responsible disclosure guidelines.

**Never run automated response (`--respond`) on production systems without understanding the commands.**

---

## Roadmap

- [ ] HTML/PDF report export
- [ ] Elasticsearch/SIEM output integration
- [ ] YARA rule integration
- [ ] Sigma rule generation
- [ ] Zeek/Suricata log correlation
- [ ] Web dashboard (Flask/FastAPI)
- [ ] VirusTotal bulk hash lookup
- [ ] MISP integration
- [ ] Automated PCAP download from case management
- [ ] Memory forensics integration (Volatility)

---

## License

MIT License - see [LICENSE](LICENSE)

---

<p align="center">
  <b>Built for defenders, by defenders.</b><br>
  <sub>Star this repo if it helps you protect your network.</sub>
</p>

<p align="center">
  <a href="https://github.com/xC0D3F4TH3R/xPREDATOR-EYE/stargazers">
    <img src="https://img.shields.io/github/stars/xC0D3F4TH3R/xPREDATOR-EYE?style=social" alt="Star xPREDATOR-EYE"/>
  </a>
</p>
