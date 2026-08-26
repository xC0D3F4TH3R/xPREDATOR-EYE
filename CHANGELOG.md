# Changelog

All notable changes to xPREDATOR-EYE will be documented in this file.

Format based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/).

## [2.0.0] - 2026-08-26

### Added

- **Real-time monitoring mode** — live packet capture via tshark integration
- **Process monitoring** — cross-platform process tracking with anomaly scoring using psutil
- **File integrity monitoring** — baseline-diff monitoring of critical system paths
- **Behavioral analysis engine** — 8 detection rules mapping event sequences to MITRE ATT&CK and Cyber Kill Chain
- **Threat actor profiling** — TTP-based attribution against known actor fingerprints (APT28, APT29, Lazarus, ransomware operators, cryptominers)
- **Damage assessment** — CIA triad impact scoring, blast radius, lateral movement detection, data exfiltration assessment, financial impact estimation
- **Real-time alert system** — rate-limited, deduplicated alerts with JSONL persistence and incident clustering
- **Automated response engine** — platform-specific containment commands for Windows/Linux/macOS with dry-run safety
- **Response playbooks** — pre-built procedures for ransomware, C2 communication, credential theft, and data exfiltration
- **Live terminal dashboard** — real-time Rich UI with threat score bars, alert feed, process monitoring, file change tracking
- **Dual CLI modes** — `live` for real-time monitoring, `analyze` for static PCAP forensics
- **MITRE ATT&CK mapping** — automatic tactic and technique identification from behavioral events
- **Lockheed Martin Cyber Kill Chain** — phase progression tracking across all analysis
- **pyproject.toml** — proper Python packaging with `pip install` support
- **Docker support** — containerized deployment via Dockerfile
- **GitHub repository files** — CONTRIBUTING.md, SECURITY.md, CHANGELOG.md, .gitignore, LICENSE

### Changed

- Complete rewrite of `models.py` — 40+ dataclasses covering all domain objects
- Expanded `config.py` — platform-adaptive configs, behavioral thresholds, detection rules
- Upgraded `cli.py` — dual-mode CLI with subcommands (`live`/`analyze`)
- Enhanced `reporter.py` — comprehensive terminal rendering with behavioral profiles, threat actor panels, damage assessment trees

### Architecture

```
pcapanalyzer/
├── capture/          Live packet, process, and file monitoring
├── analysis/         Behavioral analysis, threat profiling, damage assessment
├── core/             Alert system, orchestrator, response engine
├── ui/               Real-time terminal dashboard
├── [offline]         PCAP parsing, extraction, intelligence (v1 legacy)
```

## [1.0.0] - 2026-08-26

### Added

- Initial release as static PCAP analyzer
- PCAP validation and metadata extraction
- DNS, HTTP, TLS protocol parsing with JA3 fingerprinting
- File carving with magic-byte detection and quarantine
- Local blocklist IOC matching
- VirusTotal and AbuseIPDB API integration stubs
- JSON and Rich terminal report generation
