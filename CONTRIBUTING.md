# Contributing to xPREDATOR-EYE

Thank you for your interest in contributing! This project thrives on community collaboration. Every contribution matters.

## Ways to Contribute

| Type | What to do |
|------|-----------|
| Bug Reports | Open an issue with reproduction steps |
| Feature Requests | Open an issue with the `enhancement` label |
| Code | Fork, branch, PR |
| Detection Rules | Add behavioral patterns in `behavior_engine.py` |
| Playbooks | Add response playbooks in `response_engine.py` |
| Threat Actor Fingerprints | Add TTP signatures in `threat_actor.py` |
| Documentation | Fix typos, improve examples, add use-cases |
| Testing | Write pytest tests for any module |

## Development Setup

```bash
# Fork and clone
git clone https://github.com/YOUR_USERNAME/xPREDATOR-EYE.git
cd xPREDATOR-EYE

# Create virtual environment
python -m venv venv
source venv/bin/activate  # Linux/macOS
venv\Scripts\activate     # Windows

# Install with dev dependencies
pip install -e ".[dev]"

# Run linter
ruff check .

# Run tests
pytest -v
```

## Code Standards

- **Python 3.10+** — use modern syntax (type hints, match, union types)
- **Type hints** on all public functions
- **Docstrings** in Google style for all modules, classes, and public methods
- **Error handling** — never let exceptions crash the pipeline; log and continue
- **No secrets** in code — use environment variables for API keys
- **Test** new features with at least one pytest test

## Adding Detection Rules

Rules live in `pcapanalyzer/analysis/behavior_engine.py` in the `SEQUENCE_RULES` list:

```python
{
    "name": "Your Detection Name",
    "sequence": ["event_type_1", "event_type_2"],
    "severity": Severity.HIGH,
    "kill_chain": [KillChainPhase.COMMAND_AND_CONTROL],
    "mitre": [MITRETactic.C2],
    "techniques": ["T1071"],
    "description": "What this detects",
},
```

## Adding Response Playbooks

Playbooks live in `pcapanalyzer/response/response_engine.py` in `_load_default_playbooks()`:

```python
Playbook(
    name="Your Playbook",
    description="When to trigger this",
    trigger_conditions=["keyword1", "keyword2"],
    severity_threshold=Severity.HIGH,
    commands=[...],
    tags=["tag1", "tag2"],
),
```

## PR Guidelines

1. One feature/fix per PR
2. Include a description of what changed and why
3. Add tests for new functionality
4. Run `ruff check .` before submitting
5. Update CHANGELOG.md with your change
6. Keep commits atomic and messages clear

## Commit Convention

```
type(scope): short description

feat(behavior): add Cobalt Strike beacon detection rule
fix(capture): handle tshark timeout on slow interfaces
docs(readme): add Docker deployment instructions
refactor(damage): simplify blast radius calculation
test(intel): add unit tests for blocklist matching
```

## Reporting Security Issues

**Do NOT open public issues for security vulnerabilities.** See [SECURITY.md](SECURITY.md) for responsible disclosure.

## Code of Conduct

Be respectful, constructive, and inclusive. We are building tools to protect people — let's build a community that does the same.

---

**Every star, issue, PR, and comment helps make this tool better for defenders everywhere.**
