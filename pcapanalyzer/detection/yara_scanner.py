"""
yara_scanner.py - YARA rule compilation and malware signature scanning.

Scans carved files, memory dumps, and network payloads against YARA rules
for malware family identification and threat classification.
"""

from __future__ import annotations

import os
from pathlib import Path
from typing import Optional

from ..utils import get_logger

logger = get_logger("yara_scanner")

try:
    import yara
    YARA_AVAILABLE = True
except ImportError:
    YARA_AVAILABLE = False
    yara = None  # type: ignore[assignment]


class YaraScanner:
    """YARA-based malware signature scanner.

    Usage::

        scanner = YaraScanner()
        scanner.load_rules("rules/malware.yar")
        matches = scanner.scan_file("/path/to/suspicious.exe")
    """

    def __init__(self) -> None:
        self._compiled_rules: list = []
        self._rule_files: list[Path] = []
        if not YARA_AVAILABLE:
            logger.warning("yara-python not installed. YARA scanning disabled.")

    def load_rules(self, path: str | Path) -> None:
        """Compile and load YARA rules from a file or directory."""
        if not YARA_AVAILABLE:
            return

        path = Path(path)
        if path.is_file():
            self._load_single_rule(path)
        elif path.is_dir():
            for rule_file in path.rglob("*.yar"):
                self._load_single_rule(rule_file)
            for rule_file in path.rglob("*.yara"):
                self._load_single_rule(rule_file)

    def _load_single_rule(self, path: Path) -> None:
        try:
            rule = yara.compile(filepath=str(path))
            self._compiled_rules.append(rule)
            self._rule_files.append(path)
            logger.info("Loaded YARA rules: %s", path.name)
        except yara.SyntaxError as exc:
            logger.error("YARA rule compilation error in %s: %s", path.name, exc)
        except Exception as exc:
            logger.error("Failed to load YARA rule %s: %s", path.name, exc)

    def scan_file(self, filepath: str | Path) -> list[dict]:
        """Scan a file against all loaded YARA rules."""
        if not YARA_AVAILABLE or not self._compiled_rules:
            return []

        filepath = Path(filepath)
        if not filepath.exists():
            return []

        matches = []
        for rule in self._compiled_rules:
            try:
                file_matches = rule.match(filepath=str(filepath), timeout=30)
                for match in file_matches:
                    matches.append({
                        "rule": match.rule,
                        "tags": match.tags,
                        "meta": match.meta,
                        "strings": [
                            {
                                "identifier": s.identifier,
                                "instances": [
                                    {"offset": i.offset, "matched_length": i.matched_length}
                                    for i in s.instances
                                ]
                            }
                            for s in match.strings
                        ]
                    })
            except yara.TimeoutError:
                logger.warning("YARA scan timeout for %s", filepath.name)
            except Exception as exc:
                logger.error("YARA scan error for %s: %s", filepath.name, exc)

        return matches

    def scan_data(self, data: bytes) -> list[dict]:
        """Scan raw bytes against all loaded YARA rules."""
        if not YARA_AVAILABLE or not self._compiled_rules:
            return []

        matches = []
        for rule in self._compiled_rules:
            try:
                data_matches = rule.match(data=data, timeout=30)
                for match in data_matches:
                    matches.append({
                        "rule": match.rule,
                        "tags": match.tags,
                        "meta": match.meta,
                        "strings": [
                            {
                                "identifier": s.identifier,
                                "offsets": [(i.offset, i.matched_length) for i in s.instances]
                            }
                            for s in match.strings
                        ]
                    })
            except yara.TimeoutError:
                logger.warning("YARA scan timeout on data block")
            except Exception as exc:
                logger.error("YARA scan error: %s", exc)

        return matches

    def get_rule_count(self) -> int:
        return len(self._compiled_rules)

    def get_loaded_rules(self) -> list[str]:
        return [str(p) for p in self._rule_files]
