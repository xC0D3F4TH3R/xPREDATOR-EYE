"""
__main__.py - Enables running PcapMalAnalyzer via ``python -m pcapanalyzer``.

Usage:
  python -m pcapanalyzer live --interface Ethernet
  python -m pcapanalyzer analyze capture.pcap
"""

from __future__ import annotations

import sys


def main() -> int:
    from .cli import main as _main
    return _main()


if __name__ == "__main__":
    sys.exit(main())
