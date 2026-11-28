"""Liquid AI d1-3B Static Analysis Alert Triage CLI.

Usage:
    python d1_triage.py --demo --mock
    python d1_triage.py --scan semgrep.json --mock
    python d1_triage.py --benchmark ghsa --limit 5 --mock
    python d1_triage.py --cpu
    python d1_triage.py --mock
"""
from d1_triage.cli import main

if __name__ == "__main__":
    main()
