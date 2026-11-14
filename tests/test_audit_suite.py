"""Integration test verifying the benchmark audit suite within pytest."""
import subprocess
import sys
from pathlib import Path


def test_audit_verification_suite():
    root = Path(__file__).resolve().parent.parent
    proc = subprocess.run(
        [sys.executable, "audit/test_whole_suite.py"],
        capture_output=True,
        text=True,
        cwd=str(root),
    )
    assert proc.returncode == 0, f"Audit suite failed:\n{proc.stdout}\n{proc.stderr}"
