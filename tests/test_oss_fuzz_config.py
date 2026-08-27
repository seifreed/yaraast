"""Regression checks for the repository-owned OSS-Fuzz candidate."""

from __future__ import annotations

from pathlib import Path
import subprocess
import sys

ROOT = Path(__file__).resolve().parents[1]


def test_oss_fuzz_candidate_is_self_consistent() -> None:
    subprocess.run([sys.executable, "scripts/validate_oss_fuzz.py"], cwd=ROOT, check=True)
    subprocess.run(["bash", "-n", "oss-fuzz/build.sh"], cwd=ROOT, check=True)
