"""Regression checks for the repository-owned OSS-Fuzz candidate."""

from __future__ import annotations

from pathlib import Path
import shutil
import subprocess
import sys

import pytest

ROOT = Path(__file__).resolve().parents[1]


def test_oss_fuzz_candidate_is_self_consistent() -> None:
    subprocess.run([sys.executable, "scripts/validate_oss_fuzz.py"], cwd=ROOT, check=True)


@pytest.mark.skipif(
    shutil.which("bash") is None,
    reason="bash is unavailable on this host; docs/test-skips.yml",
)
def test_oss_fuzz_build_script_has_valid_shell_syntax() -> None:
    bash = shutil.which("bash")
    assert bash is not None
    subprocess.run([bash, "-n", "oss-fuzz/build.sh"], cwd=ROOT, check=True)
