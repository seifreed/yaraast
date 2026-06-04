from __future__ import annotations

from pathlib import Path
import subprocess
import sys

SCRIPT_PATH = Path(__file__).resolve().parents[1] / "benchmarks" / "run_all_benchmarks.py"


def test_run_all_benchmarks_help_skips_dependency_checks() -> None:
    proc = subprocess.run(
        [sys.executable, str(SCRIPT_PATH), "--help"],
        cwd=Path(__file__).resolve().parents[1],
        capture_output=True,
        text=True,
        check=False,
        encoding="utf-8",
    )

    assert proc.returncode == 0
    assert "Run the complete YARA AST parser benchmark suite" in proc.stdout
    assert "Missing required dependencies" not in proc.stdout
