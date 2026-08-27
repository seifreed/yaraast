from __future__ import annotations

from pathlib import Path
import subprocess
import sys

ROOT = Path(__file__).resolve().parents[1]


def test_quickstart_example_runs() -> None:
    result = subprocess.run(
        [sys.executable, "examples/quickstart.py"],
        cwd=ROOT,
        check=True,
        capture_output=True,
        text=True,
    )
    assert "rule example" in result.stdout
