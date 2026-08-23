from __future__ import annotations

from pathlib import Path
import subprocess
import sys


def test_readme_python_blocks_execute() -> None:
    result = subprocess.run(
        [sys.executable, "scripts/check_readme_examples.py"],
        cwd=Path(__file__).resolve().parents[1],
        capture_output=True,
        text=True,
        check=False,
    )
    assert result.returncode == 0, result.stderr
