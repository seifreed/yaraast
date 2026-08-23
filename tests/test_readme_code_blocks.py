from __future__ import annotations

import os
from pathlib import Path
import subprocess
import sys

from scripts.check_readme_examples import main


def test_readme_python_blocks_execute() -> None:
    result = subprocess.run(
        [sys.executable, "scripts/check_readme_examples.py"],
        cwd=Path(__file__).resolve().parents[1],
        capture_output=True,
        text=True,
        check=False,
    )
    assert result.returncode == 0, result.stderr


def test_readme_python_blocks_restore_working_directory() -> None:
    original_directory = Path.cwd()
    try:
        main()
        assert Path.cwd() == original_directory
    finally:
        os.chdir(original_directory)
