"""Real process-level tests for package entrypoint."""

from __future__ import annotations

import subprocess
import sys


def test_main_entry_help() -> None:
    proc = subprocess.run(
        [sys.executable, "-m", "yaraast", "--help"],
        capture_output=True,
        text=True,
        check=False,
    )
    assert proc.returncode == 0
    assert "Usage" in proc.stdout


def test_main_entry_invalid_command_nonzero() -> None:
    proc = subprocess.run(
        [sys.executable, "-m", "yaraast", "no-such-command"],
        capture_output=True,
        text=True,
        check=False,
    )
    assert proc.returncode != 0
