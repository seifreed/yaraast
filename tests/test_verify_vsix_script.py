from __future__ import annotations

from pathlib import Path
import subprocess
import sys

SCRIPT_PATH = Path(__file__).resolve().parents[1] / "vscode-yaraast" / "scripts" / "verify_vsix.py"


def test_verify_vsix_help_prints_usage_without_verifying() -> None:
    proc = subprocess.run(
        [sys.executable, str(SCRIPT_PATH), "--help"],
        cwd=Path(__file__).resolve().parents[1],
        capture_output=True,
        text=True,
        check=False,
        encoding="utf-8",
    )

    assert proc.returncode == 0
    assert "Validate the packaged VSIX" in proc.stdout
    assert "VSIX verified" not in proc.stdout
