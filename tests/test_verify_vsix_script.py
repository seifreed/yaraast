from __future__ import annotations

from pathlib import Path
import subprocess
import sys
import zipfile

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


def test_verify_vsix_accepts_an_explicit_package_path(tmp_path: Path) -> None:
    vsix_path = tmp_path / "extension.vsix"
    required_files = {
        "extension/LICENSE.txt",
        "extension/changelog.md",
        "extension/language-configuration.json",
        "extension/out/extension.js",
        "extension/package.json",
        "extension/readme.md",
        "extension/snippets/yara.code-snippets",
        "extension/syntaxes/yara.tmLanguage.json",
        "extension/icons/yara-dark.png",
        "extension/icons/yara-light.png",
        "extension/icons/yaraast.png",
    }
    with zipfile.ZipFile(vsix_path, "w") as archive:
        for name in required_files:
            archive.writestr(name, "fixture")

    proc = subprocess.run(
        [sys.executable, str(SCRIPT_PATH), str(vsix_path)],
        cwd=Path(__file__).resolve().parents[1],
        capture_output=True,
        text=True,
        check=False,
        encoding="utf-8",
    )

    assert proc.returncode == 0
    assert "VSIX verified: extension.vsix" in proc.stdout
