#!/usr/bin/env python3
"""Validate the packaged VSIX contains the expected extension assets."""

from __future__ import annotations

import argparse
import json
from pathlib import Path
import sys
import zipfile

ROOT = Path(__file__).resolve().parents[1]
PACKAGE_JSON = ROOT / "package.json"
EXPECTED_FILES = {
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
FORBIDDEN_BASENAMES = {"AGENTS.md", "CLAUDE.md", "claude.md"}


def read_version() -> str:
    data = json.loads(PACKAGE_JSON.read_text(encoding="utf-8"))
    version = data.get("version")
    if not isinstance(version, str) or not version:
        raise SystemExit("package.json does not define a valid version")
    return version


def _parse_args(argv: list[str] | None = None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Validate the packaged VSIX contains the expected extension assets.",
    )
    return parser.parse_args(argv)


def main(argv: list[str] | None = None) -> int:
    _parse_args(argv)
    version = read_version()
    vsix_path = ROOT / f"yaraast-{version}.vsix"
    if not vsix_path.exists():
        print(f"VSIX not found: {vsix_path}", file=sys.stderr)
        return 1

    with zipfile.ZipFile(vsix_path) as archive:
        names = set(archive.namelist())

    missing = sorted(EXPECTED_FILES - names)
    if missing:
        print("VSIX is missing required files:", file=sys.stderr)
        for name in missing:
            print(f"  - {name}", file=sys.stderr)
        return 1

    forbidden = sorted(name for name in names if Path(name).name in FORBIDDEN_BASENAMES)
    if forbidden:
        print("VSIX contains local agent instruction files:", file=sys.stderr)
        for name in forbidden:
            print(f"  - {name}", file=sys.stderr)
        return 1

    print(f"VSIX verified: {vsix_path.name}")
    print(f"Checked files: {len(EXPECTED_FILES)}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
