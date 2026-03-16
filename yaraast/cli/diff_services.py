"""Diff services for CLI (logic without IO)."""

from __future__ import annotations

from pathlib import Path

from yaraast.cli.simple_differ import SimpleASTDiffer


def diff_files(file1: Path, file2: Path):
    differ = SimpleASTDiffer()
    return differ.diff_files(file1, file2)
