"""Small filesystem helpers shared by serializers."""

from __future__ import annotations

from pathlib import Path


def read_utf8(path: str | Path) -> str:
    """Read UTF-8 text from disk."""
    with Path(path).open(encoding="utf-8") as handle:
        return handle.read()


def write_utf8(path: str | Path, text: str) -> None:
    """Write UTF-8 text to disk."""
    with Path(path).open("w", encoding="utf-8") as handle:
        handle.write(text)
