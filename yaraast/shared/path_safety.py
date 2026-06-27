"""Path safety helpers."""

from __future__ import annotations

from pathlib import Path


def path_is_within_directory(path: Path, directory: Path) -> bool:
    """Return True when `path` resolves inside `directory`."""
    try:
        return path.resolve().is_relative_to(directory.resolve())
    except OSError:
        return False
