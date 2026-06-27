"""Path safety helpers."""

from __future__ import annotations

from pathlib import Path


def path_is_within_directory(path: Path, directory: Path) -> bool:
    """Return True when `path` resolves inside `directory`."""
    try:
        return path.resolve().is_relative_to(directory.resolve())
    except OSError:
        return False


def path_is_symlink(path: Path) -> bool:
    """Return True when `path` is a symlink, otherwise False on access errors."""
    try:
        return path.is_symlink()
    except OSError:
        return False
