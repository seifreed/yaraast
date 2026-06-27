"""Path safety helpers."""

from __future__ import annotations

from pathlib import Path
import sys

_DARWIN_SYSTEM_SYMLINK_ANCESTORS = {Path("/") / "tmp", Path("/") / "var"}


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
        return True


def path_has_symlink_ancestor(path: Path) -> bool:
    """Return True when any existing ancestor of `path` is a symlink."""
    for ancestor in path.parents:
        if sys.platform == "darwin" and ancestor in _DARWIN_SYSTEM_SYMLINK_ANCESTORS:
            continue
        try:
            if ancestor.is_symlink():
                return True
        except OSError:
            return True
    return False
