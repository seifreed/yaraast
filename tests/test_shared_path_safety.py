"""Tests for shared path safety helpers."""

from __future__ import annotations

from pathlib import Path

from yaraast.shared.path_safety import path_has_symlink_ancestor


def test_path_has_symlink_ancestor_ignores_darwin_temp_alias(tmp_path: Path) -> None:
    assert path_has_symlink_ancestor(tmp_path) is False


def test_path_has_symlink_ancestor_detects_nested_symlink_ancestor(tmp_path: Path) -> None:
    outside = tmp_path / "outside"
    outside.mkdir()
    link_dir = tmp_path / "link"
    link_dir.symlink_to(outside, target_is_directory=True)

    nested = link_dir / "nested" / "file.yar"
    nested.parent.mkdir()

    assert path_has_symlink_ancestor(nested) is True
