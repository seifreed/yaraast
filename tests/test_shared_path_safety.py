"""Tests for shared path safety helpers."""

from __future__ import annotations

from pathlib import Path

import pytest

from yaraast.shared.path_safety import path_has_symlink_ancestor, path_is_symlink


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


def test_path_has_symlink_ancestor_fails_closed_on_oserror(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    nested = tmp_path / "nested" / "file.yar"

    original_is_symlink = Path.is_symlink

    def fake_is_symlink(self: Path) -> bool:
        if self == tmp_path:
            raise OSError("cannot inspect ancestor")
        return original_is_symlink(self)

    monkeypatch.setattr(Path, "is_symlink", fake_is_symlink)

    assert path_has_symlink_ancestor(nested) is True


def test_path_is_symlink_fails_closed_on_oserror(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    path = tmp_path / "file.yar"

    def fake_is_symlink(self: Path) -> bool:
        raise OSError("cannot inspect path")

    monkeypatch.setattr(Path, "is_symlink", fake_is_symlink)

    assert path_is_symlink(path) is True
