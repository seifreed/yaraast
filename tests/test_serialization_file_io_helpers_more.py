"""Additional tests for shared serializer file I/O helpers."""

from __future__ import annotations

from pathlib import Path
from typing import Any, cast

import pytest

from yaraast.serialization import serializer_helpers as sh
from yaraast.serialization.file_io_helpers import read_utf8, write_utf8
from yaraast.serialization.serializer_helpers import require_input_path, require_output_path


def test_file_io_helpers_read_and_write_utf8_paths(tmp_path: Path) -> None:
    path = tmp_path / "sample.txt"

    write_utf8(path, "hello")

    assert read_utf8(path) == "hello"
    assert read_utf8(str(path)) == "hello"


def test_serializer_helpers_reject_symlink_output_paths(tmp_path: Path) -> None:
    target = tmp_path / "target.txt"
    target.write_text("target", encoding="utf-8")
    link = tmp_path / "link.txt"
    link.symlink_to(target)

    with pytest.raises(ValueError, match="output_path must not traverse a symlink"):
        require_output_path(link, "output_path")


def test_file_io_helpers_reject_symlink_output_path(tmp_path: Path) -> None:
    target = tmp_path / "target.txt"
    target.write_text("target", encoding="utf-8")
    link = tmp_path / "link.txt"
    link.symlink_to(target)

    with pytest.raises(ValueError, match="path must not traverse a symlink"):
        write_utf8(link, "hello")


def test_file_io_helpers_reject_output_paths_under_symlink_ancestors(tmp_path: Path) -> None:
    outside = tmp_path / "outside"
    outside.mkdir()
    link_dir = tmp_path / "link"
    link_dir.symlink_to(outside, target_is_directory=True)

    with pytest.raises(ValueError, match="path must not traverse a symlink"):
        write_utf8(link_dir / "out.txt", "hello")


def test_serializer_helpers_drop_duplicate_text_wrappers() -> None:
    assert not hasattr(sh, "read_text")
    assert not hasattr(sh, "write_text")


def test_file_io_helpers_reject_non_utf8_encodable_text(tmp_path: Path) -> None:
    with pytest.raises(ValueError, match="text must be UTF-8 encodable"):
        write_utf8(tmp_path / "sample.txt", "\ud800")


@pytest.mark.parametrize("text", [b"content", object()])
def test_file_io_helpers_reject_non_text_content(tmp_path: Path, text: object) -> None:
    with pytest.raises(TypeError, match="text must be a string"):
        write_utf8(tmp_path / "sample.txt", cast(Any, text))


def test_file_io_helpers_reject_non_utf8_file_contents(tmp_path: Path) -> None:
    path = tmp_path / "sample.txt"
    path.write_bytes(b"\xff")

    with pytest.raises(ValueError, match="file must contain valid UTF-8 text"):
        read_utf8(path)


@pytest.mark.parametrize("path", [False, 0, object()])
def test_file_io_helpers_reject_invalid_path_types(path: Any) -> None:
    with pytest.raises(TypeError, match="path must be a file path"):
        read_utf8(cast(Any, path))

    with pytest.raises(TypeError, match="path must be a file path"):
        write_utf8(cast(Any, path), "content")


@pytest.mark.parametrize("path", ["", "   ", "\t"])
def test_file_io_helpers_reject_empty_path(path: str) -> None:
    with pytest.raises(ValueError, match="path must not be empty"):
        read_utf8(path)

    with pytest.raises(ValueError, match="path must not be empty"):
        write_utf8(path, "content")

    with pytest.raises(ValueError, match="input_path must not be empty"):
        require_input_path(path, "input_path")


def test_file_io_helpers_reject_empty_pathlike_paths() -> None:
    class EmptyPathLike:
        def __fspath__(self) -> str:
            return ""

    empty_path = EmptyPathLike()

    with pytest.raises(ValueError, match="path must not be empty"):
        read_utf8(cast(Any, empty_path))

    with pytest.raises(ValueError, match="path must not be empty"):
        write_utf8(cast(Any, empty_path), "content")

    with pytest.raises(ValueError, match="input_path must not be empty"):
        require_input_path(cast(Any, empty_path), "input_path")


def test_file_io_helpers_reject_null_byte_pathlike_paths() -> None:
    class NullPathLike:
        def __fspath__(self) -> str:
            return "\x00broken"

    null_path = NullPathLike()

    with pytest.raises(ValueError, match="path must not contain null bytes"):
        read_utf8(cast(Any, null_path))

    with pytest.raises(ValueError, match="path must not contain null bytes"):
        write_utf8(cast(Any, null_path), "content")


def test_file_io_helpers_reject_directory_paths(tmp_path: Path) -> None:
    directory = tmp_path / "dir"
    directory.mkdir()

    with pytest.raises(ValueError, match="path must not be a directory"):
        read_utf8(directory)

    with pytest.raises(ValueError, match="path must not be a directory"):
        write_utf8(directory, "content")

    with pytest.raises(ValueError, match="input_path must not be a directory"):
        require_input_path(directory, "input_path")


def test_file_io_helpers_reject_inaccessible_paths() -> None:
    path = "a" * 5000

    with pytest.raises(ValueError, match="path could not be accessed"):
        read_utf8(path)

    with pytest.raises(ValueError, match="path could not be accessed"):
        write_utf8(path, "content")

    with pytest.raises(ValueError, match="path could not be accessed"):
        require_input_path(path, "input_path")
