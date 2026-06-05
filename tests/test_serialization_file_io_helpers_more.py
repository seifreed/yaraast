"""Additional tests for shared serializer file I/O helpers."""

from __future__ import annotations

from pathlib import Path
from typing import Any, cast

import pytest

from yaraast.serialization.file_io_helpers import read_utf8, write_utf8
from yaraast.serialization.serializer_helpers import require_input_path


def test_file_io_helpers_read_and_write_utf8_paths(tmp_path: Path) -> None:
    path = tmp_path / "sample.txt"

    write_utf8(path, "hello")

    assert read_utf8(path) == "hello"
    assert read_utf8(str(path)) == "hello"


def test_file_io_helpers_reject_non_utf8_encodable_text(tmp_path: Path) -> None:
    with pytest.raises(ValueError, match="text must be UTF-8 encodable"):
        write_utf8(tmp_path / "sample.txt", "\ud800")


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


def test_file_io_helpers_reject_directory_paths(tmp_path: Path) -> None:
    directory = tmp_path / "dir"
    directory.mkdir()

    with pytest.raises(ValueError, match="path must not be a directory"):
        read_utf8(directory)

    with pytest.raises(ValueError, match="path must not be a directory"):
        write_utf8(directory, "content")

    with pytest.raises(ValueError, match="input_path must not be a directory"):
        require_input_path(directory, "input_path")
