"""Additional tests for shared serializer file I/O helpers."""

from __future__ import annotations

from pathlib import Path
from typing import Any, cast

import pytest

from yaraast.serialization.file_io_helpers import read_utf8, write_utf8


def test_file_io_helpers_read_and_write_utf8_paths(tmp_path: Path) -> None:
    path = tmp_path / "sample.txt"

    write_utf8(path, "hello")

    assert read_utf8(path) == "hello"
    assert read_utf8(str(path)) == "hello"


@pytest.mark.parametrize("path", [False, 0, object()])
def test_file_io_helpers_reject_invalid_path_types(path: Any) -> None:
    with pytest.raises(TypeError, match="path must be a file path"):
        read_utf8(cast(Any, path))

    with pytest.raises(TypeError, match="path must be a file path"):
        write_utf8(cast(Any, path), "content")


def test_file_io_helpers_reject_empty_path() -> None:
    with pytest.raises(ValueError, match="path must not be empty"):
        read_utf8("")

    with pytest.raises(ValueError, match="path must not be empty"):
        write_utf8("", "content")
