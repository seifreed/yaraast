"""Additional tests for shared CLI utilities."""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any, cast

import click
import pytest

from yaraast.cli import utils


def test_cli_utils_read_write_text_and_json(tmp_path: Path) -> None:
    text_path = tmp_path / "sample.txt"
    json_path = tmp_path / "sample.json"

    utils.write_text(text_path, "hello")
    utils.write_json(json_path, {"value": 1})

    assert utils.read_text(text_path) == "hello"
    assert json.loads(utils.read_text(json_path)) == {"value": 1}


def test_cli_utils_rejects_non_utf8_encodable_text(tmp_path: Path) -> None:
    with pytest.raises(ValueError, match="content must be UTF-8 encodable"):
        utils.write_text(tmp_path / "sample.txt", "\ud800")


@pytest.mark.parametrize("content", [b"content", object()])
def test_cli_utils_rejects_non_text_content(tmp_path: Path, content: object) -> None:
    with pytest.raises(TypeError, match="content must be a string"):
        utils.write_text(tmp_path / "sample.txt", cast(Any, content))


def test_cli_utils_rejects_non_utf8_file_contents(tmp_path: Path) -> None:
    path = tmp_path / "sample.txt"
    path.write_bytes(b"\xff")

    with pytest.raises(ValueError, match="file must contain valid UTF-8 text"):
        utils.read_text(path)


@pytest.mark.parametrize("path", [False, 0, object()])
def test_cli_utils_reject_invalid_path_types(path: Any) -> None:
    with pytest.raises(TypeError, match="path must be a file path"):
        utils.read_text(cast(Any, path))

    with pytest.raises(TypeError, match="path must be a file path"):
        utils.write_text(cast(Any, path), "content")

    with pytest.raises(TypeError, match="path must be a file path"):
        utils.write_json(cast(Any, path), {"value": 1})

    with pytest.raises(TypeError, match="path must be a file path"):
        utils.parse_yara_file(cast(Any, path))


@pytest.mark.parametrize("path", ["", "   ", "\t"])
def test_cli_utils_reject_empty_path(path: str) -> None:
    with pytest.raises(ValueError, match="path must not be empty"):
        utils.read_text(path)

    with pytest.raises(ValueError, match="path must not be empty"):
        utils.write_text(path, "content")

    with pytest.raises(ValueError, match="path must not be empty"):
        utils.write_json(path, {"value": 1})

    with pytest.raises(ValueError, match="path must not be empty"):
        utils.parse_yara_file(path)


def test_cli_utils_reject_empty_pathlike_path() -> None:
    class EmptyPathLike:
        def __fspath__(self) -> str:
            return ""

    empty_path = EmptyPathLike()

    with pytest.raises(ValueError, match="path must not be empty"):
        utils.read_text(cast(Any, empty_path))

    with pytest.raises(ValueError, match="path must not be empty"):
        utils.write_text(cast(Any, empty_path), "content")

    with pytest.raises(ValueError, match="path must not be empty"):
        utils.write_json(cast(Any, empty_path), {"value": 1})

    with pytest.raises(ValueError, match="path must not be empty"):
        utils.parse_yara_file(cast(Any, empty_path))


def test_cli_utils_rejects_inaccessible_paths() -> None:
    path = "a" * 5000

    with pytest.raises(ValueError, match="path could not be accessed"):
        utils.read_text(path)

    with pytest.raises(ValueError, match="path could not be accessed"):
        utils.write_text(path, "content")

    with pytest.raises(ValueError, match="path could not be accessed"):
        utils.write_json(path, {"value": 1})

    with pytest.raises(ValueError, match="path could not be accessed"):
        utils.parse_yara_file(path)

    with pytest.raises(click.BadParameter, match="path could not be accessed"):
        utils._validate_output_path(path)


def test_cli_utils_reject_directory_paths(tmp_path: Path) -> None:
    directory = tmp_path / "dir"
    directory.mkdir()

    with pytest.raises(ValueError, match="path must not be a directory"):
        utils.read_text(directory)

    with pytest.raises(ValueError, match="path must not be a directory"):
        utils.write_text(directory, "content")

    with pytest.raises(ValueError, match="path must not be a directory"):
        utils.write_json(directory, {"value": 1})

    with pytest.raises(ValueError, match="path must not be a directory"):
        utils.parse_yara_file(directory)
