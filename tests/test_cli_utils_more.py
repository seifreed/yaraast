"""Additional tests for shared CLI utilities."""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any, cast

import pytest

from yaraast.cli import utils


def test_cli_utils_read_write_text_and_json(tmp_path: Path) -> None:
    text_path = tmp_path / "sample.txt"
    json_path = tmp_path / "sample.json"

    utils.write_text(text_path, "hello")
    utils.write_json(json_path, {"value": 1})

    assert utils.read_text(text_path) == "hello"
    assert json.loads(utils.read_text(json_path)) == {"value": 1}


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


def test_cli_utils_reject_empty_path() -> None:
    with pytest.raises(ValueError, match="path must not be empty"):
        utils.read_text("")

    with pytest.raises(ValueError, match="path must not be empty"):
        utils.write_text("", "content")

    with pytest.raises(ValueError, match="path must not be empty"):
        utils.write_json("", {"value": 1})

    with pytest.raises(ValueError, match="path must not be empty"):
        utils.parse_yara_file("")
