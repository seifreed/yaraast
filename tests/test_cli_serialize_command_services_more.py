"""Additional tests for command-level serialization helpers."""

from __future__ import annotations

from pathlib import Path
from typing import Any, cast

import pytest

from yaraast.cli.serialize_command_services import build_diff_output_path


def test_build_diff_output_path_uses_default_when_output_is_none() -> None:
    assert build_diff_output_path("old_rules.yar", "new_rules.yar", None, "json") == (
        "diff_old_rules_to_new_rules.json"
    )


def test_build_diff_output_path_uses_explicit_output(tmp_path: Path) -> None:
    output = tmp_path / "diff.json"

    assert build_diff_output_path("old.yar", "new.yar", output, "json") == str(output)
    assert build_diff_output_path("old.yar", "new.yar", "custom.yaml", "yaml") == "custom.yaml"


@pytest.mark.parametrize("output", ["", "   ", "\t"])
def test_build_diff_output_path_rejects_empty_output_path(output: str) -> None:
    with pytest.raises(ValueError, match="output path must not be empty"):
        build_diff_output_path("old.yar", "new.yar", output, "json")


def test_build_diff_output_path_rejects_empty_pathlike_output_path() -> None:
    class EmptyPathLike:
        def __fspath__(self) -> str:
            return ""

    with pytest.raises(ValueError, match="output path must not be empty"):
        build_diff_output_path("old.yar", "new.yar", cast(Any, EmptyPathLike()), "json")


def test_build_diff_output_path_rejects_directory_output_path(tmp_path: Path) -> None:
    output_dir = tmp_path / "output"
    output_dir.mkdir()

    with pytest.raises(ValueError, match="output path must not be a directory"):
        build_diff_output_path("old.yar", "new.yar", output_dir, "json")


@pytest.mark.parametrize("output", [False, 0, object()])
def test_build_diff_output_path_rejects_invalid_output_path_types(output: Any) -> None:
    with pytest.raises(TypeError, match="output path must be a file path"):
        build_diff_output_path("old.yar", "new.yar", output, "json")
