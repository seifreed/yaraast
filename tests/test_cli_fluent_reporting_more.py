"""Additional tests for fluent reporting helpers."""

from __future__ import annotations

from pathlib import Path
from typing import Any

import pytest

from yaraast.cli import fluent_reporting as fr


def test_fluent_write_output_writes_file(
    tmp_path: Path,
    capsys: pytest.CaptureFixture[str],
) -> None:
    output = tmp_path / "rules.yar"

    fr.write_output(output, "rule x { condition: true }", "saved")

    assert output.read_text(encoding="utf-8") == "rule x { condition: true }"
    assert "saved" in capsys.readouterr().out


def test_fluent_write_output_prints_stdout(capsys: pytest.CaptureFixture[str]) -> None:
    fr.write_output(None, "inline", "ignored")

    assert "inline" in capsys.readouterr().out


def test_fluent_write_output_rejects_empty_output_path() -> None:
    with pytest.raises(ValueError, match="path must not be empty"):
        fr.write_output("", "code", "saved")


@pytest.mark.parametrize("output", [False, 0, object()])
def test_fluent_write_output_rejects_invalid_output_path_types(output: Any) -> None:
    with pytest.raises(TypeError, match="path must be a file path"):
        fr.write_output(output, "code", "saved")
