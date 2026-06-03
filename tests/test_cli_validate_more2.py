from __future__ import annotations

from pathlib import Path

import click
from click.testing import CliRunner
import pytest

from yaraast.cli.commands.validate import ValidateGroup, validate
from yaraast.libyara import YARA_AVAILABLE


def _write(path: Path, content: str) -> None:
    path.write_text(content.strip() + "\n", encoding="utf-8")


def test_validate_group_help_and_invalid_file_paths(tmp_path: Path) -> None:
    runner = CliRunner()
    invalid = tmp_path / "broken.yar"
    _write(invalid, "rule broken { condition: }")

    help_result = runner.invoke(validate, [])
    assert help_result.exit_code != 0
    assert "Usage:" in help_result.output

    invalid_result = runner.invoke(validate, [str(invalid)])
    assert invalid_result.exit_code != 0
    assert "Invalid YARA file" in invalid_result.output or "Error" in invalid_result.output


def test_validate_group_resolve_command_empty_args() -> None:
    ctx = click.Context(validate)

    try:
        validate.resolve_command(ctx, [])
    except IndexError:
        pass
    else:
        raise AssertionError("Expected Click to reject empty command arguments")

    assert isinstance(validate, ValidateGroup)


@pytest.mark.skipif(not YARA_AVAILABLE, reason="yara-python is not installed")
def test_validate_roundtrip_handles_test_data_read_error(tmp_path: Path) -> None:
    runner = CliRunner()
    rule = tmp_path / "rule.yar"
    data_dir = tmp_path / "data_dir"

    _write(
        rule,
        """
rule ok {
    condition:
        true
}
""",
    )
    data_dir.mkdir()

    result = runner.invoke(validate, ["roundtrip", str(rule), "-d", str(data_dir)])
    assert result.exit_code == 2
    assert "is a directory" in result.output
    assert "Error reading test data" not in result.output
