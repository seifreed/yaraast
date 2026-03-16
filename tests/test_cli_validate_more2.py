from __future__ import annotations

from pathlib import Path

import click
import pytest
from click.testing import CliRunner

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
def test_validate_cross_handles_rule_parse_and_test_file_read_errors(tmp_path: Path) -> None:
    runner = CliRunner()
    invalid_rule = tmp_path / "invalid_rule.yar"
    valid_rule = tmp_path / "valid_rule.yar"
    data_dir = tmp_path / "data_dir"

    _write(invalid_rule, "rule broken { condition: }")
    _write(
        valid_rule,
        """
rule ok {
    condition:
        true
}
""",
    )
    data_dir.mkdir()

    parse_error = runner.invoke(validate, ["cross", str(invalid_rule), str(data_dir)])
    assert parse_error.exit_code != 0
    assert "Error parsing rules" in parse_error.output

    read_error = runner.invoke(validate, ["cross", str(valid_rule), str(data_dir)])
    assert read_error.exit_code != 0
    assert "Error reading test file" in read_error.output


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
    assert result.exit_code != 0
    assert "Error reading test data" in result.output
