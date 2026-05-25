"""Real tests for CLI validate command (no mocks)."""

from __future__ import annotations

from pathlib import Path
from textwrap import dedent

from click.testing import CliRunner

from yaraast.cli.commands.validate import validate


def _write(tmp_path: Path, name: str, content: str) -> str:
    path = tmp_path / name
    path.write_text(dedent(content), encoding="utf-8")
    return str(path)


def test_validate_default_file(tmp_path: Path) -> None:
    code = """
    rule ok {
        condition:
            true
    }
    """
    file_path = _write(tmp_path, "ok.yar", code)

    runner = CliRunner()
    result = runner.invoke(validate, [file_path])

    assert result.exit_code == 0
    assert "Valid YARA file" in result.output


def test_validate_parse_externals_and_roundtrip_skip_when_no_yara(tmp_path: Path) -> None:
    # _parse_externals handling of invalid format
    runner = CliRunner()
    dummy_rule = _write(tmp_path, "r.yar", "rule r { condition: true }")
    dummy_data = _write(tmp_path, "d.bin", "abc")
    result = runner.invoke(validate, ["cross", dummy_rule, dummy_data, "--external", "badformat"])
    assert result.exit_code != 0
    assert "Invalid external format" in result.output

    empty_key = runner.invoke(validate, ["cross", dummy_rule, dummy_data, "--external", "=value"])
    assert empty_key.exit_code != 0
    assert "External variable name cannot be empty" in empty_key.output

    blank_key = runner.invoke(
        validate, ["cross", dummy_rule, dummy_data, "--external", "   =value"]
    )
    assert blank_key.exit_code != 0
    assert "External variable name cannot be empty" in blank_key.output

    invalid_name = runner.invoke(
        validate, ["cross", dummy_rule, dummy_data, "--external", "bad-name=value"]
    )
    assert invalid_name.exit_code != 0
    assert "Invalid external variable name: bad-name" in invalid_name.output

    digit_name = runner.invoke(
        validate, ["cross", dummy_rule, dummy_data, "--external", "1bad=value"]
    )
    assert digit_name.exit_code != 0
    assert "Invalid external variable name: 1bad" in digit_name.output
