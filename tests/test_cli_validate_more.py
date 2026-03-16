"""Real tests for CLI validate command (no mocks)."""

from __future__ import annotations

from textwrap import dedent

from click.testing import CliRunner

from yaraast.cli.commands.validate import validate


def _write(tmp_path, name: str, content: str) -> str:
    path = tmp_path / name
    path.write_text(dedent(content))
    return str(path)


def test_validate_default_file(tmp_path) -> None:
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


def test_validate_parse_externals_and_roundtrip_skip_when_no_yara(tmp_path) -> None:
    # _parse_externals handling of invalid format
    runner = CliRunner()
    dummy_rule = _write(tmp_path, "r.yar", "rule r { condition: true }")
    dummy_data = _write(tmp_path, "d.bin", "abc")
    result = runner.invoke(validate, ["cross", dummy_rule, dummy_data, "--external", "badformat"])
    assert result.exit_code != 0
    assert "Invalid external format" in result.output
