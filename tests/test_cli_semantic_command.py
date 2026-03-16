"""CLI tests for semantic validation command."""

from __future__ import annotations

from textwrap import dedent

from click.testing import CliRunner

from yaraast.cli.commands.semantic import semantic


def test_semantic_command_json_output(tmp_path) -> None:
    yara_code = """
    rule semantic_ok {
        strings:
            $a = "test"
        condition:
            $a
    }
    """
    yara_path = tmp_path / "ok.yar"
    yara_path.write_text(dedent(yara_code).strip() + "\n", encoding="utf-8")

    runner = CliRunner()
    result = runner.invoke(
        semantic,
        [str(yara_path), "--format", "json"],
    )
    assert result.exit_code == 0
    assert str(yara_path) in result.output


def test_semantic_command_no_files() -> None:
    runner = CliRunner()
    result = runner.invoke(semantic, [])
    assert result.exit_code == 1
    assert "No files provided" in result.output
