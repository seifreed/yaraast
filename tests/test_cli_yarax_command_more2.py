"""Additional CLI tests for YARA-X command group."""

from __future__ import annotations

from textwrap import dedent

from click.testing import CliRunner

from yaraast.cli.commands.yarax import yarax


def _write(tmp_path, name: str, content: str) -> str:
    path = tmp_path / name
    path.write_text(dedent(content), encoding="utf-8")
    return str(path)


def test_yarax_check_reports_real_compatibility_issues(tmp_path) -> None:
    file_path = _write(
        tmp_path,
        "incompatible.yar",
        """
        rule regex_test {
            strings:
                $a = /abc{/
            condition:
                $a
        }
        """,
    )
    runner = CliRunner()

    result = runner.invoke(yarax, ["check", file_path, "--strict", "--fix"])

    assert result.exit_code == 0
    assert "Errors:" in result.output or "Warnings:" in result.output
    assert "Unescaped '{'" in result.output or "Escape the brace" in result.output
