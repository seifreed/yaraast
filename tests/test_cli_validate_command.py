"""CLI tests for validate command."""

from __future__ import annotations

from pathlib import Path

from click.testing import CliRunner

from yaraast.cli.commands.validate import validate


def _sample_rule() -> str:
    return """
rule sample_validate {
    strings:
        $a = "abc"
    condition:
        $a
}
"""


def test_validate_default_file(tmp_path: Path) -> None:
    runner = CliRunner()
    yara_path = tmp_path / "sample.yar"
    yara_path.write_text(_sample_rule(), encoding="utf-8")

    result = runner.invoke(validate, [str(yara_path)])
    assert result.exit_code == 0
