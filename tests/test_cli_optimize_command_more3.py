"""More tests for optimize CLI command (no mocks)."""

from __future__ import annotations

from pathlib import Path

from click.testing import CliRunner

from yaraast.cli.commands.optimize import optimize


def test_optimize_command_dry_run_with_analyze(tmp_path: Path) -> None:
    input_file = tmp_path / "input.yar"
    output_file = tmp_path / "output.yar"
    input_file.write_text(
        'rule a { strings: $a = "x" condition: $a }',
    )

    runner = CliRunner()
    result = runner.invoke(
        optimize,
        [str(input_file), str(output_file), "--dry-run", "--analyze"],
    )

    assert result.exit_code == 0
    assert "Dry run" in result.output
