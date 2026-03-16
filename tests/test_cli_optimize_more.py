"""Real tests for CLI optimize command (no mocks)."""

from __future__ import annotations

from textwrap import dedent

from click.testing import CliRunner

from yaraast.cli.commands.optimize import optimize


def _write(tmp_path, name: str, content: str) -> str:
    path = tmp_path / name
    path.write_text(dedent(content))
    return str(path)


def test_cli_optimize_dry_run(tmp_path) -> None:
    code = """
    rule opt {
        strings:
            $a = "abc"
        condition:
            $a
    }
    """
    infile = _write(tmp_path, "in.yar", code)
    outfile = tmp_path / "out.yar"

    runner = CliRunner()
    result = runner.invoke(optimize, [infile, str(outfile), "--dry-run"])

    assert result.exit_code == 0
    assert not outfile.exists()
    assert "Dry run" in result.output


def test_cli_optimize_analyze_and_write(tmp_path) -> None:
    code = """
    rule opt2 {
        strings:
            $a = "abc"
        condition:
            $a
    }
    """
    infile = _write(tmp_path, "in2.yar", code)
    outfile = tmp_path / "out2.yar"

    runner = CliRunner()
    result = runner.invoke(optimize, [infile, str(outfile), "--analyze"])

    assert result.exit_code == 0
    assert outfile.exists()
    assert "Performance analysis" in result.output
