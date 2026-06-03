"""Real tests for CLI optimize command (no mocks)."""

from __future__ import annotations

from pathlib import Path
from textwrap import dedent

from click.testing import CliRunner

from yaraast.cli.commands.optimize import optimize


def _write(tmp_path: Path, name: str, content: str) -> str:
    path = tmp_path / name
    path.write_text(dedent(content), encoding="utf-8")
    return str(path)


def test_cli_optimize_dry_run(tmp_path: Path) -> None:
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


def test_cli_optimize_analyze_and_write(tmp_path: Path) -> None:
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


def test_cli_optimize_warns_on_recovered_parse_errors(tmp_path: Path) -> None:
    # A rule whose condition section is empty is rejected by real YARA; the
    # error-tolerant parser recovers it with a placeholder condition, and the
    # command must surface that recovery instead of silently optimizing a
    # rule whose meaning was fabricated.
    infile = _write(
        tmp_path,
        "broken.yar",
        """
        rule broken {
            strings:
                $a = "abc"
            condition:
        }
        """,
    )
    outfile = tmp_path / "out.yar"
    result = CliRunner().invoke(optimize, [infile, str(outfile)])
    assert "Recovered from" in result.output
    assert "no condition" in result.output


def test_cli_optimize_does_not_warn_on_valid_input(tmp_path: Path) -> None:
    infile = _write(
        tmp_path,
        "ok.yar",
        """
        rule ok {
            strings:
                $a = "abc"
            condition:
                $a
        }
        """,
    )
    outfile = tmp_path / "out.yar"
    result = CliRunner().invoke(optimize, [infile, str(outfile)])
    assert "Recovered from" not in result.output
