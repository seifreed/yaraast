"""CLI tests for analyze/optimize/performance-check commands."""

from __future__ import annotations

from pathlib import Path

from click.testing import CliRunner

from yaraast.cli.commands.analyze import analyze
from yaraast.cli.commands.optimize import optimize
from yaraast.cli.commands.performance_check import performance_check


def _sample_rule() -> str:
    return """
rule sample_perf {
    strings:
        $a = "abc"
        $b = /test.*/
    condition:
        any of them
}
"""


def test_analyze_full_and_best_practices(tmp_path: Path) -> None:
    runner = CliRunner()
    yara_path = tmp_path / "sample.yar"
    yara_path.write_text(_sample_rule())

    result = runner.invoke(analyze, ["full", str(yara_path), "-f", "json"])
    assert result.exit_code == 0

    result = runner.invoke(
        analyze,
        ["best-practices", str(yara_path), "-c", "all"],
    )
    assert result.exit_code in (0, 1)


def test_optimize_dry_run(tmp_path: Path) -> None:
    runner = CliRunner()
    yara_path = tmp_path / "sample.yar"
    yara_path.write_text(_sample_rule())

    out_path = tmp_path / "optimized.yar"
    result = runner.invoke(
        optimize,
        [str(yara_path), str(out_path), "--dry-run"],
    )
    assert result.exit_code == 0


def test_performance_check_summary(tmp_path: Path) -> None:
    runner = CliRunner()
    yara_path = tmp_path / "sample.yar"
    yara_path.write_text(_sample_rule())

    result = runner.invoke(
        performance_check,
        [str(yara_path), "--summary"],
    )
    assert result.exit_code == 0
