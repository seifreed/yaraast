"""CLI tests for performance command module (no mocks)."""

from __future__ import annotations

from textwrap import dedent

from click.testing import CliRunner

from yaraast.cli.commands.performance import performance


def _write_rule(path) -> None:
    path.write_text(
        dedent(
            """
            rule perf_rule {
                condition:
                    true
            }
            """
        ).strip()
        + "\n",
        encoding="utf-8",
    )


def test_performance_batch_stream_parallel(tmp_path) -> None:
    rule_path = tmp_path / "rule.yar"
    _write_rule(rule_path)

    runner = CliRunner()

    batch_out = tmp_path / "batch_output"
    result = runner.invoke(
        performance,
        [
            "batch",
            str(rule_path),
            "--operations",
            "parse",
            "--output-dir",
            str(batch_out),
            "--batch-size",
            "1",
        ],
    )
    assert result.exit_code == 0
    assert (batch_out / "batch_results.json").exists()

    stream_out = tmp_path / "stream.json"
    result = runner.invoke(
        performance,
        [
            "stream",
            str(rule_path),
            "--output",
            str(stream_out),
            "--memory-limit",
            "64",
        ],
    )
    assert result.exit_code == 0
    assert stream_out.exists()

    parallel_out = tmp_path / "parallel"
    result = runner.invoke(
        performance,
        [
            "parallel",
            str(rule_path),
            "--output-dir",
            str(parallel_out),
            "--analysis-type",
            "complexity",
            "--chunk-size",
            "1",
        ],
    )
    assert result.exit_code == 0
    assert parallel_out.exists()
