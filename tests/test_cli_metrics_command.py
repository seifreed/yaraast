"""CLI tests for metrics commands."""

from __future__ import annotations

from pathlib import Path

from click.testing import CliRunner

from yaraast.cli.commands.metrics import metrics


def _sample_rule() -> str:
    return """
import "pe"

rule sample_cli_metrics {
    meta:
        author = "unit"
    strings:
        $a = "abc"
    condition:
        $a and pe.number_of_sections > 0
}
"""


def test_metrics_complexity_json(tmp_path: Path) -> None:
    runner = CliRunner()
    yara_path = tmp_path / "sample.yar"
    yara_path.write_text(_sample_rule())

    result = runner.invoke(
        metrics,
        ["complexity", str(yara_path), "-f", "json"],
    )
    assert result.exit_code == 0
    assert "quality_score" in result.output


def test_metrics_complexity_text_output_file(tmp_path: Path) -> None:
    runner = CliRunner()
    yara_path = tmp_path / "sample.yar"
    output_path = tmp_path / "metrics.txt"
    yara_path.write_text(_sample_rule())

    result = runner.invoke(
        metrics,
        ["complexity", str(yara_path), "-f", "text", "-o", str(output_path)],
    )
    assert result.exit_code == 0
    assert output_path.exists()


def test_metrics_graph_dot(tmp_path: Path) -> None:
    runner = CliRunner()
    yara_path = tmp_path / "sample.yar"
    yara_path.write_text(_sample_rule())

    output_path = tmp_path / "graph.dot"
    result = runner.invoke(
        metrics,
        [
            "graph",
            str(yara_path),
            "-o",
            str(output_path),
            "-f",
            "dot",
            "-t",
            "rules",
            "--engine",
            "dot",
        ],
    )
    assert result.exit_code == 0
    assert output_path.exists()
