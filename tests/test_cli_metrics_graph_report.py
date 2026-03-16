"""CLI metrics graph/report tests (real, no mocks)."""

from __future__ import annotations

import json
from pathlib import Path

from click.testing import CliRunner

from yaraast.cli.main import cli


def _write_rule(tmp_path: Path) -> Path:
    rule_text = """
import "pe"

rule graph_rule {
    strings:
        $a = "hello"
        $b = /te(s|x)t/
    condition:
        $a or $b or pe.number_of_sections > 0
}
"""
    rule_path = tmp_path / "graph_metrics.yar"
    rule_path.write_text(rule_text.strip())
    return rule_path


def test_metrics_complexity_json_and_quality_gate(tmp_path: Path) -> None:
    rule_path = _write_rule(tmp_path)
    output = tmp_path / "complexity.json"
    runner = CliRunner()

    result = runner.invoke(
        cli,
        [
            "metrics",
            "complexity",
            str(rule_path),
            "--format",
            "json",
            "--output",
            str(output),
            "--quality-gate",
            "99",
        ],
    )

    assert result.exit_code == 0
    assert output.exists()
    data = json.loads(output.read_text(encoding="utf-8"))
    assert "quality_score" in data
    assert "quality_grade" in data
    assert "total_rules" in data.get("file_metrics", {})


def test_metrics_graph_generates_output(tmp_path: Path) -> None:
    rule_path = _write_rule(tmp_path)
    output = tmp_path / "dep.dot"
    runner = CliRunner()

    result = runner.invoke(
        cli,
        [
            "metrics",
            "graph",
            str(rule_path),
            "--type",
            "full",
            "--format",
            "dot",
            "--output",
            str(output),
        ],
    )

    assert result.exit_code == 0
    assert output.exists()
    assert "Dependency graph generated" in result.output


def test_metrics_graph_complexity_type(tmp_path: Path) -> None:
    rule_path = _write_rule(tmp_path)
    output = tmp_path / "complexity.dot"
    runner = CliRunner()

    result = runner.invoke(
        cli,
        [
            "metrics",
            "graph",
            str(rule_path),
            "--type",
            "complexity",
            "--format",
            "dot",
            "--output",
            str(output),
        ],
    )

    assert result.exit_code == 0
    assert output.exists()


def test_metrics_report_generates_files(tmp_path: Path) -> None:
    rule_path = _write_rule(tmp_path)
    output_dir = tmp_path / "report"
    runner = CliRunner()

    result = runner.invoke(
        cli,
        ["metrics", "report", str(rule_path), "--output-dir", str(output_dir), "--format", "svg"],
    )

    assert result.exit_code == 0
    assert output_dir.exists()
    assert (output_dir / "graph_metrics_complexity.json").exists()
    assert (output_dir / "graph_metrics_tree.html").exists()
