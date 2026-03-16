"""Additional CLI metrics tests (no mocks)."""

from __future__ import annotations

import json
from pathlib import Path

from click.testing import CliRunner

from yaraast.cli.main import cli


def _write_rule(tmp_path: Path) -> Path:
    rule_text = """
rule metrics_rule {
    strings:
        $a = "hello"
        $b = { 48 65 6C 6C 6F }
        $c = /te(s|x)t/
    condition:
        $a or $b or $c
}
"""
    rule_path = tmp_path / "metrics.yar"
    rule_path.write_text(rule_text.strip())
    return rule_path


def test_metrics_strings_json(tmp_path: Path) -> None:
    rule_path = _write_rule(tmp_path)
    runner = CliRunner()

    result = runner.invoke(cli, ["metrics", "strings", str(rule_path), "--format", "json"])

    assert result.exit_code == 0
    data = json.loads(result.output)
    assert data["total_strings"] == 3
    assert data["type_distribution"]["plain"] == 1
    assert data["type_distribution"]["hex"] == 1
    assert data["type_distribution"]["regex"] == 1


def test_metrics_tree_output(tmp_path: Path) -> None:
    rule_path = _write_rule(tmp_path)
    output = tmp_path / "tree.html"
    runner = CliRunner()

    result = runner.invoke(cli, ["metrics", "tree", str(rule_path), "--output", str(output)])

    assert result.exit_code == 0
    assert output.exists()


def test_metrics_patterns_text_fallback(tmp_path: Path) -> None:
    rule_path = _write_rule(tmp_path)
    runner = CliRunner()

    result = runner.invoke(
        cli,
        ["metrics", "patterns", str(rule_path), "--type", "flow", "--format", "dot", "--stats"],
    )

    assert result.exit_code == 0
