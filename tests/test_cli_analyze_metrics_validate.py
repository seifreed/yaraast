"""CLI tests for analyze/metrics/validate commands (no mocks)."""

from __future__ import annotations

import json
from pathlib import Path

from click.testing import CliRunner

from yaraast.cli.main import cli


def _write_rule(tmp_path: Path) -> Path:
    rule_text = """
rule test_rule {
    strings:
        $a = "abc"
    condition:
        $a
}
"""
    rule_path = tmp_path / "sample.yar"
    rule_path.write_text(rule_text.strip(), encoding="utf-8")
    return rule_path


def test_analyze_full_json(tmp_path: Path) -> None:
    rule_path = _write_rule(tmp_path)
    runner = CliRunner()

    result = runner.invoke(
        cli,
        ["analyze", "full", str(rule_path), "--format", "json"],
    )

    assert result.exit_code == 0
    payload = json.loads(result.output)
    assert "best_practices" in payload
    assert "optimization" in payload


def test_analyze_json_commands_reject_empty_output_path(tmp_path: Path) -> None:
    rule_path = _write_rule(tmp_path)
    runner = CliRunner()

    for command in ("full", "optimize"):
        result = runner.invoke(
            cli,
            ["analyze", command, str(rule_path), "--format", "json", "--output", ""],
        )

        assert result.exit_code == 2
        assert "path must not be empty" in result.output


def test_analyze_commands_reject_directory_rule_file(tmp_path: Path) -> None:
    input_dir = tmp_path / "rules"
    input_dir.mkdir()
    runner = CliRunner()

    commands = (
        ["analyze", "full", str(input_dir)],
        ["analyze", "best-practices", str(input_dir)],
        ["analyze", "optimize", str(input_dir)],
    )
    for command in commands:
        result = runner.invoke(cli, command)

        assert result.exit_code == 2
        assert "is a directory" in result.output
        assert "Errno" not in result.output


def test_analyze_best_practices(tmp_path: Path) -> None:
    rule_path = _write_rule(tmp_path)
    runner = CliRunner()

    result = runner.invoke(
        cli,
        ["analyze", "best-practices", str(rule_path), "--category", "style"],
    )

    assert result.exit_code == 0


def test_metrics_complexity_json(tmp_path: Path) -> None:
    rule_path = _write_rule(tmp_path)
    runner = CliRunner()

    result = runner.invoke(
        cli,
        ["metrics", "complexity", str(rule_path), "--format", "json"],
    )

    assert result.exit_code == 0
    output = result.output.strip()
    json_blob = output.split("\n\n", 1)[0]
    payload = json.loads(json_blob)
    assert "quality_score" in payload
    assert "quality_grade" in payload


def test_validate_file(tmp_path: Path) -> None:
    rule_path = _write_rule(tmp_path)
    runner = CliRunner()

    result = runner.invoke(cli, ["validate", str(rule_path)])

    assert result.exit_code == 0
    assert "Valid YARA file." in result.output
