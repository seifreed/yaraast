"""More tests for fluent CLI command (no mocks)."""

from __future__ import annotations

from pathlib import Path

from click.testing import CliRunner

from yaraast.cli.commands.fluent import fluent


def test_fluent_examples_command_writes_file(tmp_path: Path) -> None:
    runner = CliRunner()
    output = tmp_path / "examples.yar"
    result = runner.invoke(fluent, ["examples", "--output", str(output)])

    assert result.exit_code == 0
    assert output.exists()
    content = output.read_text()
    assert "rule example_malware" in content


def test_fluent_string_patterns_command_writes_file(tmp_path: Path) -> None:
    runner = CliRunner()
    output = tmp_path / "strings.yar"
    result = runner.invoke(fluent, ["string-patterns", "--output", str(output)])

    assert result.exit_code == 0
    content = output.read_text()
    assert "rule string_pattern_demo" in content
    assert "$mz" in content


def test_fluent_template_command_network(tmp_path: Path) -> None:
    runner = CliRunner()
    output = tmp_path / "template.yar"
    result = runner.invoke(
        fluent,
        [
            "template",
            "net_rule",
            "--type",
            "network",
            "--author",
            "Unit Test",
            "--tags",
            "demo,net",
            "--output",
            str(output),
        ],
    )

    assert result.exit_code == 0
    content = output.read_text()
    assert "rule net_rule" in content
    assert "Unit Test" in content
