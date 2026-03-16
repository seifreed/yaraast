from __future__ import annotations

from pathlib import Path

from click.testing import CliRunner

from yaraast.cli.commands.fluent import fluent


def test_fluent_commands_emit_real_output(tmp_path: Path) -> None:
    runner = CliRunner()

    examples = runner.invoke(fluent, ["examples"])
    assert examples.exit_code == 0
    assert "example_malware" in examples.output

    string_patterns = runner.invoke(fluent, ["string-patterns"])
    assert string_patterns.exit_code == 0
    assert "string_pattern_demo" in string_patterns.output

    conditions = runner.invoke(fluent, ["conditions"])
    assert conditions.exit_code == 0
    assert "condition_demo" in conditions.output

    transformations = runner.invoke(fluent, ["transformations"])
    assert transformations.exit_code == 0
    assert "variant_malware" in transformations.output or "base_malware" in transformations.output

    template = runner.invoke(
        fluent,
        [
            "template",
            "net_rule",
            "--type",
            "network",
            "--author",
            "tester",
            "--tags",
            "alpha, beta",
        ],
    )
    assert template.exit_code == 0
    assert "rule net_rule" in template.output
    assert "alpha" in template.output and "beta" in template.output


def test_fluent_commands_abort_on_real_output_write_error(tmp_path: Path) -> None:
    runner = CliRunner()
    bad_output = tmp_path / "as_dir"
    bad_output.mkdir()

    for cmd in [
        ["examples", "--output", str(bad_output)],
        ["string-patterns", "--output", str(bad_output)],
        ["conditions", "--output", str(bad_output)],
        ["transformations", "--output", str(bad_output)],
        ["template", "broken_rule", "--output", str(bad_output)],
    ]:
        result = runner.invoke(fluent, cmd)
        assert result.exit_code != 0
        assert "Error generating" in result.output
