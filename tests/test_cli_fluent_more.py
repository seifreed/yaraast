from __future__ import annotations

from pathlib import Path
from typing import NoReturn

import click
from click.testing import CliRunner, Result
import pytest

import yaraast.cli.commands.fluent as fluent_command
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


def test_fluent_commands_reject_invalid_output_paths(tmp_path: Path) -> None:
    runner = CliRunner()
    bad_output = tmp_path / "as_dir"
    bad_output.mkdir()

    for output, message in [
        ("", "path must not be empty"),
        (str(bad_output), "output path must not be a directory"),
    ]:
        for cmd in [
            ["examples", "--output", output],
            ["string-patterns", "--output", output],
            ["conditions", "--output", output],
            ["transformations", "--output", output],
            ["template", "broken_rule", "--output", output],
        ]:
            result = runner.invoke(fluent, cmd)
            assert result.exit_code == 2
            assert message in result.output
            assert "Error generating" not in result.output


def _assert_abort_preserves_cause(result: Result, cause: BaseException) -> None:
    exception = result.exception
    assert isinstance(exception, click.Abort)
    assert exception.__cause__ is cause


@pytest.mark.parametrize(
    ("command", "service_name", "error_fragment"),
    [
        (["examples"], "create_example_rules", "examples"),
        (["string-patterns"], "create_string_patterns_rule", "string patterns"),
        (["conditions"], "create_condition_demo_rules", "conditions"),
        (["transformations"], "create_transformation_rules", "transformations"),
        (["template", "sentinel_rule"], "create_template_rule", "template"),
    ],
)
def test_fluent_commands_abort_preserves_original_cause(
    command: list[str],
    service_name: str,
    error_fragment: str,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    sentinel = RuntimeError(f"{service_name} sentinel")

    def fail_service(*_args: object, **_kwargs: object) -> NoReturn:
        raise sentinel

    monkeypatch.setattr(fluent_command, service_name, fail_service)

    result = CliRunner().invoke(fluent, command, standalone_mode=False)

    assert result.exit_code != 0
    assert f"Error generating {error_fragment}" in result.output
    assert str(sentinel) in result.output
    _assert_abort_preserves_cause(result, sentinel)
