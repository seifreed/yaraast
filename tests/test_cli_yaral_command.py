"""CLI tests for YARA-L commands."""

from __future__ import annotations

import builtins
from collections.abc import Callable, Mapping
from pathlib import Path
from textwrap import dedent
from typing import NoReturn

import click
from click.testing import CliRunner, Result
import pytest

import yaraast.cli.commands.yaral as yaral_command
from yaraast.cli.commands.yaral import yaral


def _write_yaral(tmp_path: Path, name: str, content: str) -> str:
    path = tmp_path / name
    path.write_text(dedent(content).strip() + "\n", encoding="utf-8")
    return str(path)


def _assert_abort_preserves_cause(result: Result, cause: BaseException) -> None:
    exception = result.exception
    assert isinstance(exception, click.Abort)
    assert exception.__cause__ is cause


def _basic_yaral_rule() -> str:
    return """
    rule login_attempts {
        events:
            $e.metadata.event_type = "LOGIN"

        condition:
            #e > 1
    }
    """


def test_yaral_parse_validate_and_info(tmp_path: Path) -> None:
    yaral_code = """
    rule login_attempts {
        meta:
            author = "security"

        events:
            $e.metadata.event_type = "LOGIN"

        condition:
            #e > 1
    }
    """
    yaral_path = _write_yaral(tmp_path, "rule.yaral", yaral_code)

    runner = CliRunner()

    result = runner.invoke(
        yaral,
        ["parse", yaral_path, "--format", "json"],
    )
    assert result.exit_code == 0
    assert "Using standard YARA-L parser" in result.output
    assert "Successfully parsed 1 rules" in result.output

    result = runner.invoke(
        yaral,
        ["validate", yaral_path, "--json"],
    )
    assert result.exit_code == 0
    assert '"valid": true' in result.output

    result = runner.invoke(
        yaral,
        ["info", "--functions"],
    )
    assert result.exit_code == 0
    assert "Available Aggregation Functions" in result.output


def test_yaral_optimize_generate_compare(tmp_path: Path) -> None:
    yaral_code = """
    rule download_events {
        events:
            $e.metadata.event_type = "FILE_DOWNLOAD"

        condition:
            #e > 0
    }
    """
    yaral_path = _write_yaral(tmp_path, "download.yaral", yaral_code)

    runner = CliRunner()

    result = runner.invoke(
        yaral,
        ["optimize", yaral_path, "--dry-run"],
    )
    assert result.exit_code == 0
    assert "Optimization Preview" in result.output

    result = runner.invoke(
        yaral,
        ["generate", yaral_path, "--format"],
    )
    assert result.exit_code == 0
    assert "Successfully generated code" in result.output

    other_path = _write_yaral(tmp_path, "download2.yaral", yaral_code)
    result = runner.invoke(
        yaral,
        ["compare", yaral_path, other_path, "--semantic"],
    )
    assert result.exit_code == 0
    assert "semantically equivalent" in result.output


def test_yaral_parse_enhanced_writes_output(tmp_path: Path) -> None:
    yaral_code = """
    rule enhanced_parse {
        events:
            $e.metadata.event_type = "LOGIN"
        outcome:
            $count = count(metadata.event_type)
        condition:
            #e > 0
    }
    """
    yaral_path = _write_yaral(tmp_path, "enhanced.yaral", yaral_code)
    output_path = tmp_path / "ast.json"

    runner = CliRunner()
    result = runner.invoke(
        yaral,
        [
            "parse",
            yaral_path,
            "--enhanced",
            "--format",
            "json",
            "--output",
            str(output_path),
        ],
    )

    assert result.exit_code == 0
    assert "Using enhanced YARA-L parser" in result.output
    assert output_path.exists()
    assert "rules" in output_path.read_text(encoding="utf-8")


def test_yaral_parse_enhanced_rejects_recovered_parser_errors(tmp_path: Path) -> None:
    yaral_path = _write_yaral(
        tmp_path,
        "bad.yaral",
        "rule bad { events: $e.metadata.event_type = condition: $e }",
    )

    result = CliRunner().invoke(yaral, ["parse", yaral_path, "--enhanced"])

    assert result.exit_code != 0
    assert "YARA-L parse failed" in result.output
    assert "Successfully parsed 0 rules" not in result.output


def test_yaral_generate_rejects_recovered_parser_errors(tmp_path: Path) -> None:
    yaral_path = _write_yaral(
        tmp_path,
        "bad_generate.yaral",
        "rule bad { events: $e.metadata.event_type = condition: $e }",
    )

    result = CliRunner().invoke(yaral, ["generate", yaral_path])

    assert result.exit_code != 0
    assert "YARA-L parse failed" in result.output
    assert "Successfully generated code for 0 rules" not in result.output


@pytest.mark.parametrize(
    ("command_factory", "message"),
    [
        (lambda first, _second: ["parse", first], "Error parsing YARA-L file"),
        (lambda first, _second: ["validate", first], "Error validating YARA-L file"),
        (lambda first, _second: ["optimize", first], "Error optimizing YARA-L file"),
        (lambda first, _second: ["generate", first], "Error generating YARA-L code"),
        (lambda first, second: ["compare", first, second], "Error comparing YARA-L files"),
    ],
)
def test_yaral_commands_abort_preserves_original_cause(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    command_factory: Callable[[str, str], list[str]],
    message: str,
) -> None:
    first = _write_yaral(tmp_path, "first.yaral", _basic_yaral_rule())
    second = _write_yaral(tmp_path, "second.yaral", _basic_yaral_rule())
    sentinel = RuntimeError("yaral sentinel")

    def fail_parse_yaral(*_args: object, **_kwargs: object) -> NoReturn:
        raise sentinel

    monkeypatch.setattr(yaral_command, "parse_yaral", fail_parse_yaral)

    result = CliRunner().invoke(
        yaral,
        command_factory(first, second),
        standalone_mode=False,
    )

    assert result.exit_code != 0
    assert message in result.output
    assert "yaral sentinel" in result.output
    _assert_abort_preserves_cause(result, sentinel)


def test_yaral_parse_yaml_import_error_preserves_original_cause(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    source = _write_yaral(tmp_path, "rule.yaral", _basic_yaral_rule())
    original_import = builtins.__import__
    sentinel = ImportError("No module named yaml", name="yaml")

    def fail_yaml_import(
        name: str,
        globals_: Mapping[str, object] | None = None,
        locals_: Mapping[str, object] | None = None,
        fromlist: tuple[str, ...] = (),
        level: int = 0,
    ) -> object:
        if name == "yaml":
            raise sentinel
        return original_import(name, globals_, locals_, fromlist, level)

    monkeypatch.setattr(builtins, "__import__", fail_yaml_import)

    result = CliRunner().invoke(
        yaral,
        ["parse", source, "--format", "yaml"],
        standalone_mode=False,
    )

    assert result.exit_code != 0
    assert "Error parsing YARA-L file" in result.output
    _assert_abort_preserves_cause(result, sentinel)
