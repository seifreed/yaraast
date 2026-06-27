from __future__ import annotations

from pathlib import Path
import runpy
import sys
from typing import NoReturn

import click
from click.testing import CliRunner, Result
import pytest
from rich.console import Console

import yaraast.cli.commands.format_cmd as format_command
from yaraast.cli.commands.format_cmd import format_yara, validate_syntax
from yaraast.cli.format_reporting import (
    display_format_success,
    display_validation_error,
    display_validation_success,
)
from yaraast.cli.format_services import build_format_stats, format_ast
from yaraast.parser import Parser
from yaraast.parser.source import parse_yara_source


def _yarax_rule() -> str:
    return "rule x { condition: with xs = [1]: match xs { _ => true } }"


def _assert_abort_preserves_cause(result: Result, cause: BaseException) -> None:
    exception = result.exception
    assert isinstance(exception, click.Abort)
    assert exception.__cause__ is cause


def test_package_main_module_runs_without_error() -> None:
    namespace = runpy.run_module("yaraast.__main__", run_name="not_main")
    assert callable(namespace["main"])
    original_argv = sys.argv[:]
    try:
        sys.argv = ["yaraast", "--help"]
        with pytest.raises(SystemExit) as exc:
            namespace["main"]()
        assert exc.value.code == 0
    finally:
        sys.argv = original_argv


def test_format_reporting_helpers_render_messages() -> None:
    console = Console(record=True, width=120)

    display_format_success(console, "out.yar")
    display_validation_success(console, "sample.yar", {"rules": 2, "imports": 1})
    display_validation_error(console, "broken.yar", ValueError("bad syntax"))

    output = console.export_text()
    assert "Formatted YARA file written to out.yar" in output
    assert "Valid YARA file" in output
    assert "sample.yar" in output
    assert "Invalid YARA file" in output
    assert "bad syntax" in output


def test_format_reporting_escapes_markup_in_dynamic_values() -> None:
    console = Console(record=True, width=120)
    bad = "bad[/red][broken"

    display_format_success(console, bad)
    display_validation_error(console, "broken.yar", ValueError(bad))

    output = console.export_text()
    assert bad in output


def test_format_reporting_handles_null_byte_input_file_names() -> None:
    console = Console(record=True, width=120)

    display_validation_success(console, "bad\x00name.yar", {"rules": 1, "imports": 0})
    display_validation_error(console, "bad\x00name.yar", ValueError("broken"))

    output = console.export_text()
    assert "bad\x00name.yar" in output


def test_format_services_format_ast_and_stats() -> None:
    ast = Parser().parse("""
        import "pe"

        rule sample {
            condition:
                true
        }
        """)

    formatted = format_ast(ast)
    stats = build_format_stats(ast)

    assert 'import "pe"' in formatted
    assert "rule sample" in formatted
    assert stats == {"rules": 1, "imports": 1}


def test_format_services_and_command_accept_yarax(tmp_path: Path) -> None:
    ast = Parser().parse("rule classic { condition: true }")
    yarax_ast = parse_yara_source(_yarax_rule())

    assert "rule classic" in format_ast(ast)
    assert "with xs = [1]" in format_ast(yarax_ast)

    runner = CliRunner()
    input_file = tmp_path / "x.yar"
    output_file = tmp_path / "out.yar"
    input_file.write_text(_yarax_rule(), encoding="utf-8")

    validate_result = runner.invoke(validate_syntax, [str(input_file)])
    format_result = runner.invoke(format_yara, [str(input_file), str(output_file)])

    assert validate_result.exit_code == 0
    assert "Valid YARA file" in validate_result.output
    assert format_result.exit_code == 0
    assert "match xs" in output_file.read_text(encoding="utf-8")


def test_format_command_validate_syntax_success_and_error(tmp_path: Path) -> None:
    runner = CliRunner()

    valid = tmp_path / "valid.yar"
    valid.write_text("rule ok { condition: true }", encoding="utf-8")
    success = runner.invoke(validate_syntax, [str(valid)])
    assert success.exit_code == 0
    assert "Valid YARA file" in success.output

    invalid = tmp_path / "invalid.yar"
    invalid.write_text("rule broken", encoding="utf-8")
    failure = runner.invoke(validate_syntax, [str(invalid)])
    assert failure.exit_code != 0
    assert "Invalid YARA file" in failure.output


def test_format_command_writes_output_file(tmp_path: Path) -> None:
    runner = CliRunner()
    input_file = tmp_path / "input.yar"
    output_file = tmp_path / "output.yar"
    input_file.write_text('rule fmt { strings: $a = "x" condition: $a }', encoding="utf-8")

    result = runner.invoke(format_yara, [str(input_file), str(output_file)])

    assert result.exit_code == 0
    assert output_file.exists()
    assert "Formatted YARA file written" in result.output
    assert "rule fmt" in output_file.read_text(encoding="utf-8")


def test_format_command_rejects_empty_output_file(tmp_path: Path) -> None:
    runner = CliRunner()
    input_file = tmp_path / "input.yar"
    input_file.write_text("rule fmt { condition: true }", encoding="utf-8")

    result = runner.invoke(format_yara, [str(input_file), ""])

    assert result.exit_code == 2
    assert "path must not be empty" in result.output
    assert "Is a directory" not in result.output
    assert "Formatted YARA file written" not in result.output


def test_format_command_rejects_inaccessible_output_file(tmp_path: Path) -> None:
    runner = CliRunner()
    input_file = tmp_path / "input.yar"
    input_file.write_text("rule fmt { condition: true }", encoding="utf-8")

    result = runner.invoke(format_yara, [str(input_file), "a" * 5000])

    assert result.exit_code == 2
    assert "path could not be accessed" in result.output
    assert "Errno" not in result.output
    assert "Formatted YARA file written" not in result.output


def test_format_commands_reject_directory_input(tmp_path: Path) -> None:
    runner = CliRunner()
    input_dir = tmp_path / "rules"
    input_dir.mkdir()
    output_file = tmp_path / "output.yar"

    format_result = runner.invoke(format_yara, [str(input_dir), str(output_file)])
    assert format_result.exit_code == 2
    assert "is a directory" in format_result.output
    assert "Errno" not in format_result.output
    assert not output_file.exists()

    validate_result = runner.invoke(validate_syntax, [str(input_dir)])
    assert validate_result.exit_code == 2
    assert "is a directory" in validate_result.output
    assert "Invalid YARA file" not in validate_result.output


def test_format_command_abort_preserves_original_cause(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    input_file = tmp_path / "input.yar"
    output_file = tmp_path / "output.yar"
    input_file.write_text("rule fmt { condition: true }", encoding="utf-8")
    sentinel = RuntimeError("format sentinel")

    def fail_parse(_source: str) -> NoReturn:
        raise sentinel

    monkeypatch.setattr(format_command, "parse_yara_source_with_comments", fail_parse)

    result = CliRunner().invoke(
        format_yara,
        [str(input_file), str(output_file)],
        standalone_mode=False,
    )

    assert result.exit_code != 0
    assert "format sentinel" in result.output
    assert not output_file.exists()
    _assert_abort_preserves_cause(result, sentinel)


def test_validate_syntax_abort_preserves_original_cause(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    input_file = tmp_path / "input.yar"
    input_file.write_text("rule fmt { condition: true }", encoding="utf-8")
    sentinel = RuntimeError("validate sentinel")

    def fail_parse(_source: str) -> NoReturn:
        raise sentinel

    monkeypatch.setattr(format_command, "parse_yara_source_with_comments", fail_parse)

    result = CliRunner().invoke(
        validate_syntax,
        [str(input_file)],
        standalone_mode=False,
    )

    assert result.exit_code != 0
    assert "Invalid YARA file" in result.output
    assert "validate sentinel" in result.output
    _assert_abort_preserves_cause(result, sentinel)


def test_format_command_reports_parse_error(tmp_path: Path) -> None:
    runner = CliRunner()
    input_file = tmp_path / "broken.yar"
    output_file = tmp_path / "out.yar"
    input_file.write_text("rule broken", encoding="utf-8")

    result = runner.invoke(format_yara, [str(input_file), str(output_file)])

    assert result.exit_code != 0
    assert "Error" in result.output or "Expected" in result.output


def test_format_commands_reject_invalid_utf8(tmp_path: Path) -> None:
    runner = CliRunner()
    input_file = tmp_path / "bad_utf8.yar"
    output_file = tmp_path / "out.yar"
    input_file.write_bytes(b"\xff")

    format_result = runner.invoke(format_yara, [str(input_file), str(output_file)])
    validate_result = runner.invoke(validate_syntax, [str(input_file)])

    assert format_result.exit_code != 0
    assert "file must contain valid UTF-8 text" in format_result.output
    assert "codec can't decode" not in format_result.output
    assert not output_file.exists()
    assert validate_result.exit_code != 0
    assert "file must contain valid UTF-8 text" in validate_result.output
    assert "codec can't decode" not in validate_result.output
