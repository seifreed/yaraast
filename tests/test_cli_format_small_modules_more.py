from __future__ import annotations

import runpy
import sys
from pathlib import Path

import pytest
from click.testing import CliRunner
from rich.console import Console

from yaraast.cli.commands.format_cmd import format_yara, validate_syntax
from yaraast.cli.format_reporting import (
    display_format_success,
    display_validation_error,
    display_validation_success,
)
from yaraast.cli.format_services import build_format_stats, format_ast
from yaraast.parser import Parser


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


def test_format_services_format_ast_and_stats() -> None:
    ast = Parser().parse(
        """
        import "pe"

        rule sample {
            condition:
                true
        }
        """
    )

    formatted = format_ast(ast)
    stats = build_format_stats(ast)

    assert 'import "pe"' in formatted
    assert "rule sample" in formatted
    assert stats == {"rules": 1, "imports": 1}


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


def test_format_command_reports_parse_error(tmp_path: Path) -> None:
    runner = CliRunner()
    input_file = tmp_path / "broken.yar"
    output_file = tmp_path / "out.yar"
    input_file.write_text("rule broken", encoding="utf-8")

    result = runner.invoke(format_yara, [str(input_file), str(output_file)])

    assert result.exit_code != 0
    assert "Error" in result.output or "Expected" in result.output
