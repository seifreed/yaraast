from __future__ import annotations

from collections.abc import Callable
from pathlib import Path
from typing import NoReturn

import click
from click.testing import CliRunner, Result
import pytest

import yaraast.cli.commands.parse_cmd as parse_command
from yaraast.cli.commands.parse_cmd import parse


def _write(path: Path, content: str) -> None:
    path.write_text(content.strip() + "\n", encoding="utf-8")


def _assert_abort_preserves_cause(result: Result, cause: BaseException) -> None:
    exception = result.exception
    assert isinstance(exception, click.Abort)
    assert exception.__cause__ is cause


def test_parse_cmd_writes_tree_output_and_handles_output_error(tmp_path: Path) -> None:
    runner = CliRunner()
    source = tmp_path / "ok.yar"
    output_dir = tmp_path / "out_dir"
    output_dir.mkdir()

    _write(
        source,
        """
rule ok {
    condition:
        true
}
""",
    )

    tree_result = runner.invoke(parse, [str(source), "--format", "tree"])
    assert tree_result.exit_code == 0
    assert "ok" in tree_result.output

    error_result = runner.invoke(
        parse, [str(source), "--format", "json", "--output", str(output_dir)]
    )
    assert error_result.exit_code == 2
    assert "output path must not be a directory" in error_result.output

    for output_format in ("yara", "json", "yaml", "tree"):
        empty_output = runner.invoke(
            parse, [str(source), "--format", output_format, "--output", ""]
        )
        assert empty_output.exit_code == 2
        assert "path must not be empty" in empty_output.output
        assert "Rule: ok" not in empty_output.output


def test_parse_cmd_rejects_directory_input(tmp_path: Path) -> None:
    runner = CliRunner()
    input_dir = tmp_path / "rules"
    input_dir.mkdir()

    result = runner.invoke(parse, [str(input_dir)])

    assert result.exit_code == 2
    assert "is a directory" in result.output
    assert "Errno" not in result.output


def test_parse_cmd_auto_yarax_outputs_extended_syntax(tmp_path: Path) -> None:
    runner = CliRunner()
    source = tmp_path / "yarax.yar"

    _write(
        source,
        """
rule yarax_sample {
    condition:
        with xs = [1]: match xs { _ => true }
}
""",
    )

    yara_result = runner.invoke(parse, [str(source), "--dialect", "auto"])
    assert yara_result.exit_code == 0
    assert "Detected dialect: YARA_X" in yara_result.output
    assert "with xs = [1]" in yara_result.output
    assert "match xs" in yara_result.output

    json_result = runner.invoke(parse, [str(source), "--dialect", "yara-x", "--format", "json"])
    assert json_result.exit_code == 0
    assert '"type": "WithStatement"' in json_result.output


def test_parse_cmd_tree_preserves_selective_extern_import_details(tmp_path: Path) -> None:
    runner = CliRunner()
    source = tmp_path / "extern_import.yar"

    _write(
        source,
        """
import "external.rules" (A, B) as er

rule uses_external {
    condition:
        er.A
}
""",
    )

    result = runner.invoke(parse, [str(source), "--format", "tree"])

    assert result.exit_code == 0
    assert "extern import external.rules (A, B) as er" in result.output


def test_parse_cmd_tree_preserves_extern_rule_details(tmp_path: Path) -> None:
    runner = CliRunner()
    source = tmp_path / "extern_rule.yar"

    _write(
        source,
        """
namespace corp
extern rule private corp.Nested

rule uses_external {
    condition:
        corp.Nested
}
""",
    )

    result = runner.invoke(parse, [str(source), "--format", "tree"])

    assert result.exit_code == 0
    assert "extern rule private corp.Nested" in result.output


def test_parse_cmd_tree_preserves_pragma_details(tmp_path: Path) -> None:
    runner = CliRunner()
    source = tmp_path / "pragmas.yar"

    _write(
        source,
        """
#define FOO 1
#pragma optimize fast
#ifdef FOO
rule guarded {
    condition:
        true
}
#endif
""",
    )

    result = runner.invoke(parse, [str(source), "--format", "tree"])

    assert result.exit_code == 0
    assert "#define FOO 1" in result.output
    assert "#pragma optimize fast" in result.output
    assert "#ifdef FOO" in result.output


def test_parse_cmd_json_reports_parse_errors_on_stderr(tmp_path: Path) -> None:
    runner = CliRunner()
    source = tmp_path / "broken.yar"
    source.write_text("rule broken { strings: $a =\n", encoding="utf-8")

    result = runner.invoke(parse, [str(source), "--format", "json"])

    assert result.exit_code == 1
    assert "Parser Issues" in result.stderr
    assert 'rule "broken" has no condition' in result.stderr


def test_parse_cmd_abort_preserves_original_cause(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    source = tmp_path / "ok.yar"
    _write(source, "rule ok { condition: true }")
    sentinel = RuntimeError("parse sentinel")

    def fail_parse_content(
        _content: str,
        _dialect: str,
        _show_status: bool,
        _status_callback: Callable[[str], None],
    ) -> NoReturn:
        raise sentinel

    monkeypatch.setattr(parse_command, "parse_content_by_dialect", fail_parse_content)

    result = CliRunner().invoke(parse, [str(source)], standalone_mode=False)

    assert result.exit_code != 0
    assert "parse sentinel" in result.output
    _assert_abort_preserves_cause(result, sentinel)
