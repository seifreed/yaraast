"""Additional tests for CLI AST tools without mocks."""

from __future__ import annotations

from io import StringIO
from pathlib import Path
from typing import Any, cast

import pytest
from rich.console import Console

from yaraast.ast.base import YaraFile
from yaraast.ast.expressions import BooleanLiteral
from yaraast.ast.modifiers import MetaEntry
from yaraast.ast.rules import Import, Include, Rule, Tag
from yaraast.ast.strings import PlainString
from yaraast.cli.ast_tools import ASTFormatter, print_ast, visualize_ast
from yaraast.errors import ValidationError
from yaraast.shared.ast_analysis import ASTDiffer


def test_print_ast_and_visualize_formats() -> None:
    ast = YaraFile(
        imports=[Import(module="pe", alias="x")],
        includes=[Include(path="common.yar")],
        rules=[
            Rule(
                name="demo",
                modifiers=["private"],
                tags=[Tag(name="tag1")],
                meta=[MetaEntry.from_key_value("author", "me")],
                strings=[PlainString(identifier="$a", value="abc")],
                condition=BooleanLiteral(value=True),
            )
        ],
    )

    console = Console(file=StringIO(), record=True, force_terminal=False)
    print_ast(ast, console=console)
    rendered = console.export_text()
    assert "YaraFile" in rendered
    assert 'import "pe" as x' in rendered
    assert 'include "common.yar"' in rendered
    assert "rule demo" in rendered

    json_out = visualize_ast(ast, output_format="json")
    assert '"type": "YaraFile"' in json_out

    dict_out = visualize_ast(ast, output_format="dict")
    assert "YaraFile" in dict_out


def test_print_ast_includes_falsy_present_rule_condition() -> None:
    class FalsyBooleanLiteral(BooleanLiteral):
        def __bool__(self) -> bool:
            return False

    ast = YaraFile(rules=[Rule(name="falsy", condition=FalsyBooleanLiteral(value=False))])
    console = Console(file=StringIO(), record=True, force_terminal=False)

    print_ast(ast, console=console)

    rendered = console.export_text()
    assert "condition" in rendered
    assert "value=False" in rendered


def test_visualize_ast_invalid_format_raises() -> None:
    ast = YaraFile(rules=[Rule(name="x", condition=BooleanLiteral(value=True))])
    try:
        visualize_ast(ast, output_format="xml")
    except (ValueError, ValidationError) as exc:
        assert "Unsupported output format" in str(exc)
    else:
        raise AssertionError("Expected ValidationError")


@pytest.mark.parametrize("output_format", [None, 123, object()])
def test_visualize_ast_rejects_non_string_formats(output_format: Any) -> None:
    ast = YaraFile(rules=[Rule(name="x", condition=BooleanLiteral(value=True))])

    with pytest.raises(TypeError, match="output format must be a string"):
        visualize_ast(ast, output_format=cast(str, output_format))


def test_ast_formatter_output_and_errors(tmp_path: Path) -> None:
    good = tmp_path / "ok.yar"
    good.write_text('rule a { strings: $a = "x" condition: $a }', encoding="utf-8")

    formatter = ASTFormatter()
    out_path = tmp_path / "formatted.yar"
    ok, msg = formatter.format_file(good, output_path=out_path, style="compact")
    assert ok is True
    assert out_path.exists()
    assert "Formatted file written to" in msg

    bad = tmp_path / "bad.yar"
    bad.write_text("rule", encoding="utf-8")
    ok_bad, err = formatter.format_file(bad)
    assert ok_bad is False
    assert "Formatting error:" in err

    missing = tmp_path / "missing.yar"
    needs_fmt, issues = formatter.check_format(missing)
    assert needs_fmt is False
    assert issues and issues[0].startswith("Check error:")


def test_ast_formatter_rejects_empty_output_path(tmp_path: Path) -> None:
    good = tmp_path / "ok.yar"
    good.write_text("rule a { condition: true }", encoding="utf-8")

    ok, err = ASTFormatter().format_file(good, output_path="")

    assert ok is False
    assert err == "Formatting error: output_path must not be empty"


def test_ast_formatter_rejects_empty_pathlike_output_path(tmp_path: Path) -> None:
    class EmptyPathLike:
        def __fspath__(self) -> str:
            return ""

    good = tmp_path / "ok.yar"
    good.write_text("rule a { condition: true }", encoding="utf-8")

    ok, err = ASTFormatter().format_file(good, output_path=cast(Any, EmptyPathLike()))

    assert ok is False
    assert err == "Formatting error: output_path must not be empty"


def test_ast_formatter_rejects_empty_input_path() -> None:
    ok, err = ASTFormatter().format_file("")

    assert ok is False
    assert err == "Formatting error: input_path must not be empty"


@pytest.mark.parametrize("input_path", [False, 0, object(), b"ok.yar"])
def test_ast_formatter_rejects_invalid_input_path_types(input_path: Any) -> None:
    ok, err = ASTFormatter().format_file(cast(Any, input_path))

    assert ok is False
    assert err == "Formatting error: input_path must be a file path"


def test_ast_formatter_check_format_rejects_empty_file_path() -> None:
    needs_format, issues = ASTFormatter().check_format("")

    assert needs_format is False
    assert issues == ["Check error: file_path must not be empty"]


def test_ast_formatter_rejects_directory_output_path(tmp_path: Path) -> None:
    good = tmp_path / "ok.yar"
    good.write_text("rule a { condition: true }", encoding="utf-8")

    ok, err = ASTFormatter().format_file(good, output_path=tmp_path)

    assert ok is False
    assert err == "Formatting error: output_path must not be a directory"


@pytest.mark.parametrize("output_path", [False, 0, object()])
def test_ast_formatter_rejects_invalid_output_path_types(
    output_path: Any,
    tmp_path: Path,
) -> None:
    good = tmp_path / "ok.yar"
    good.write_text("rule a { condition: true }", encoding="utf-8")

    ok, err = ASTFormatter().format_file(good, output_path=cast(Any, output_path))

    assert ok is False
    assert err == "Formatting error: output_path must be a file path"


def test_ast_differ_rejects_empty_file_paths(tmp_path: Path) -> None:
    good = tmp_path / "ok.yar"
    good.write_text("rule a { condition: true }", encoding="utf-8")

    result = ASTDiffer().diff_files("", good)

    assert result.has_changes is True
    assert result.logical_changes == ["Error comparing files: file1_path must not be empty"]


@pytest.mark.parametrize("file_path", [False, 0, object(), b"ok.yar"])
def test_ast_differ_rejects_invalid_file_path_types(
    tmp_path: Path,
    file_path: Any,
) -> None:
    good = tmp_path / "ok.yar"
    good.write_text("rule a { condition: true }", encoding="utf-8")

    result = ASTDiffer().diff_files(cast(Any, file_path), good)

    assert result.has_changes is True
    assert result.logical_changes == ["Error comparing files: file1_path must be a file path"]


def test_ast_formatter_format_file_propagates_internal_generator_errors(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    good = tmp_path / "ok.yar"
    good.write_text("rule a { condition: true }", encoding="utf-8")
    formatter = ASTFormatter()

    def broken_generate(ast: YaraFile) -> str:
        raise AttributeError("generator state missing")

    monkeypatch.setattr(formatter.generator, "generate", broken_generate)

    with pytest.raises(AttributeError, match="generator state missing"):
        formatter.format_file(good, style="compact")


def test_ast_formatter_check_format_propagates_internal_printer_errors(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    good = tmp_path / "ok.yar"
    good.write_text("rule a { condition: true }", encoding="utf-8")
    formatter = ASTFormatter()

    def broken_pretty_print(ast: YaraFile) -> str:
        raise AttributeError("printer state missing")

    monkeypatch.setattr(formatter.pretty_printer, "pretty_print", broken_pretty_print)

    with pytest.raises(AttributeError, match="printer state missing"):
        formatter.check_format(good)
