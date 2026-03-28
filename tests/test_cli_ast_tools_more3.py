"""Additional tests for CLI AST tools without mocks."""

from __future__ import annotations

from io import StringIO

from rich.console import Console

from yaraast.ast.base import YaraFile
from yaraast.ast.expressions import BooleanLiteral
from yaraast.ast.modifiers import MetaEntry
from yaraast.ast.rules import Import, Include, Rule, Tag
from yaraast.ast.strings import PlainString
from yaraast.cli.ast_tools import ASTFormatter, print_ast, visualize_ast
from yaraast.errors import ValidationError


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


def test_visualize_ast_invalid_format_raises() -> None:
    ast = YaraFile(rules=[Rule(name="x", condition=BooleanLiteral(value=True))])
    try:
        visualize_ast(ast, output_format="xml")
    except (ValueError, ValidationError) as exc:
        assert "Unsupported output format" in str(exc)
    else:
        raise AssertionError("Expected ValidationError")


def test_ast_formatter_output_and_errors(tmp_path) -> None:
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
