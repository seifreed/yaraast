"""Extra branch coverage for CLI visitors formatters/tree builder."""

from __future__ import annotations

from io import StringIO
from types import SimpleNamespace

import pytest
from rich.console import Console

from yaraast.ast.expressions import BinaryExpression, Identifier, IntegerLiteral
from yaraast.ast.strings import HexString
from yaraast.cli.visitors.formatters import (
    ConditionStringFormatter,
    DetailedNodeStringFormatter,
    ExpressionStringFormatter,
)
from yaraast.cli.visitors.tree_builder import ASTTreeBuilder


def _render(tree) -> str:
    console = Console(file=StringIO(), record=True, force_terminal=False)
    console.print(tree)
    return console.export_text()


def test_condition_formatter_additional_branches() -> None:
    fmt = ConditionStringFormatter()

    assert fmt._format_boolean_literal(SimpleNamespace(), 0) == "true"
    assert fmt._format_of_expression(SimpleNamespace(), 0) == "any of them"

    simple = SimpleNamespace(left=Identifier("a"), right=IntegerLiteral(1), operator="==")
    assert "==" in fmt._format_top_level_binary(simple, "==", 0)

    assert "and ..." in fmt._format_hash_condition(["x==1"] * 20, "and")
    assert "..." in fmt._format_hash_condition(["x==1"] * 30, "and")
    assert "..." in fmt._format_long_condition(["x"] * 10, "and")

    nested = fmt._format_nested_binary(SimpleNamespace(), "and", 1)
    assert nested == "... and ..."

    assert fmt._format_function_args(SimpleNamespace(), 0) == ""
    assert fmt._format_parentheses(SimpleNamespace(), 0) == "(...)"
    assert fmt._format_member_access(SimpleNamespace(), 0) == "obj.member"
    assert fmt._format_array_access(SimpleNamespace(), 0) == "arr[0]"

    parts: list[str] = []
    fmt._collect_binary_parts(SimpleNamespace(), "and", parts, 999)
    assert parts == ["..."]


def test_expression_and_detailed_formatter_additional_branches() -> None:
    expr = ExpressionStringFormatter()
    detailed = DetailedNodeStringFormatter()

    assert expr.format_expression(Identifier("x"), depth=10) == "..."
    assert expr.format_expression(SimpleNamespace()) == "<SimpleName>"

    of_no_set = SimpleNamespace(quantifier="all")
    assert expr._format_of_expression(of_no_set, 0) == "all of them"

    wildcard = SimpleNamespace(prefix="abc", __class__=SimpleNamespace(__name__="StringWildcard"))
    assert expr._format_string_wildcard(wildcard) == "($abc*)"
    assert expr._format_string_wildcard(SimpleNamespace()) == "($*)"

    assert expr._format_set_expression(SimpleNamespace(), 0) == "(...)"
    assert expr._format_string_offset(SimpleNamespace(string_id="$a"), 0) == "@$a"
    assert expr._format_for_expression(SimpleNamespace(), 0) == "for any i in ... : (...)"
    assert expr._format_member_access(SimpleNamespace(), 0) == "?.?"
    assert expr._format_range_expression(SimpleNamespace(), 0) == "(0.....)"

    assert detailed.format_node(None) == "..."
    assert detailed._format_function_args(SimpleNamespace(), 0) == ""
    assert (
        detailed._format_binary_expression(
            BinaryExpression(Identifier("a"), "and", Identifier("b")), 2
        )
        == "(...)"
    )
    assert detailed._format_parentheses(SimpleNamespace(), 0) == "(...)"
    assert detailed._format_member_access(SimpleNamespace(), 0) == "obj.member"


def test_tree_builder_additional_branches() -> None:
    builder = ASTTreeBuilder()

    with pytest.raises(AttributeError):
        _ = builder.foo

    fallback = builder.visit_unknown
    assert callable(fallback)
    assert _render(fallback(object())).strip() == ""

    class BrokenAccept:
        def accept(self, _visitor):
            raise RuntimeError("boom")

    rendered = _render(builder.visit(BrokenAccept()))
    assert rendered.strip() == ""

    preview_none = builder._get_string_preview(HexString(identifier="$h"), lambda x: x)
    assert preview_none == ""

    assert builder._truncate_at_boundary("abcdef", 3) == "abc..."

    ps = builder.visit_plain_string(SimpleNamespace(identifier="$a", value=123, modifiers=[]))
    assert "$a" in _render(ps)

    rs = builder.visit_regex_string(SimpleNamespace(identifier="$r", regex=123, modifiers=[]))
    assert "$r" in _render(rs)
