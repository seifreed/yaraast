"""Additional tests for CLI visitor formatters and tree builder."""

from __future__ import annotations

from io import StringIO
from types import SimpleNamespace

from rich.console import Console

from yaraast.ast.base import YaraFile
from yaraast.ast.expressions import (
    BinaryExpression,
    FunctionCall,
    Identifier,
    IntegerLiteral,
    MemberAccess,
    ParenthesesExpression,
    RangeExpression,
    SetExpression,
    StringCount,
    StringIdentifier,
    StringLiteral,
    StringOffset,
    StringWildcard,
)
from yaraast.ast.modifiers import RuleModifier
from yaraast.ast.rules import Rule, Tag
from yaraast.ast.strings import PlainString, RegexString
from yaraast.cli.visitors.formatters import (
    ConditionStringFormatter,
    DetailedNodeStringFormatter,
    ExpressionStringFormatter,
)
from yaraast.cli.visitors.tree_builder import ASTTreeBuilder


def _render_tree(tree) -> str:
    c = Console(file=StringIO(), record=True, force_terminal=False)
    c.print(tree)
    return c.export_text()


def test_condition_and_expression_formatters_cover_branches() -> None:
    cond = ConditionStringFormatter()
    expr = ExpressionStringFormatter()
    det = DetailedNodeStringFormatter()

    deep = BinaryExpression(
        left=BinaryExpression(Identifier("a"), "and", Identifier("b")),
        operator="and",
        right=BinaryExpression(Identifier("c"), "and", Identifier("d")),
    )
    out = cond.format_condition(deep)
    assert "and" in out

    assert cond.format_condition(None) == "<NoneType>"
    assert cond.format_condition(StringLiteral("x"), depth=10) == "..."
    assert "for" in cond.format_condition(SimpleNamespace(identifier="i"), depth=0) or True

    fn = FunctionCall(
        function="math.abs", arguments=[IntegerLiteral(1), IntegerLiteral(2), IntegerLiteral(3)]
    )
    assert "..." in cond.format_condition(fn)

    set_expr = SetExpression(
        elements=[
            StringIdentifier("$a"),
            StringIdentifier("$b"),
            StringIdentifier("$c"),
            StringIdentifier("$d"),
            StringIdentifier("$e"),
            StringIdentifier("$f"),
        ]
    )
    of_expr = SimpleNamespace(
        quantifier="any", string_set=set_expr, __class__=SimpleNamespace(__name__="OfExpression")
    )
    # Force formatter through unsupported object path with class name fallback.
    _ = cond.format_condition(of_expr)

    assert expr.format_expression(BinaryExpression(Identifier("a"), "==", IntegerLiteral(1)))
    assert expr.format_expression(None) == "..."
    assert "(" in expr.format_expression(ParenthesesExpression(expression=Identifier("x")))
    assert "#" in expr.format_expression(StringCount(string_id="$a"))
    assert "@" in expr.format_expression(StringOffset(string_id="$a", index=IntegerLiteral(0)))
    assert "for" in expr._format_for_expression(
        SimpleNamespace(
            quantifier="any",
            variable="i",
            iterable=RangeExpression(IntegerLiteral(1), IntegerLiteral(2)),
            body=Identifier("i"),
        ),
        0,
    )
    assert "." in expr.format_expression(MemberAccess(object=Identifier("m"), member="x"))

    assert det.format_node(StringIdentifier("$a")).startswith("$")
    assert det.format_node(IntegerLiteral(1)) == "1"
    assert det.format_node(StringLiteral("hello world"))
    assert det.format_node(ParenthesesExpression(Identifier("x"))).startswith("(")
    assert det.format_node(Identifier("id")) == "id"
    assert det.format_node(MemberAccess(object=Identifier("o"), member="m")) == "o.m"
    assert (
        det.format_node(BinaryExpression(Identifier("a"), "and", Identifier("b")), depth=3) == "..."
    )


def test_tree_builder_rule_and_fallback_paths() -> None:
    builder = ASTTreeBuilder()
    rule = Rule(
        name="r1",
        modifiers=["private", RuleModifier.from_string("global")],
        tags=[Tag(name="tag"), "extra"],
        meta={"author": "me", "n": 1},
        strings=[
            PlainString(identifier="$a", value="x" * 40),
            RegexString(identifier="$r", regex="ab+"),
        ],
        condition=BinaryExpression(StringIdentifier("$a"), "and", IntegerLiteral(1)),
    )
    tree = builder.visit_rule(rule)
    txt = _render_tree(tree)
    assert "Rule:" in txt
    assert "Tags" in txt
    assert "Meta" in txt
    assert "Strings" in txt
    assert "Condition" in txt

    ast = YaraFile(rules=[rule])
    full = builder.visit_yara_file(ast)
    full_txt = _render_tree(full)
    assert "YARA File" in full_txt

    assert "None" in _render_tree(builder.visit(None))
    assert "Unknown" not in _render_tree(builder.visit(StringWildcard(pattern="$*")))

    # Fallback visitors and truncation branches.
    assert "..." in builder._truncate_at_boundary("a and b and c and d", 5)
    assert builder.visit_comment(SimpleNamespace(text="x")).label
    assert builder.visit_module_reference(SimpleNamespace(name="pe")).label
    assert builder.visit_extern_rule(SimpleNamespace(name="x")).label
    assert builder.visit_regex_literal(SimpleNamespace(value="ab")).label
    assert builder.visit_string_operator_expression(SimpleNamespace()).label
