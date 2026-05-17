"""More tests for CLI visitors and formatters (no mocks)."""

from __future__ import annotations

from typing import Any, cast

from yaraast.ast.conditions import ForExpression, ForOfExpression, OfExpression
from yaraast.ast.expressions import (
    BinaryExpression,
    BooleanLiteral,
    DoubleLiteral,
    FunctionCall,
    Identifier,
    IntegerLiteral,
    StringCount,
    StringLength,
    StringLiteral,
    StringOffset,
    StringWildcard,
)
from yaraast.ast.meta import Meta
from yaraast.ast.modifiers import RuleModifier, RuleModifierType
from yaraast.ast.rules import Rule, Tag
from yaraast.ast.strings import PlainString
from yaraast.cli.visitors import ASTDumper, ASTTreeBuilder, ConditionStringFormatter
from yaraast.cli.visitors.formatters import ExpressionStringFormatter
from yaraast.parser import Parser
from yaraast.parser.source import parse_yara_source


def test_ast_dumper_handles_tags_meta_and_modifiers() -> None:
    rule = Rule(
        name="r1",
        modifiers=[RuleModifier(RuleModifierType.PRIVATE), "global", 123],
        tags=cast(Any, [Tag(name="alpha"), "beta"]),
        meta=[Meta(key="owner", value="me"), Meta(key="flag", value=True)],
        strings=[PlainString(identifier="$a", value="x")],
        condition=Identifier(name="true"),
    )

    dumper = ASTDumper()
    dumped = dumper.visit_rule(rule)

    assert dumped["name"] == "r1"
    assert "private" in dumped["modifiers"]
    assert "global" in dumped["modifiers"]
    assert "123" in dumped["modifiers"]
    assert any(tag.get("name") == "alpha" for tag in dumped["tags"] if isinstance(tag, dict))
    assert "beta" in dumped["tags"]
    assert dumped["meta"]["owner"] == "me"
    assert dumped["meta"]["flag"] is True


def test_condition_formatter_literals_and_calls() -> None:
    formatter = ConditionStringFormatter()

    long_string = StringLiteral(value="x" * 50)
    assert formatter.format_condition(long_string).startswith('"')
    assert "..." in formatter.format_condition(long_string)

    big_int = IntegerLiteral(value=512)
    assert formatter.format_condition(big_int) == "0x200"

    func = FunctionCall(
        function="hash.md5", arguments=[Identifier("x"), Identifier("y"), Identifier("z")]
    )
    assert formatter.format_condition(func).endswith("...)")

    assert formatter.format_condition(StringCount("a")) == "#a"
    assert formatter.format_condition(StringOffset("b")) == "@b"
    assert formatter.format_condition(StringLength("c")) == "!c"


def test_condition_formatter_of_expression_and_binary() -> None:
    formatter = ConditionStringFormatter()
    of_expr = OfExpression(quantifier="all", string_set=Identifier(name="them"))
    assert formatter.format_condition(of_expr) == "all of them"

    binary = BinaryExpression(
        left=Identifier(name="a"),
        operator="and",
        right=Identifier(name="b"),
    )
    assert formatter.format_condition(binary) == "a and b"


def test_condition_formatter_handles_parsed_of_literals() -> None:
    ast = Parser().parse('rule r { strings: $a = "a" condition: any of them }')
    condition = ast.rules[0].condition

    assert ConditionStringFormatter().format_condition(condition) == "any of them"
    assert ExpressionStringFormatter()._format_of_expression(condition, 0) == "any of them"

    percent_ast = Parser().parse('rule r { strings: $a = "a" $b = "b" condition: 50% of them }')
    percent_condition = percent_ast.rules[0].condition
    assert ConditionStringFormatter().format_condition(percent_condition) == "50% of them"
    assert ExpressionStringFormatter()._format_of_expression(percent_condition, 0) == "50% of them"
    raw_percent = OfExpression(quantifier=0.5, string_set=Identifier("them"))
    literal_percent = OfExpression(quantifier=DoubleLiteral(0.5), string_set=Identifier("them"))
    assert ConditionStringFormatter().format_condition(raw_percent) == "50% of them"
    assert ExpressionStringFormatter()._format_of_expression(literal_percent, 0) == "50% of them"

    assert (
        ExpressionStringFormatter()._format_string_set(
            OfExpression(quantifier="any", string_set=StringWildcard("$a*")),
            0,
        )
        == "($a*)"
    )
    assert (
        ExpressionStringFormatter()._format_string_set(
            OfExpression(quantifier="any", string_set=["$a", "$b"]),
            0,
        )
        == "($a, $b)"
    )

    wildcard_ast = Parser().parse('rule r { strings: $a = "a" condition: any of ($a*) }')
    wildcard_condition = wildcard_ast.rules[0].condition
    assert ConditionStringFormatter().format_condition(wildcard_condition) == "any of ($a*)"
    assert ExpressionStringFormatter()._format_of_expression(wildcard_condition, 0) == (
        "any of ($a*)"
    )


def test_condition_formatter_handles_parsed_for_expression() -> None:
    ast = Parser().parse("rule r { condition: for any i in (1..3) : (i > 1) }")

    assert (
        ConditionStringFormatter().format_condition(ast.rules[0].condition)
        == "for any i in ((1..3)) : (i > 1)"
    )

    built = ForExpression(
        quantifier=IntegerLiteral(2),
        variable="i",
        iterable=Identifier("items"),
        body=Identifier("i"),
    )
    assert ExpressionStringFormatter().format_expression(built) == "for 2 i in items : (i)"


def test_condition_formatter_handles_for_of_expression_details() -> None:
    ast = Parser().parse('rule r { strings: $a = "a" condition: for any of them : ($) }')
    condition = ast.rules[0].condition

    assert ConditionStringFormatter().format_condition(condition) == "for any of them : ($)"
    assert ExpressionStringFormatter().format_expression(condition) == "for any of them : ($)"

    raw_without_body = ForOfExpression(quantifier="all", string_set=["$a", "$b"], condition=None)
    assert ConditionStringFormatter().format_condition(raw_without_body) == "all of ($a, $b)"
    assert ExpressionStringFormatter().format_expression(raw_without_body) == "all of ($a, $b)"

    built = ForOfExpression(
        quantifier=IntegerLiteral(2),
        string_set=StringWildcard("$a*"),
        condition=BooleanLiteral(True),
    )
    assert ConditionStringFormatter().format_condition(built) == "for 2 of ($a*) : (true)"
    assert ExpressionStringFormatter().format_expression(built) == "for 2 of ($a*) : (true)"

    raw_percent = ForOfExpression(quantifier=0.5, string_set=Identifier("them"))
    literal_percent = ForOfExpression(quantifier=DoubleLiteral(0.5), string_set=Identifier("them"))
    assert ConditionStringFormatter().format_condition(raw_percent) == "50% of them"
    assert ExpressionStringFormatter().format_expression(literal_percent) == "50% of them"


def test_tree_builder_formats_yarax_condition() -> None:
    ast = parse_yara_source("rule x { condition: with xs = [1]: match xs { _ => true } }")

    condition = ASTTreeBuilder()._get_condition_string(ast.rules[0].condition)

    assert "with xs = [1]" in condition
    assert "match xs" in condition
