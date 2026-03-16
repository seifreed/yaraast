"""More tests for CLI visitors and formatters (no mocks)."""

from __future__ import annotations

from yaraast.ast.conditions import OfExpression
from yaraast.ast.expressions import (
    BinaryExpression,
    FunctionCall,
    Identifier,
    IntegerLiteral,
    StringLiteral,
)
from yaraast.ast.meta import Meta
from yaraast.ast.modifiers import RuleModifier, RuleModifierType
from yaraast.ast.rules import Rule, Tag
from yaraast.ast.strings import PlainString
from yaraast.cli.visitors import ASTDumper, ConditionStringFormatter


def test_ast_dumper_handles_tags_meta_and_modifiers() -> None:
    rule = Rule(
        name="r1",
        modifiers=[RuleModifier(RuleModifierType.PRIVATE), "global", 123],
        tags=[Tag(name="alpha"), "beta"],
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
