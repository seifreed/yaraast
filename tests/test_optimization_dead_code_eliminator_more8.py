"""Additional branch coverage for dead code eliminator."""

from __future__ import annotations

from types import SimpleNamespace

from yaraast.ast.base import YaraFile
from yaraast.ast.expressions import (
    BinaryExpression,
    BooleanLiteral,
    Identifier,
    StringCount,
    StringIdentifier,
    StringLength,
    StringOffset,
    StringWildcard,
    UnaryExpression,
)
from yaraast.ast.rules import Rule
from yaraast.ast.strings import HexString, PlainString, RegexString
from yaraast.optimization.dead_code_eliminator import DeadCodeEliminator, eliminate_dead_code


def test_contains_rule_reference_and_external_references() -> None:
    dce = DeadCodeEliminator()

    assert dce._contains_rule_reference(Identifier("other_rule")) is True
    assert dce._contains_rule_reference(Identifier("them")) is False
    assert (
        dce._contains_rule_reference(BinaryExpression(Identifier("true"), "and", Identifier("x")))
        is True
    )

    no_cond = Rule(name="a", condition=None)
    with_cond = Rule(name="b", condition=Identifier("ref_rule"))
    assert dce._has_external_references(no_cond) is False
    assert dce._has_external_references(with_cond) is True


def test_visit_methods_track_usage_and_passthrough_nodes() -> None:
    dce = DeadCodeEliminator()
    dce.in_condition = True

    assert dce.visit_string_identifier(StringIdentifier("$a")) == StringIdentifier("$a")
    assert "$a" in dce.used_strings

    assert dce.visit_identifier(Identifier("ref_rule")) == Identifier("ref_rule")
    assert "ref_rule" in dce.used_rules

    assert dce.visit_identifier(Identifier("any")) == Identifier("any")
    assert dce.visit_string_wildcard(StringWildcard("$x*")) is None

    assert dce.visit_string_count(StringCount("$c")) == StringCount("$c")
    assert dce.visit_string_offset(StringOffset("$o")) == StringOffset("$o")
    assert dce.visit_string_length(StringLength("$l")) == StringLength("$l")
    assert "$c" in dce.used_strings and "$o" in dce.used_strings and "$l" in dce.used_strings

    dce.in_condition = False
    assert dce.visit_import(SimpleNamespace()) is not None
    assert dce.visit_include(SimpleNamespace()) is not None
    assert dce.visit_tag(SimpleNamespace()) is not None
    assert dce.visit_meta(SimpleNamespace()) is not None
    assert dce.visit_plain_string(PlainString(identifier="$p", value="x")) == PlainString(
        identifier="$p", value="x"
    )
    assert dce.visit_hex_string(HexString(identifier="$h", tokens=[])) == HexString(
        identifier="$h", tokens=[]
    )
    assert dce.visit_regex_string(RegexString(identifier="$r", regex="x")) == RegexString(
        identifier="$r", regex="x"
    )


def test_binary_and_unary_expression_simplifications() -> None:
    dce = DeadCodeEliminator()

    assert dce.visit_binary_expression(
        BinaryExpression(BooleanLiteral(True), "and", BooleanLiteral(False))
    ) == BooleanLiteral(False)
    assert dce.visit_binary_expression(
        BinaryExpression(BooleanLiteral(True), "or", BooleanLiteral(False))
    ) == BooleanLiteral(True)
    assert dce.visit_binary_expression(
        BinaryExpression(BooleanLiteral(False), "and", Identifier("x"))
    ) == BooleanLiteral(False)
    assert dce.visit_binary_expression(
        BinaryExpression(BooleanLiteral(True), "or", Identifier("x"))
    ) == BooleanLiteral(True)
    assert dce.visit_binary_expression(
        BinaryExpression(Identifier("x"), "and", BooleanLiteral(False))
    ) == BooleanLiteral(False)
    assert dce.visit_binary_expression(
        BinaryExpression(Identifier("x"), "or", BooleanLiteral(True))
    ) == BooleanLiteral(True)

    assert dce.visit_unary_expression(
        UnaryExpression("not", BooleanLiteral(True))
    ) == BooleanLiteral(False)
    non_folded = UnaryExpression("-", BooleanLiteral(True))
    assert dce.visit_unary_expression(non_folded) is non_folded


def test_visit_rule_and_file_filtering_paths() -> None:
    dce = DeadCodeEliminator()

    rule_used = Rule(
        name="used",
        strings=[PlainString(identifier="$a", value="a"), PlainString(identifier="$b", value="b")],
        condition=StringIdentifier("$a"),
    )
    rule_false = Rule(name="drop_false", condition=BooleanLiteral(False))
    rule_ref = Rule(name="ref", condition=Identifier("used"))
    rule_private = Rule(name="priv", modifiers=["private"], condition=Identifier("other"))
    yf = YaraFile(rules=[rule_used, rule_false, rule_ref, rule_private])

    optimized, count = dce.eliminate(yf)

    assert count >= 2
    assert all(r.name != "drop_false" for r in optimized.rules)
    kept_used = next(r for r in optimized.rules if r.name == "used")
    assert [s.identifier for s in kept_used.strings] == ["$a"]


def test_eliminate_dead_code_single_rule_and_convenience_wrapper() -> None:
    dce = DeadCodeEliminator()
    rule = Rule(
        name="single",
        strings=[PlainString(identifier="$x", value="x"), PlainString(identifier="$y", value="y")],
        condition=StringIdentifier("$y"),
    )

    out_rule = dce.eliminate_dead_code(rule)
    assert [s.identifier for s in out_rule.strings] == ["$y"]

    # Wrapper currently returns the full eliminate() tuple.
    file_out, elim_count = eliminate_dead_code(YaraFile(rules=[rule]))
    assert isinstance(file_out, YaraFile)
    assert isinstance(elim_count, int)


def test_visit_boolean_literal_passthrough() -> None:
    dce = DeadCodeEliminator()
    lit = BooleanLiteral(True)
    assert dce.visit_boolean_literal(lit) is lit
