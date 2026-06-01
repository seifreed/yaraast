"""More tests for fluent rule builder (no mocks)."""

from __future__ import annotations

from yaraast.ast.expressions import BinaryExpression, BooleanLiteral
from yaraast.builder.fluent_file_builder import yara_file
from yaraast.builder.fluent_rule_builder import FluentRuleBuilder


def test_fluent_rule_builder_strings_and_modifiers() -> None:
    rule = (
        FluentRuleBuilder("demo")
        .string("$a")
        .text("hello")
        .nocase()
        .then()
        .string("$b")
        .hex("4D 5A")
        .then()
        .matches_any()
        .build()
    )

    assert rule.name == "demo"
    assert len(rule.strings) == 2
    assert rule.condition is not None


def test_fluent_rule_builder_for_pe_and_filesize() -> None:
    rule = FluentRuleBuilder("pe_demo").mz_header().for_pe_files().for_large_files().build()

    assert any(s.identifier == "$mz" or s.identifier == "MZ" for s in rule.strings)
    assert rule.condition is not None


def test_fluent_rule_builder_combines_falsy_present_condition() -> None:
    class FalsyBooleanLiteral(BooleanLiteral):
        def __bool__(self) -> bool:
            return False

    rule = (
        FluentRuleBuilder("falsy_combo")
        .condition(FalsyBooleanLiteral(value=False))
        .for_large_files()
        .build()
    )

    assert isinstance(rule.condition, BinaryExpression)
    assert isinstance(rule.condition.left, FalsyBooleanLiteral)
    assert rule.condition.left.value is False


def test_fluent_yara_file_builder_then_rule() -> None:
    yf = (
        yara_file()
        .import_module("pe")
        .rule("r1")
        .text_string("$a", "x")
        .condition("true")
        .then_rule("r2")
        .text_string("$b", "y")
        .condition(BooleanLiteral(value=True))
        .then_build_file()
    )

    assert len(yf.rules) == 2
    assert yf.imports[0].module == "pe"
