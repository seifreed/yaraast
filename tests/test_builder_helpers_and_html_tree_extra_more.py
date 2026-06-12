"""Additional real coverage for small builder and html tree helpers."""

from __future__ import annotations

from typing import Any

import pytest

from yaraast.ast.expressions import FunctionCall, Identifier, StringIdentifier, StringLiteral
from yaraast.ast.strings import HexByte, HexString, PlainString
from yaraast.builder.condition_builder import ConditionBuilder
from yaraast.builder.file_builder import YaraFileBuilder
from yaraast.builder.fluent_condition_helpers import (
    build_entropy_call,
    build_of_expression,
    build_string_set,
    chain_or,
    make_binary,
    make_filesize_compare,
)
from yaraast.builder.fluent_file_builder import yara_file
from yaraast.builder.fluent_string_builder import FluentStringBuilder
from yaraast.builder.hex_string_builder import HexStringBuilder
from yaraast.builder.rule_builder import RuleBuilder
from yaraast.errors import ValidationError
from yaraast.metrics.html_tree_nodes_extra import HtmlTreeNodesExtraMixin


class _HtmlExtraVisitor(HtmlTreeNodesExtraMixin):
    def __init__(self) -> None:
        self._counter = 0

    def _get_node_id(self) -> str:
        self._counter += 1
        return f"n{self._counter}"

    def visit(self, node: Any) -> dict[str, str]:
        return {"id": self._get_node_id(), "value": getattr(node, "name", "node")}


class _PatternNode:
    def __init__(self, pattern: str) -> None:
        self.pattern = pattern


def test_fluent_condition_small_helpers_more() -> None:
    string_set = build_string_set("them", "them")
    assert isinstance(string_set, Identifier)
    assert string_set.name == "them"

    of_expr = build_of_expression("any", Identifier(name="them"))
    assert isinstance(of_expr.quantifier, StringLiteral)
    assert of_expr.quantifier.value == "any"

    entropy_call = build_entropy_call(0, 1024)
    assert isinstance(entropy_call, FunctionCall)
    assert entropy_call.function == "math.entropy"
    assert len(entropy_call.arguments) == 2

    try:
        chain_or([])
    except ValidationError as exc:
        assert "Expected at least one condition" in str(exc)
    else:
        raise AssertionError("chain_or([]) should raise")


def test_fluent_condition_helpers_reject_boolean_integer_arguments() -> None:
    with pytest.raises(TypeError, match="Invalid integer literal value"):
        make_filesize_compare("==", True)

    with pytest.raises(TypeError, match="Invalid integer literal value"):
        build_of_expression(False, Identifier(name="them"))

    with pytest.raises(TypeError, match="Invalid integer literal value"):
        build_entropy_call(True, 1024)


def test_fluent_condition_helpers_reject_invalid_of_quantifiers() -> None:
    with pytest.raises(ValidationError, match="of quantifier must not be empty"):
        build_of_expression("", Identifier(name="them"))

    invalid_quantifier: Any = object()
    with pytest.raises(TypeError, match="of quantifier must be an integer or string"):
        build_of_expression(invalid_quantifier, Identifier(name="them"))


def test_fluent_condition_helpers_reject_invalid_prebuilt_expression_structure() -> None:
    invalid_string = StringIdentifier(name="")

    with pytest.raises(ValueError, match="String identifier cannot be empty"):
        build_of_expression("any", invalid_string)

    with pytest.raises(ValueError, match="String identifier cannot be empty"):
        chain_or([Identifier(name="valid"), invalid_string])

    with pytest.raises(ValueError, match="String identifier cannot be empty"):
        make_binary(Identifier(name="valid"), "and", invalid_string)


def test_rule_builder_builds_independent_ast_nodes() -> None:
    builder = RuleBuilder("stable").with_plain_string("$a", "alpha").with_condition("$a")

    first = builder.build()
    second = builder.build()

    assert isinstance(first.strings[0], PlainString)
    assert isinstance(second.strings[0], PlainString)
    assert isinstance(first.condition, StringIdentifier)
    assert isinstance(second.condition, StringIdentifier)
    first.strings[0].identifier = "$corrupted"
    first.condition.name = "$corrupted"

    assert second.strings[0].identifier == "$a"
    assert second.condition.name == "$a"
    assert builder.build().strings[0].identifier == "$a"


def test_condition_and_string_builders_build_independent_ast_nodes() -> None:
    condition_builder = ConditionBuilder().string("$a")
    condition_first = condition_builder.build()
    condition_second = condition_builder.build()
    assert isinstance(condition_first, StringIdentifier)
    assert isinstance(condition_second, StringIdentifier)
    condition_first.name = "$corrupted"
    condition_third = condition_builder.build()
    assert isinstance(condition_third, StringIdentifier)
    assert condition_second.name == "$a"
    assert condition_third.name == "$a"

    hex_builder = HexStringBuilder().add(0x41)
    hex_first = hex_builder.build()
    hex_second = hex_builder.build()
    assert isinstance(hex_first[0], HexByte)
    assert isinstance(hex_second[0], HexByte)
    hex_first[0].value = 0
    hex_third = hex_builder.build()
    assert isinstance(hex_third[0], HexByte)
    assert hex_second[0].value == 0x41
    assert hex_third[0].value == 0x41

    string_builder = FluentStringBuilder("$h").hex_bytes("41").private()
    string_first = string_builder.build()
    string_second = string_builder.build()
    assert isinstance(string_first, HexString)
    assert isinstance(string_second, HexString)
    assert isinstance(string_first.tokens[0], HexByte)
    assert isinstance(string_second.tokens[0], HexByte)
    string_first.tokens[0].value = 0
    string_first.modifiers[0].value = 9
    assert string_second.tokens[0].value == 0x41
    assert string_second.modifiers[0].value is None


def test_file_builders_build_independent_rule_nodes() -> None:
    rule = RuleBuilder("stable").with_condition("true").build()

    direct_builder = YaraFileBuilder().with_import("pe").with_rule(rule)
    direct_first = direct_builder.build()
    direct_second = direct_builder.build()
    direct_first.rules[0].name = "corrupted"

    assert direct_second.rules[0].name == "stable"
    assert direct_builder.build().rules[0].name == "stable"

    fluent_builder = yara_file().import_module("pe").with_rule(rule)
    fluent_first = fluent_builder.build()
    fluent_second = fluent_builder.build()
    fluent_first.imports[0].module = "corrupted"
    fluent_first.rules[0].name = "corrupted"

    assert fluent_second.imports[0].module == "pe"
    assert fluent_second.rules[0].name == "stable"
    assert fluent_builder.build().rules[0].name == "stable"


def test_html_tree_nodes_extra_missing_visitors() -> None:
    visitor = _HtmlExtraVisitor()

    wildcard = visitor.visit_string_wildcard(_PatternNode("$a*"))
    assert wildcard == {"type": "StringWildcard", "pattern": "$a*"}

    condition = visitor.visit_condition(object())
    assert condition["label"] == "Condition"
    assert condition["node_class"] == "condition"
