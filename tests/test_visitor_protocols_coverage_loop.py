# Copyright (c) 2026 Marc Rivero López
# Licensed under GPLv3. See LICENSE file for details.
# This test suite validates real code behavior without mocks or stubs.
"""Coverage for yaraast.visitor.protocols — Protocol stub bodies and isinstance checks.

The module defines four @runtime_checkable Protocol classes:
  RuleVisitor, StringVisitor, ExpressionVisitor, HexVisitor.

Every visit method has an Ellipsis stub body (``...``). Coverage marks these as
branches ``N->exit`` that are only executed when the stub body is called directly.
The Ellipsis expression is evaluated and the function returns None implicitly.

Strategy:
  1. For each Protocol, define a concrete subclass that satisfies the Protocol
     structurally (each method returns None). The concrete instances are used for
     isinstance() checks.
  2. Call each Protocol method as an unbound class-method call passing the
     concrete instance — this routes through the Protocol's MRO and executes the
     Ellipsis stub body, covering the missing N->exit branches.
  3. Verify isinstance() structural matching for @runtime_checkable protocols.
  4. Verify that a class missing required methods fails isinstance().
"""

from __future__ import annotations

from typing import Any

import pytest

from yaraast.ast.base import YaraFile
from yaraast.ast.expressions import (
    ArrayAccess,
    BinaryExpression,
    BooleanLiteral,
    Expression,
    FunctionCall,
    Identifier,
    IntegerLiteral,
    MemberAccess,
    ParenthesesExpression,
    StringLiteral,
    UnaryExpression,
)
from yaraast.ast.meta import Meta
from yaraast.ast.modifiers import StringModifier, StringModifierType
from yaraast.ast.rules import Import, Include, Rule, Tag
from yaraast.ast.strings import (
    HexAlternative,
    HexByte,
    HexJump,
    HexNegatedByte,
    HexNibble,
    HexString,
    HexToken,
    HexWildcard,
    PlainString,
    RegexString,
    StringDefinition,
)
from yaraast.visitor.protocols import (
    ExpressionVisitor,
    HexVisitor,
    RuleVisitor,
    StringVisitor,
)

# ---------------------------------------------------------------------------
# Concrete Protocol subclasses for structural isinstance() validation
# ---------------------------------------------------------------------------


class _ConcreteRuleVisitor(RuleVisitor[None]):
    """Minimal concrete implementation of RuleVisitor used for isinstance checks."""

    def visit_yara_file(self, node: YaraFile) -> None:
        return None

    def visit_rule(self, node: Rule) -> None:
        return None

    def visit_import(self, node: Import) -> None:
        return None

    def visit_include(self, node: Include) -> None:
        return None

    def visit_tag(self, node: Tag) -> None:
        return None

    def visit_meta(self, node: Meta) -> None:
        return None


class _ConcreteStringVisitor(StringVisitor[None]):
    """Minimal concrete implementation of StringVisitor used for isinstance checks."""

    def visit_string_definition(self, node: StringDefinition) -> None:
        return None

    def visit_plain_string(self, node: PlainString) -> None:
        return None

    def visit_hex_string(self, node: HexString) -> None:
        return None

    def visit_regex_string(self, node: RegexString) -> None:
        return None

    def visit_string_modifier(self, node: StringModifier) -> None:
        return None


class _ConcreteExpressionVisitor(ExpressionVisitor[None]):
    """Minimal concrete implementation of ExpressionVisitor used for isinstance checks."""

    def visit_expression(self, node: Expression) -> None:
        return None

    def visit_identifier(self, node: Identifier) -> None:
        return None

    def visit_binary_expression(self, node: BinaryExpression) -> None:
        return None

    def visit_unary_expression(self, node: UnaryExpression) -> None:
        return None

    def visit_parentheses_expression(self, node: ParenthesesExpression) -> None:
        return None

    def visit_function_call(self, node: FunctionCall) -> None:
        return None

    def visit_member_access(self, node: MemberAccess) -> None:
        return None

    def visit_array_access(self, node: ArrayAccess) -> None:
        return None

    def visit_integer_literal(self, node: IntegerLiteral) -> None:
        return None

    def visit_string_literal(self, node: StringLiteral) -> None:
        return None

    def visit_boolean_literal(self, node: BooleanLiteral) -> None:
        return None


class _ConcreteHexVisitor(HexVisitor[None]):
    """Minimal concrete implementation of HexVisitor used for isinstance checks."""

    def visit_hex_token(self, node: HexToken) -> None:
        return None

    def visit_hex_byte(self, node: HexByte) -> None:
        return None

    def visit_hex_negated_byte(self, node: HexNegatedByte) -> None:
        return None

    def visit_hex_wildcard(self, node: HexWildcard) -> None:
        return None

    def visit_hex_jump(self, node: HexJump) -> None:
        return None

    def visit_hex_alternative(self, node: HexAlternative) -> None:
        return None

    def visit_hex_nibble(self, node: HexNibble) -> None:
        return None


# ---------------------------------------------------------------------------
# RuleVisitor stub body tests
#
# Each test calls the Protocol method as an unbound call: Protocol.method(instance, node).
# This routes through the Protocol class in the MRO and executes the Ellipsis
# stub body directly, covering the N->exit branch that is otherwise unreachable
# when the concrete subclass's own method body is called instead.
# ---------------------------------------------------------------------------


class TestRuleVisitorStubBodies:
    """Each test exercises a RuleVisitor Protocol stub body via unbound call."""

    def test_visit_yara_file_stub_returns_none(self) -> None:
        visitor = _ConcreteRuleVisitor()
        node = YaraFile()
        result: Any = RuleVisitor.visit_yara_file(visitor, node)
        assert result is None

    def test_visit_rule_stub_returns_none(self) -> None:
        visitor = _ConcreteRuleVisitor()
        node = Rule(name="test_rule")
        result: Any = RuleVisitor.visit_rule(visitor, node)
        assert result is None

    def test_visit_import_stub_returns_none(self) -> None:
        visitor = _ConcreteRuleVisitor()
        node = Import(module="pe")
        result: Any = RuleVisitor.visit_import(visitor, node)
        assert result is None

    def test_visit_include_stub_returns_none(self) -> None:
        visitor = _ConcreteRuleVisitor()
        node = Include(path="other.yar")
        result: Any = RuleVisitor.visit_include(visitor, node)
        assert result is None

    def test_visit_tag_stub_returns_none(self) -> None:
        visitor = _ConcreteRuleVisitor()
        node = Tag(name="malware")
        result: Any = RuleVisitor.visit_tag(visitor, node)
        assert result is None

    def test_visit_meta_stub_returns_none(self) -> None:
        visitor = _ConcreteRuleVisitor()
        node = Meta(key="author", value="Marc")
        result: Any = RuleVisitor.visit_meta(visitor, node)
        assert result is None


# ---------------------------------------------------------------------------
# StringVisitor stub body tests
# ---------------------------------------------------------------------------


class TestStringVisitorStubBodies:
    """Each test exercises a StringVisitor Protocol stub body via unbound call."""

    def test_visit_string_definition_stub_returns_none(self) -> None:
        visitor = _ConcreteStringVisitor()
        node = PlainString(identifier="$s", value="hello")
        result: Any = StringVisitor.visit_string_definition(visitor, node)
        assert result is None

    def test_visit_plain_string_stub_returns_none(self) -> None:
        visitor = _ConcreteStringVisitor()
        node = PlainString(identifier="$p", value="world")
        result: Any = StringVisitor.visit_plain_string(visitor, node)
        assert result is None

    def test_visit_hex_string_stub_returns_none(self) -> None:
        visitor = _ConcreteStringVisitor()
        node = HexString(identifier="$h", tokens=[])
        result: Any = StringVisitor.visit_hex_string(visitor, node)
        assert result is None

    def test_visit_regex_string_stub_returns_none(self) -> None:
        visitor = _ConcreteStringVisitor()
        node = RegexString(identifier="$r", regex="foo.*")
        result: Any = StringVisitor.visit_regex_string(visitor, node)
        assert result is None

    def test_visit_string_modifier_stub_returns_none(self) -> None:
        visitor = _ConcreteStringVisitor()
        node = StringModifier(modifier_type=StringModifierType.NOCASE)
        result: Any = StringVisitor.visit_string_modifier(visitor, node)
        assert result is None


# ---------------------------------------------------------------------------
# ExpressionVisitor stub body tests
# ---------------------------------------------------------------------------


class TestExpressionVisitorStubBodies:
    """Each test exercises an ExpressionVisitor Protocol stub body via unbound call."""

    def test_visit_expression_stub_returns_none(self) -> None:
        visitor = _ConcreteExpressionVisitor()
        node = Expression()
        result: Any = ExpressionVisitor.visit_expression(visitor, node)
        assert result is None

    def test_visit_identifier_stub_returns_none(self) -> None:
        visitor = _ConcreteExpressionVisitor()
        node = Identifier(name="pe")
        result: Any = ExpressionVisitor.visit_identifier(visitor, node)
        assert result is None

    def test_visit_binary_expression_stub_returns_none(self) -> None:
        visitor = _ConcreteExpressionVisitor()
        left = Identifier(name="a")
        right = IntegerLiteral(value=1)
        node = BinaryExpression(left=left, operator="==", right=right)
        result: Any = ExpressionVisitor.visit_binary_expression(visitor, node)
        assert result is None

    def test_visit_unary_expression_stub_returns_none(self) -> None:
        visitor = _ConcreteExpressionVisitor()
        operand = BooleanLiteral(value=True)
        node = UnaryExpression(operator="not", operand=operand)
        result: Any = ExpressionVisitor.visit_unary_expression(visitor, node)
        assert result is None

    def test_visit_parentheses_expression_stub_returns_none(self) -> None:
        visitor = _ConcreteExpressionVisitor()
        inner = BooleanLiteral(value=False)
        node = ParenthesesExpression(expression=inner)
        result: Any = ExpressionVisitor.visit_parentheses_expression(visitor, node)
        assert result is None

    def test_visit_function_call_stub_returns_none(self) -> None:
        visitor = _ConcreteExpressionVisitor()
        node = FunctionCall(function="pe.is_pe", arguments=[])
        result: Any = ExpressionVisitor.visit_function_call(visitor, node)
        assert result is None

    def test_visit_member_access_stub_returns_none(self) -> None:
        visitor = _ConcreteExpressionVisitor()
        obj = Identifier(name="pe")
        node = MemberAccess(object=obj, member="number_of_sections")
        result: Any = ExpressionVisitor.visit_member_access(visitor, node)
        assert result is None

    def test_visit_array_access_stub_returns_none(self) -> None:
        visitor = _ConcreteExpressionVisitor()
        arr = Identifier(name="pe")
        idx = IntegerLiteral(value=0)
        node = ArrayAccess(array=arr, index=idx)
        result: Any = ExpressionVisitor.visit_array_access(visitor, node)
        assert result is None

    def test_visit_integer_literal_stub_returns_none(self) -> None:
        visitor = _ConcreteExpressionVisitor()
        node = IntegerLiteral(value=42)
        result: Any = ExpressionVisitor.visit_integer_literal(visitor, node)
        assert result is None

    def test_visit_string_literal_stub_returns_none(self) -> None:
        visitor = _ConcreteExpressionVisitor()
        node = StringLiteral(value="test")
        result: Any = ExpressionVisitor.visit_string_literal(visitor, node)
        assert result is None

    def test_visit_boolean_literal_stub_returns_none(self) -> None:
        visitor = _ConcreteExpressionVisitor()
        node = BooleanLiteral(value=True)
        result: Any = ExpressionVisitor.visit_boolean_literal(visitor, node)
        assert result is None


# ---------------------------------------------------------------------------
# HexVisitor stub body tests
# ---------------------------------------------------------------------------


class TestHexVisitorStubBodies:
    """Each test exercises a HexVisitor Protocol stub body via unbound call."""

    def test_visit_hex_token_stub_returns_none(self) -> None:
        visitor = _ConcreteHexVisitor()
        node = HexToken()
        result: Any = HexVisitor.visit_hex_token(visitor, node)
        assert result is None

    def test_visit_hex_byte_stub_returns_none(self) -> None:
        visitor = _ConcreteHexVisitor()
        node = HexByte(value=0xAB)
        result: Any = HexVisitor.visit_hex_byte(visitor, node)
        assert result is None

    def test_visit_hex_negated_byte_stub_returns_none(self) -> None:
        visitor = _ConcreteHexVisitor()
        node = HexNegatedByte(value=0xCC)
        result: Any = HexVisitor.visit_hex_negated_byte(visitor, node)
        assert result is None

    def test_visit_hex_wildcard_stub_returns_none(self) -> None:
        visitor = _ConcreteHexVisitor()
        node = HexWildcard()
        result: Any = HexVisitor.visit_hex_wildcard(visitor, node)
        assert result is None

    def test_visit_hex_jump_stub_returns_none(self) -> None:
        visitor = _ConcreteHexVisitor()
        node = HexJump(min_jump=1, max_jump=4)
        result: Any = HexVisitor.visit_hex_jump(visitor, node)
        assert result is None

    def test_visit_hex_alternative_stub_returns_none(self) -> None:
        visitor = _ConcreteHexVisitor()
        node = HexAlternative()
        result: Any = HexVisitor.visit_hex_alternative(visitor, node)
        assert result is None

    def test_visit_hex_nibble_stub_returns_none(self) -> None:
        visitor = _ConcreteHexVisitor()
        node = HexNibble(high=True, value=0xF)
        result: Any = HexVisitor.visit_hex_nibble(visitor, node)
        assert result is None


# ---------------------------------------------------------------------------
# isinstance() checks for @runtime_checkable protocols
# ---------------------------------------------------------------------------


class TestRuntimeCheckableIsinstance:
    """@runtime_checkable allows isinstance() structural matching. These tests
    validate that the runtime dispatch is correct for each Protocol."""

    def test_rule_visitor_isinstance_recognises_concrete_subclass(self) -> None:
        visitor = _ConcreteRuleVisitor()
        assert isinstance(visitor, RuleVisitor)

    def test_string_visitor_isinstance_recognises_concrete_subclass(self) -> None:
        visitor = _ConcreteStringVisitor()
        assert isinstance(visitor, StringVisitor)

    def test_expression_visitor_isinstance_recognises_concrete_subclass(self) -> None:
        visitor = _ConcreteExpressionVisitor()
        assert isinstance(visitor, ExpressionVisitor)

    def test_hex_visitor_isinstance_recognises_concrete_subclass(self) -> None:
        visitor = _ConcreteHexVisitor()
        assert isinstance(visitor, HexVisitor)

    def test_rule_visitor_isinstance_rejects_unrelated_class(self) -> None:
        class _Unrelated:
            pass

        assert not isinstance(_Unrelated(), RuleVisitor)

    def test_string_visitor_isinstance_rejects_unrelated_class(self) -> None:
        class _Unrelated:
            pass

        assert not isinstance(_Unrelated(), StringVisitor)

    def test_expression_visitor_isinstance_rejects_unrelated_class(self) -> None:
        class _Unrelated:
            pass

        assert not isinstance(_Unrelated(), ExpressionVisitor)

    def test_hex_visitor_isinstance_rejects_unrelated_class(self) -> None:
        class _Unrelated:
            pass

        assert not isinstance(_Unrelated(), HexVisitor)

    def test_protocol_subclasses_do_not_cross_satisfy_each_other(self) -> None:
        # RuleVisitor should not structurally satisfy StringVisitor because
        # StringVisitor requires visit_plain_string, visit_hex_string, etc.
        visitor = _ConcreteRuleVisitor()
        assert isinstance(visitor, RuleVisitor)
        assert not isinstance(visitor, StringVisitor)
        assert not isinstance(visitor, ExpressionVisitor)
        assert not isinstance(visitor, HexVisitor)

    def test_hex_visitor_is_only_hex_visitor(self) -> None:
        visitor = _ConcreteHexVisitor()
        assert isinstance(visitor, HexVisitor)
        assert not isinstance(visitor, RuleVisitor)
        assert not isinstance(visitor, StringVisitor)
        assert not isinstance(visitor, ExpressionVisitor)


# ---------------------------------------------------------------------------
# __all__ export validation
# ---------------------------------------------------------------------------


class TestProtocolExports:
    """Validate that the four Protocol names are exported via __all__."""

    def test_all_exports_contains_expected_protocol_names(self) -> None:
        from yaraast.visitor import protocols as _protocols_module

        exported = set(_protocols_module.__all__)
        assert "RuleVisitor" in exported
        assert "StringVisitor" in exported
        assert "ExpressionVisitor" in exported
        assert "HexVisitor" in exported

    def test_all_exports_contains_exactly_four_names(self) -> None:
        from yaraast.visitor import protocols as _protocols_module

        assert len(_protocols_module.__all__) == 4

    @pytest.mark.parametrize(
        "protocol_cls",
        [RuleVisitor, StringVisitor, ExpressionVisitor, HexVisitor],
    )
    def test_protocol_is_runtime_checkable(self, protocol_cls: type) -> None:
        # A @runtime_checkable Protocol supports isinstance() without raising TypeError.
        # If the decorator were missing, isinstance() would raise TypeError.
        try:
            isinstance(object(), protocol_cls)
        except TypeError:
            pytest.fail(
                f"{protocol_cls.__name__} is not @runtime_checkable "
                f"but isinstance() raised TypeError"
            )
