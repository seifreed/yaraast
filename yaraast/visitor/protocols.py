"""Focused visitor protocols for Interface Segregation Principle.

These protocols allow structural typing so that consumers can depend on
only the subset of visit methods they actually need, rather than the
full ASTVisitor interface.
"""

from __future__ import annotations

from typing import Protocol, TypeVar, runtime_checkable

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
from yaraast.ast.modifiers import StringModifier
from yaraast.ast.rules import Import, Include, Rule, Tag
from yaraast.ast.strings import (
    HexAlternative,
    HexByte,
    HexJump,
    HexNibble,
    HexString,
    HexToken,
    HexWildcard,
    PlainString,
    RegexString,
    StringDefinition,
)

T = TypeVar("T", covariant=True)


@runtime_checkable
class RuleVisitor(Protocol[T]):
    """Visitor for rule-level nodes only."""

    def visit_yara_file(self, node: YaraFile) -> T: ...

    def visit_rule(self, node: Rule) -> T: ...

    def visit_import(self, node: Import) -> T: ...

    def visit_include(self, node: Include) -> T: ...

    def visit_tag(self, node: Tag) -> T: ...

    def visit_meta(self, node: Meta) -> T: ...


@runtime_checkable
class StringVisitor(Protocol[T]):
    """Visitor for string-related nodes only."""

    def visit_string_definition(self, node: StringDefinition) -> T: ...

    def visit_plain_string(self, node: PlainString) -> T: ...

    def visit_hex_string(self, node: HexString) -> T: ...

    def visit_regex_string(self, node: RegexString) -> T: ...

    def visit_string_modifier(self, node: StringModifier) -> T: ...


@runtime_checkable
class ExpressionVisitor(Protocol[T]):
    """Visitor for expression nodes only."""

    def visit_expression(self, node: Expression) -> T: ...

    def visit_identifier(self, node: Identifier) -> T: ...

    def visit_binary_expression(self, node: BinaryExpression) -> T: ...

    def visit_unary_expression(self, node: UnaryExpression) -> T: ...

    def visit_parentheses_expression(self, node: ParenthesesExpression) -> T: ...

    def visit_function_call(self, node: FunctionCall) -> T: ...

    def visit_member_access(self, node: MemberAccess) -> T: ...

    def visit_array_access(self, node: ArrayAccess) -> T: ...

    def visit_integer_literal(self, node: IntegerLiteral) -> T: ...

    def visit_string_literal(self, node: StringLiteral) -> T: ...

    def visit_boolean_literal(self, node: BooleanLiteral) -> T: ...


@runtime_checkable
class HexVisitor(Protocol[T]):
    """Visitor for hex pattern nodes only."""

    def visit_hex_token(self, node: HexToken) -> T: ...

    def visit_hex_byte(self, node: HexByte) -> T: ...

    def visit_hex_wildcard(self, node: HexWildcard) -> T: ...

    def visit_hex_jump(self, node: HexJump) -> T: ...

    def visit_hex_alternative(self, node: HexAlternative) -> T: ...

    def visit_hex_nibble(self, node: HexNibble) -> T: ...


__all__ = [
    "ExpressionVisitor",
    "HexVisitor",
    "RuleVisitor",
    "StringVisitor",
]
