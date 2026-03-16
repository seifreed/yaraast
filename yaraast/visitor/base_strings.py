"""String traversal mixin for BaseVisitor."""

from __future__ import annotations

from typing import TypeVar

from yaraast.ast.modifiers import StringModifier
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
from yaraast.visitor.base_helpers import VisitorHelperProtocol

T = TypeVar("T")


class BaseVisitorStringsMixin:
    """String traversal methods."""

    def visit_string_definition(self: VisitorHelperProtocol[T], node: StringDefinition) -> T:
        return self._noop()

    def visit_plain_string(self: VisitorHelperProtocol[T], node: PlainString) -> T:
        self._visit_all(node.modifiers)
        return self._noop()

    def visit_hex_string(self: VisitorHelperProtocol[T], node: HexString) -> T:
        self._visit_all(node.tokens)
        self._visit_all(node.modifiers)
        return self._noop()

    def visit_regex_string(self: VisitorHelperProtocol[T], node: RegexString) -> T:
        self._visit_all(node.modifiers)
        return self._noop()

    def visit_string_modifier(self: VisitorHelperProtocol[T], node: StringModifier) -> T:
        return self._noop()

    def visit_hex_token(self: VisitorHelperProtocol[T], node: HexToken) -> T:
        return self._noop()

    def visit_hex_byte(self: VisitorHelperProtocol[T], node: HexByte) -> T:
        return self._noop()

    def visit_hex_wildcard(self: VisitorHelperProtocol[T], node: HexWildcard) -> T:
        return self._noop()

    def visit_hex_jump(self: VisitorHelperProtocol[T], node: HexJump) -> T:
        return self._noop()

    def visit_hex_alternative(self: VisitorHelperProtocol[T], node: HexAlternative) -> T:
        for alternative in node.alternatives:
            self._visit_all(alternative)
        return self._noop()

    def visit_hex_nibble(self: VisitorHelperProtocol[T], node: HexNibble) -> T:
        return self._noop()
