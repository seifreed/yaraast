"""String-related AST nodes."""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any

from yaraast.ast.base import ASTNode, _VisitorType
from yaraast.ast.modifiers import StringModifier


@dataclass
class StringDefinition(ASTNode):
    """Base class for string definitions."""

    identifier: str
    modifiers: list[StringModifier] = field(default_factory=list)

    def accept(self, visitor: _VisitorType) -> Any:
        return visitor.visit_string_definition(self)


@dataclass
class PlainString(StringDefinition):
    """Plain text string definition."""

    value: str = ""  # Add default

    def accept(self, visitor: _VisitorType) -> Any:
        return visitor.visit_plain_string(self)


@dataclass
class HexString(StringDefinition):
    """Hex string definition."""

    tokens: list[HexToken] = field(default_factory=list)  # Add default

    def accept(self, visitor: _VisitorType) -> Any:
        return visitor.visit_hex_string(self)


@dataclass
class HexToken(ASTNode):
    """Base class for hex string tokens."""

    def accept(self, visitor: _VisitorType) -> Any:
        return visitor.visit_hex_token(self)


@dataclass
class HexByte(HexToken):
    """Single hex byte."""

    value: int = 0  # Add default

    def accept(self, visitor: _VisitorType) -> Any:
        return visitor.visit_hex_byte(self)


@dataclass
class HexNegatedByte(HexToken):
    """Negated hex byte — matches anything except this value."""

    value: int = 0

    def accept(self, visitor: _VisitorType) -> Any:
        if hasattr(visitor, "visit_hex_negated_byte"):
            return visitor.visit_hex_negated_byte(self)
        return visitor.visit_hex_byte(self)


@dataclass
class HexWildcard(HexToken):
    """Hex wildcard (?)."""

    def accept(self, visitor: _VisitorType) -> Any:
        return visitor.visit_hex_wildcard(self)


@dataclass
class HexJump(HexToken):
    """Hex jump [n-m]."""

    min_jump: int | None = None
    max_jump: int | None = None

    def accept(self, visitor: _VisitorType) -> Any:
        return visitor.visit_hex_jump(self)


@dataclass
class HexAlternative(HexToken):
    """Hex alternative (a|b|c)."""

    alternatives: list[list[HexToken]] = field(default_factory=list)  # Add default

    def accept(self, visitor: _VisitorType) -> Any:
        return visitor.visit_hex_alternative(self)


@dataclass
class HexNibble(HexToken):
    """Hex nibble (half-byte) pattern."""

    high: bool  # True for X?, False for ?X
    value: int = 0  # 0-15

    def accept(self, visitor: _VisitorType) -> Any:
        return visitor.visit_hex_nibble(self)


@dataclass
class RegexString(StringDefinition):
    """Regular expression string."""

    regex: str = ""  # Add default

    def accept(self, visitor: _VisitorType) -> Any:
        return visitor.visit_regex_string(self)
