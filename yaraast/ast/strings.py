"""String-related AST nodes."""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any

from yaraast.ast.base import ASTNode, _require_ast_node_sequence, _VisitorType


def _require_string(value: Any, field_name: str) -> str:
    if not isinstance(value, str):
        msg = f"{field_name} must be a string"
        raise TypeError(msg)
    return value


@dataclass
class StringDefinition(ASTNode):
    """Base class for string definitions."""

    identifier: str
    modifiers: list[Any] = field(default_factory=list)
    is_anonymous: bool = field(default=False, kw_only=True)

    def validate_structure(self) -> None:
        """Validate string definition scalar fields before direct analysis."""
        _require_string(self.identifier, "String identifier")

    def accept(self, visitor: _VisitorType) -> Any:
        return visitor.visit_string_definition(self)


@dataclass
class PlainString(StringDefinition):
    """Plain text string definition."""

    value: str | bytes = ""
    # Exact bytes libyara matches, preserved by the lexer so high-byte escapes
    # (\xHH, 0x80-0xFF) survive a parse -> generate round trip. None when the
    # node was built outside the lexer (e.g. programmatically).
    raw_bytes: bytes | None = None

    def validate_structure(self) -> None:
        """Validate plain string scalar fields before direct analysis."""
        super().validate_structure()
        if not isinstance(self.value, str | bytes):
            msg = "Plain string value must be a string or bytes"
            raise TypeError(msg)
        if self.raw_bytes is not None and not isinstance(self.raw_bytes, bytes):
            msg = "Plain string raw_bytes must be bytes or None"
            raise TypeError(msg)

    def accept(self, visitor: _VisitorType) -> Any:
        return visitor.visit_plain_string(self)


@dataclass
class HexString(StringDefinition):
    """Hex string definition."""

    tokens: list[Any] = field(default_factory=list)

    def validate_structure(self) -> None:
        """Validate hex token containers before direct analysis."""
        super().validate_structure()
        _require_ast_node_sequence(self.tokens, "HexString.tokens")

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

    value: int | str = 0

    def accept(self, visitor: _VisitorType) -> Any:
        return visitor.visit_hex_byte(self)


@dataclass
class HexNegatedByte(HexToken):
    """Negated hex byte or nibble pattern."""

    value: int | str = 0

    def accept(self, visitor: _VisitorType) -> Any:
        if hasattr(visitor, "visit_hex_negated_byte"):
            return visitor.visit_hex_negated_byte(self)
        return visitor.visit_hex_token(self)


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

    alternatives: Any = field(default_factory=list)

    def accept(self, visitor: _VisitorType) -> Any:
        return visitor.visit_hex_alternative(self)


@dataclass
class HexNibble(HexToken):
    """Hex nibble (half-byte) pattern."""

    high: bool  # True for X?, False for ?X
    value: int | str = 0

    def accept(self, visitor: _VisitorType) -> Any:
        return visitor.visit_hex_nibble(self)


@dataclass
class RegexString(StringDefinition):
    """Regular expression string."""

    regex: str = ""  # Add default

    def validate_structure(self) -> None:
        """Validate regex string scalar fields before direct analysis."""
        super().validate_structure()
        _require_string(self.regex, "Regex string pattern")

    def accept(self, visitor: _VisitorType) -> Any:
        return visitor.visit_regex_string(self)
