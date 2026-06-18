"""String-related AST nodes."""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any

from yaraast.ast.base import (
    ASTNode,
    _require_ast_node_sequence,
    _require_nonempty_string,
    _VisitorType,
    require_string,
)
from yaraast.regex_literals import validate_regex_pattern
from yaraast.string_references import validate_string_identifier_text

_HEX_CHARS = frozenset("0123456789abcdefABCDEF")
_REGEX_SUFFIX_MODIFIER_NAMES = frozenset({"i", "m", "s"})
_UNSUPPORTED_PLAIN_STRING_MODIFIERS = frozenset(
    {
        "case",
        "dotall",
        "i",
        "m",
        "multiline",
        "s",
        "utf8",
        "utf16",
        "utf16le",
        "utf16be",
    }
)
_BASE64_MODIFIER_NAMES = frozenset({"base64", "base64wide"})
_BASE64_INCOMPATIBLE_MODIFIERS = frozenset({"fullword", "nocase", "xor"})
_XOR_INCOMPATIBLE_MODIFIERS = frozenset({"base64", "base64wide", "nocase"})
_HEX_ALLOWED_MODIFIERS = frozenset({"private"})
_REGEX_DISALLOWED_MODIFIERS = frozenset({"base64", "base64wide", "xor"})
_MISSING = object()


def _is_byte_value(value: Any) -> bool:
    return (isinstance(value, int) and not isinstance(value, bool) and 0 <= value <= 0xFF) or (
        isinstance(value, str) and len(value) == 2 and all(char in _HEX_CHARS for char in value)
    )


def _is_negated_nibble_pattern(value: str) -> bool:
    if len(value) != 2:
        return False
    first = value[0]
    second = value[1]
    return (first == "?" and second in _HEX_CHARS) or (first in _HEX_CHARS and second == "?")


def _validate_hex_byte_value(value: Any, field_name: str) -> None:
    if _is_byte_value(value):
        return
    msg = f"{field_name} must be a byte"
    raise TypeError(msg)


def _validate_hex_jump_bound(value: Any, field_name: str) -> int | None:
    if value is None:
        return None
    if isinstance(value, bool) or not isinstance(value, int) or value < 0:
        msg = f"HexJump {field_name} must be a non-negative integer"
        raise TypeError(msg)
    return int(value)


def _validate_hex_token(value: Any, context: str, *, inside_alternative: bool) -> None:
    if inside_alternative and isinstance(value, int | str):
        _validate_hex_byte_value(value, "HexByte value")
        return
    if not isinstance(value, HexToken):
        msg = f"Unsupported hex token '{type(value).__name__}' for {context}"
        raise TypeError(msg)
    validate_structure = getattr(value, "validate_structure", None)
    if callable(validate_structure):
        validate_structure()
    if inside_alternative and isinstance(value, HexJump) and value.max_jump is None:
        msg = "Unbounded HexJump is not allowed inside hex alternatives"
        raise ValueError(msg)


def _validate_hex_token_sequence(
    values: list[Any] | tuple[Any, ...],
    context: str,
    *,
    inside_alternative: bool,
) -> None:
    if not values:
        if inside_alternative:
            msg = "HexAlternative branches must not be empty"
        else:
            msg = "Hex string must contain at least one token"
        raise ValueError(msg)
    for value in values:
        _validate_hex_token(value, context, inside_alternative=inside_alternative)
    if isinstance(values[0], HexJump) or isinstance(values[-1], HexJump):
        msg = f"HexJump cannot appear at the beginning or end of {context}"
        raise ValueError(msg)


def _require_string_identifier(value: Any, node_type: str) -> str:
    identifier = require_string(value, "String identifier")
    if not identifier.strip():
        msg = f"{node_type} identifier must not be empty"
        raise ValueError(msg)
    return identifier


def _validate_regex_text(regex: str) -> None:
    if any(0xD800 <= ord(character) <= 0xDFFF for character in regex):
        msg = "Regex pattern must not contain Unicode surrogate code points"
        raise ValueError(msg)
    if "\n" in regex:
        msg = "Regex pattern must not contain line breaks"
        raise ValueError(msg)
    if "\x00" in regex:
        msg = "Regex pattern must not contain NUL bytes"
        raise ValueError(msg)
    validate_regex_pattern(regex)


@dataclass
class StringDefinition(ASTNode):
    """Base class for string definitions."""

    identifier: str
    modifiers: list[Any] = field(default_factory=list)
    is_anonymous: bool = field(default=False, kw_only=True)

    def validate_structure(self) -> None:
        """Validate string definition scalar fields before direct analysis."""
        identifier = _require_string_identifier(self.identifier, type(self).__name__)
        if self.is_anonymous:
            validate_string_identifier_text(identifier, allow_placeholder=True)
        else:
            validate_string_identifier_text(identifier)
        if not isinstance(self.modifiers, list):
            msg = f"{type(self).__name__} modifiers must be a list"
            raise TypeError(msg)
        from yaraast.ast.modifiers import StringModifier, StringModifierType

        known_modifier_names = {modifier_type.value for modifier_type in StringModifierType}

        modifier_names: list[str] = []
        for modifier in self.modifiers:
            if isinstance(modifier, StringModifier):
                modifier.validate_structure()
                modifier_names.append(modifier.name)
            elif isinstance(modifier, str):
                modifier_name = _require_nonempty_string(
                    modifier,
                    f"{type(self).__name__} modifier name",
                )
                normalized_name = modifier_name.lower()
                if (
                    normalized_name not in _REGEX_SUFFIX_MODIFIER_NAMES
                    and normalized_name not in known_modifier_names
                ):
                    msg = f"Unknown string modifier: {modifier_name}"
                    raise ValueError(msg)
                modifier_names.append(normalized_name)
            else:
                msg = f"{type(self).__name__} modifiers item must be StringModifier or string"
                raise TypeError(msg)
        self._validate_modifier_names(modifier_names)
        if not isinstance(self.is_anonymous, bool):
            msg = f"{type(self).__name__} is_anonymous must be a boolean"
            raise TypeError(msg)

    def _validate_modifier_names(self, modifier_names: list[str]) -> None:
        seen: set[str] = set()
        for modifier_name in modifier_names:
            if modifier_name in seen:
                msg = f"Duplicate string modifier '{modifier_name}'"
                raise ValueError(msg)
            seen.add(modifier_name)

    def accept(self, visitor: _VisitorType) -> Any:
        return visitor.visit_string_definition(self)


@dataclass(init=False)
class PlainString(StringDefinition):
    """Plain text string definition."""

    value: str | bytes = ""
    # Exact bytes libyara matches, preserved by the lexer so high-byte escapes
    # (\xHH, 0x80-0xFF) survive a parse -> generate round trip. None when the
    # node was built outside the lexer (e.g. programmatically).
    raw_bytes: bytes | None = None

    def __init__(
        self,
        identifier: str,
        value: str | bytes = "",
        modifiers: Any = _MISSING,
        *,
        is_anonymous: bool = False,
        raw_bytes: bytes | None = None,
    ) -> None:
        modifier_values = [] if modifiers is _MISSING else modifiers
        super().__init__(
            identifier=identifier,
            modifiers=modifier_values,
            is_anonymous=is_anonymous,
        )
        self.value = value
        self.raw_bytes = raw_bytes

    def validate_structure(self) -> None:
        """Validate plain string scalar fields before direct analysis."""
        super().validate_structure()
        if not isinstance(self.value, str | bytes):
            msg = "Plain string value must be a string or bytes"
            raise TypeError(msg)
        if isinstance(self.value, str) and any(
            0xD800 <= ord(character) <= 0xDFFF for character in self.value
        ):
            msg = "Plain string value must not contain Unicode surrogate code points"
            raise ValueError(msg)
        if self.raw_bytes is not None and not isinstance(self.raw_bytes, bytes):
            msg = "Plain string raw_bytes must be bytes or None"
            raise TypeError(msg)

    def _validate_modifier_names(self, modifier_names: list[str]) -> None:
        super()._validate_modifier_names(modifier_names)
        names = set(modifier_names)
        for modifier_name in sorted(names & _UNSUPPORTED_PLAIN_STRING_MODIFIERS):
            msg = f"Unsupported string modifier: {modifier_name}"
            raise ValueError(msg)
        for base64_name in sorted(names & _BASE64_MODIFIER_NAMES):
            for incompatible_name in sorted(names & _BASE64_INCOMPATIBLE_MODIFIERS):
                msg = (
                    f"String modifier '{incompatible_name}' cannot be combined "
                    f"with '{base64_name}'"
                )
                raise ValueError(msg)
        if "xor" not in names:
            return
        for incompatible_name in sorted(names & _XOR_INCOMPATIBLE_MODIFIERS):
            msg = f"String modifier '{incompatible_name}' cannot be combined with 'xor'"
            raise ValueError(msg)

    def accept(self, visitor: _VisitorType) -> Any:
        return visitor.visit_plain_string(self)


@dataclass(init=False)
class HexString(StringDefinition):
    """Hex string definition."""

    tokens: list[Any] = field(default_factory=list)

    def __init__(
        self,
        identifier: str,
        tokens: Any = _MISSING,
        modifiers: Any = _MISSING,
        *,
        is_anonymous: bool = False,
    ) -> None:
        modifier_values = [] if modifiers is _MISSING else modifiers
        super().__init__(
            identifier=identifier,
            modifiers=modifier_values,
            is_anonymous=is_anonymous,
        )
        self.tokens = [] if tokens is _MISSING else tokens

    def validate_structure(self) -> None:
        """Validate hex token containers before direct analysis."""
        super().validate_structure()
        tokens = _require_ast_node_sequence(self.tokens, "HexString.tokens")
        _validate_hex_token_sequence(tokens, "hex string", inside_alternative=False)

    def _validate_modifier_names(self, modifier_names: list[str]) -> None:
        super()._validate_modifier_names(modifier_names)
        for modifier_name in sorted(set(modifier_names)):
            if modifier_name in _HEX_ALLOWED_MODIFIERS:
                continue
            msg = f"String modifier '{modifier_name}' is not valid on hex strings"
            raise ValueError(msg)

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

    def validate_structure(self) -> None:
        """Validate byte value before direct analysis."""
        _validate_hex_byte_value(self.value, "HexByte value")

    def accept(self, visitor: _VisitorType) -> Any:
        return visitor.visit_hex_byte(self)


@dataclass
class HexNegatedByte(HexToken):
    """Negated hex byte or nibble pattern."""

    value: int | str = 0

    def validate_structure(self) -> None:
        """Validate negated byte value before direct analysis."""
        if _is_byte_value(self.value):
            return
        if isinstance(self.value, str) and _is_negated_nibble_pattern(self.value):
            return
        msg = "HexNegatedByte value must be a byte or negated nibble"
        raise TypeError(msg)

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

    def validate_structure(self) -> None:
        """Validate jump bounds before direct analysis."""
        min_jump = _validate_hex_jump_bound(self.min_jump, "min_jump")
        max_jump = _validate_hex_jump_bound(self.max_jump, "max_jump")
        if min_jump is not None and max_jump is not None and min_jump > max_jump:
            msg = "HexJump min_jump cannot exceed max_jump"
            raise TypeError(msg)

    def accept(self, visitor: _VisitorType) -> Any:
        return visitor.visit_hex_jump(self)


@dataclass
class HexAlternative(HexToken):
    """Hex alternative (a|b|c)."""

    alternatives: Any = field(default_factory=list)

    def validate_structure(self) -> None:
        """Validate alternative branches before direct analysis."""
        if not isinstance(self.alternatives, list | tuple) or not self.alternatives:
            msg = "HexAlternative must contain at least one branch"
            raise ValueError(msg)
        for alternative in self.alternatives:
            branch = alternative if isinstance(alternative, list | tuple) else [alternative]
            _validate_hex_token_sequence(
                branch,
                "hex alternative branch",
                inside_alternative=True,
            )

    def accept(self, visitor: _VisitorType) -> Any:
        return visitor.visit_hex_alternative(self)


@dataclass
class HexNibble(HexToken):
    """Hex nibble (half-byte) pattern."""

    high: bool  # True for X?, False for ?X
    value: int | str = 0

    def validate_structure(self) -> None:
        """Validate nibble side and value before direct analysis."""
        if not isinstance(self.high, bool):
            msg = "HexNibble high must be a boolean"
            raise TypeError(msg)
        if (
            isinstance(self.value, int)
            and not isinstance(self.value, bool)
            and 0 <= self.value <= 0xF
        ):
            return
        if isinstance(self.value, str) and len(self.value) == 1 and self.value in _HEX_CHARS:
            return
        msg = "HexNibble value must be a nibble"
        raise TypeError(msg)

    def accept(self, visitor: _VisitorType) -> Any:
        return visitor.visit_hex_nibble(self)


@dataclass(init=False)
class RegexString(StringDefinition):
    """Regular expression string."""

    regex: str = ""  # Add default

    def __init__(
        self,
        identifier: str,
        regex: str = "",
        modifiers: Any = _MISSING,
        *,
        is_anonymous: bool = False,
    ) -> None:
        modifier_values = [] if modifiers is _MISSING else modifiers
        super().__init__(
            identifier=identifier,
            modifiers=modifier_values,
            is_anonymous=is_anonymous,
        )
        self.regex = regex

    def validate_structure(self) -> None:
        """Validate regex string scalar fields before direct analysis."""
        super().validate_structure()
        regex = require_string(self.regex, "Regex string pattern")
        if not regex:
            msg = "RegexString regex must not be empty"
            raise ValueError(msg)
        _validate_regex_text(regex)

    def _validate_modifier_names(self, modifier_names: list[str]) -> None:
        super()._validate_modifier_names(modifier_names)
        for modifier_name in sorted(set(modifier_names) & _REGEX_DISALLOWED_MODIFIERS):
            msg = f"String modifier '{modifier_name}' is not valid on regex strings"
            raise ValueError(msg)

    def accept(self, visitor: _VisitorType) -> Any:
        return visitor.visit_regex_string(self)
