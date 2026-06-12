"""String modifiers and other AST modifiers as proper enums."""

from dataclasses import dataclass
from enum import Enum
import math
from typing import Any

from yaraast.ast.base import ASTNode, _require_nonempty_string, _VisitorType, require_string
from yaraast.errors import ValidationError
from yaraast.string_escaping import escape_string_source_value
from yaraast.xor_keys import parse_xor_key_text


def _require_meta_value(value: Any) -> str | int | bool | float:
    if isinstance(value, str | bool | int):
        return value
    if isinstance(value, float) and math.isfinite(value):
        return value
    msg = "Meta value must be a string, integer, boolean, or finite float"
    raise TypeError(msg)


def _require_string_modifier_value(value: Any) -> str | int | float | tuple[int, int] | None:
    if value is None or isinstance(value, str):
        return value
    if isinstance(value, bool):
        msg = "StringModifier value must be a string, number, tuple, or null"
        raise TypeError(msg)
    if isinstance(value, int):
        return value
    if isinstance(value, float):
        if not math.isfinite(value):
            msg = "StringModifier value must be finite"
            raise ValueError(msg)
        return value
    if isinstance(value, tuple):
        if len(value) != 2:
            msg = "StringModifier tuple value must contain two integers"
            raise TypeError(msg)
        low, high = value
        if (
            isinstance(low, bool)
            or isinstance(high, bool)
            or not isinstance(low, int)
            or not isinstance(high, int)
        ):
            msg = "StringModifier tuple value must contain two integers"
            raise TypeError(msg)
        return (low, high)
    msg = "StringModifier value must be a string, number, tuple, or null"
    raise TypeError(msg)


def _require_string_modifier_type(value: Any) -> "StringModifierType":
    if not isinstance(value, StringModifierType):
        msg = "StringModifier modifier_type must be a StringModifierType"
        raise TypeError(msg)
    return value


def _require_rule_modifier_type(value: Any) -> "RuleModifierType":
    if not isinstance(value, RuleModifierType):
        msg = "RuleModifier modifier_type must be a RuleModifierType"
        raise TypeError(msg)
    return value


def _require_meta_scope(value: Any) -> "MetaScope":
    if not isinstance(value, MetaScope):
        msg = "Meta scope must be a MetaScope"
        raise TypeError(msg)
    return value


def _is_xor_modifier_text(value: str) -> bool:
    parts = value.split("-", maxsplit=1)
    keys: list[int] = []
    for part in parts:
        key = _parse_xor_key_text(part)
        if key is None:
            return False
        keys.append(key)
    return len(keys) == 1 or keys[0] <= keys[1]


def _parse_xor_key_text(value: str) -> int | None:
    key = parse_xor_key_text(value)
    if key is None:
        return None
    return key if 0 <= key <= 0xFF else None


class StringModifierType(Enum):
    """Enumeration of all YARA string modifiers."""

    # Character encoding modifiers
    ASCII = "ascii"
    WIDE = "wide"
    UTF8 = "utf8"
    UTF16 = "utf16"
    UTF16LE = "utf16le"
    UTF16BE = "utf16be"

    # Case sensitivity
    NOCASE = "nocase"
    CASE = "case"  # Dialect-specific explicit case-sensitive modifier
    DOTALL = "dotall"
    MULTILINE = "multiline"

    # String interpretation
    FULLWORD = "fullword"

    # Base64 encodings
    BASE64 = "base64"
    BASE64WIDE = "base64wide"

    # XOR encodings
    XOR = "xor"

    # Private modifier
    PRIVATE = "private"

    @classmethod
    def from_string(cls, modifier_str: str) -> "StringModifierType":
        """Convert string to modifier enum, handling case insensitivity."""
        modifier_text = require_string(modifier_str, "String modifier input")
        try:
            return cls(modifier_text.lower())
        except ValueError:
            # For unknown modifiers, we could either raise an error or create a custom type
            msg = f"Unknown string modifier: {modifier_text}"
            raise ValidationError(msg) from None

    def __str__(self) -> str:
        """Return the string representation."""
        return self.value


class RuleModifierType(Enum):
    """Enumeration of rule-level modifiers."""

    PRIVATE = "private"
    GLOBAL = "global"

    @classmethod
    def from_string(cls, modifier_str: str) -> "RuleModifierType":
        """Convert string to rule modifier enum."""
        modifier_text = require_string(modifier_str, "Rule modifier input")
        try:
            return cls(modifier_text.lower())
        except ValueError:
            msg = f"Unknown rule modifier: {modifier_text}"
            raise ValidationError(msg) from None

    def __str__(self) -> str:
        return self.value


class MetaScope(Enum):
    """Enumeration of meta key scopes."""

    PUBLIC = "public"  # Default scope - accessible from other rules
    PRIVATE = "private"  # Private scope - only accessible within the rule
    PROTECTED = "protected"  # Protected scope - accessible within module

    @classmethod
    def from_string(cls, scope_str: str) -> "MetaScope":
        """Convert string to meta scope enum."""
        scope_text = require_string(scope_str, "Meta scope input")
        if not scope_text.strip():
            msg = "Meta scope input cannot be empty"
            raise ValueError(msg)
        try:
            return cls(scope_text.lower())
        except ValueError:
            return cls.PUBLIC  # Default to public if unknown

    def __str__(self) -> str:
        return self.value


@dataclass
class StringModifier(ASTNode):
    """Enhanced string modifier with proper type safety."""

    modifier_type: StringModifierType
    value: str | int | float | tuple[int, int] | None = None

    def validate_structure(self) -> None:
        """Validate string modifier fields before direct analysis."""
        _require_string_modifier_type(self.modifier_type)
        _require_string_modifier_value(self.value)

    @classmethod
    def from_name_value(cls, name: str, value: Any | None = None) -> "StringModifier":
        """Create StringModifier from name and optional value."""
        modifier_type = StringModifierType.from_string(name)
        return cls(modifier_type=modifier_type, value=value)

    @property
    def name(self) -> str:
        """Get the modifier name for backward compatibility."""
        return _require_string_modifier_type(self.modifier_type).value

    def accept(self, visitor: _VisitorType) -> Any:
        return visitor.visit_string_modifier(self)

    def __str__(self) -> str:
        """String representation of the modifier."""
        modifier_type = _require_string_modifier_type(self.modifier_type)
        value = _require_string_modifier_value(self.value)
        if value is not None:
            if isinstance(value, tuple):
                return f"{modifier_type.value}({value[0]}-{value[1]})"
            if isinstance(value, str):
                if modifier_type == StringModifierType.XOR and _is_xor_modifier_text(value):
                    return f"{modifier_type.value}({value})"
                return f'{modifier_type.value}("{escape_string_source_value(value)}")'
            return f"{modifier_type.value}({value})"
        return modifier_type.value


@dataclass(frozen=True)
class RuleModifier:
    """Rule-level modifier with proper type safety."""

    modifier_type: RuleModifierType

    def validate_structure(self) -> None:
        """Validate rule modifier fields before direct analysis."""
        _require_rule_modifier_type(self.modifier_type)

    @classmethod
    def from_string(cls, modifier_str: str) -> "RuleModifier":
        """Create RuleModifier from string."""
        modifier_type = RuleModifierType.from_string(modifier_str)
        return cls(modifier_type=modifier_type)

    @property
    def name(self) -> str:
        """Get the modifier name for backward compatibility."""
        return _require_rule_modifier_type(self.modifier_type).value

    def __str__(self) -> str:
        return _require_rule_modifier_type(self.modifier_type).value


@dataclass
class MetaEntry:
    """Enhanced meta entry with scope support."""

    key: str
    value: str | int | bool | float
    scope: MetaScope = MetaScope.PUBLIC

    def validate_structure(self) -> None:
        """Validate meta entry fields before direct analysis."""
        _require_nonempty_string(self.key, "Meta key")
        _require_meta_value(self.value)
        _require_meta_scope(self.scope)

    @classmethod
    def from_key_value(
        cls,
        key: str,
        value: str | int | bool | float,
        scope: str | None = None,
    ) -> "MetaEntry":
        """Create MetaEntry from key, value, and optional scope."""
        meta_key = _require_nonempty_string(key, "Meta key")
        meta_value = _require_meta_value(value)
        meta_scope = MetaScope.from_string(scope) if scope is not None else MetaScope.PUBLIC
        return cls(key=meta_key, value=meta_value, scope=meta_scope)

    @property
    def is_private(self) -> bool:
        """Check if meta entry is private."""
        return _require_meta_scope(self.scope) == MetaScope.PRIVATE

    @property
    def is_public(self) -> bool:
        """Check if meta entry is public."""
        return _require_meta_scope(self.scope) == MetaScope.PUBLIC

    def __str__(self) -> str:
        """String representation of meta entry."""
        key = _require_nonempty_string(self.key, "Meta key")
        value = _require_meta_value(self.value)
        scope = _require_meta_scope(self.scope)
        scope_prefix = f"{scope.value}:" if scope != MetaScope.PUBLIC else ""
        if isinstance(value, str):
            return f'{scope_prefix}{key} = "{escape_string_source_value(value)}"'
        if isinstance(value, bool):
            bool_value = "true" if value else "false"
            return f"{scope_prefix}{key} = {bool_value}"
        return f"{scope_prefix}{key} = {value}"


# Convenience functions for creating modifiers
def create_string_modifier(name: str, value: Any | None = None) -> StringModifier:
    """Create a string modifier from name and optional value."""
    return StringModifier.from_name_value(name, value)


def create_rule_modifier(name: str) -> RuleModifier:
    """Create a rule modifier from name."""
    return RuleModifier.from_string(name)


def create_meta_entry(
    key: str,
    value: str | int | bool | float,
    scope: str | None = None,
) -> MetaEntry:
    """Create a meta entry with optional scope."""
    return MetaEntry.from_key_value(key, value, scope)


# Predefined common modifiers for convenience
class CommonStringModifiers:
    """Pre-defined common string modifiers."""

    ASCII = StringModifier(StringModifierType.ASCII)
    WIDE = StringModifier(StringModifierType.WIDE)
    NOCASE = StringModifier(StringModifierType.NOCASE)
    FULLWORD = StringModifier(StringModifierType.FULLWORD)
    BASE64 = StringModifier(StringModifierType.BASE64)
    BASE64WIDE = StringModifier(StringModifierType.BASE64WIDE)
    UTF8 = StringModifier(StringModifierType.UTF8)
    UTF16 = StringModifier(StringModifierType.UTF16)
    UTF16LE = StringModifier(StringModifierType.UTF16LE)
    UTF16BE = StringModifier(StringModifierType.UTF16BE)


class CommonRuleModifiers:
    """Pre-defined common rule modifiers."""

    PRIVATE = RuleModifier(RuleModifierType.PRIVATE)
    GLOBAL = RuleModifier(RuleModifierType.GLOBAL)
