"""String modifiers and other AST modifiers as proper enums."""

from dataclasses import dataclass
from enum import Enum
from typing import Any


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
    CASE = "case"  # Explicit case-sensitive (rare but valid)

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
        try:
            return cls(modifier_str.lower())
        except ValueError:
            # For unknown modifiers, we could either raise an error or create a custom type
            msg = f"Unknown string modifier: {modifier_str}"
            raise ValueError(msg) from None

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
        try:
            return cls(modifier_str.lower())
        except ValueError:
            msg = f"Unknown rule modifier: {modifier_str}"
            raise ValueError(msg) from None

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
        try:
            return cls(scope_str.lower())
        except ValueError:
            return cls.PUBLIC  # Default to public if unknown

    def __str__(self) -> str:
        return self.value


@dataclass
class StringModifier:
    """Enhanced string modifier with proper type safety."""

    modifier_type: StringModifierType
    value: str | int | float | None = None  # For modifiers that take parameters

    @classmethod
    def from_name_value(cls, name: str, value: Any | None = None) -> "StringModifier":
        """Create StringModifier from name and optional value."""
        modifier_type = StringModifierType.from_string(name)
        return cls(modifier_type=modifier_type, value=value)

    @property
    def name(self) -> str:
        """Get the modifier name for backward compatibility."""
        return self.modifier_type.value

    def __str__(self) -> str:
        """String representation of the modifier."""
        if self.value is not None:
            return f"{self.modifier_type.value}({self.value})"
        return self.modifier_type.value

    def to_legacy_modifier(self):
        """Convert to legacy StringModifier format."""
        from yaraast.ast.strings import StringModifier as LegacyStringModifier

        return LegacyStringModifier(name=self.name, value=self.value)


@dataclass
class RuleModifier:
    """Rule-level modifier with proper type safety."""

    modifier_type: RuleModifierType

    @classmethod
    def from_string(cls, modifier_str: str) -> "RuleModifier":
        """Create RuleModifier from string."""
        modifier_type = RuleModifierType.from_string(modifier_str)
        return cls(modifier_type=modifier_type)

    @property
    def name(self) -> str:
        """Get the modifier name for backward compatibility."""
        return self.modifier_type.value

    def __str__(self) -> str:
        return self.modifier_type.value


@dataclass
class MetaEntry:
    """Enhanced meta entry with scope support."""

    key: str
    value: Any
    scope: MetaScope = MetaScope.PUBLIC

    @classmethod
    def from_key_value(
        cls,
        key: str,
        value: Any,
        scope: str | None = None,
    ) -> "MetaEntry":
        """Create MetaEntry from key, value, and optional scope."""
        meta_scope = MetaScope.from_string(scope) if scope else MetaScope.PUBLIC
        return cls(key=key, value=value, scope=meta_scope)

    @property
    def is_private(self) -> bool:
        """Check if meta entry is private."""
        return self.scope == MetaScope.PRIVATE

    @property
    def is_public(self) -> bool:
        """Check if meta entry is public."""
        return self.scope == MetaScope.PUBLIC

    def __str__(self) -> str:
        """String representation of meta entry."""
        scope_prefix = f"{self.scope.value}:" if self.scope != MetaScope.PUBLIC else ""
        if isinstance(self.value, str):
            return f'{scope_prefix}{self.key} = "{self.value}"'
        return f"{scope_prefix}{self.key} = {self.value}"


# Convenience functions for creating modifiers
def create_string_modifier(name: str, value: Any | None = None) -> StringModifier:
    """Create a string modifier from name and optional value."""
    return StringModifier.from_name_value(name, value)


def create_rule_modifier(name: str) -> RuleModifier:
    """Create a rule modifier from name."""
    return RuleModifier.from_string(name)


def create_meta_entry(key: str, value: Any, scope: str | None = None) -> MetaEntry:
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


# Simple modifier classes for test compatibility
class Wide:
    """Wide string modifier."""

    def __init__(self) -> None:
        self.name = "wide"
        self.value = None

    def __str__(self) -> str:
        return "wide"


class Ascii:
    """ASCII string modifier."""

    def __init__(self) -> None:
        self.name = "ascii"
        self.value = None

    def __str__(self) -> str:
        return "ascii"


class Nocase:
    """Nocase string modifier."""

    def __init__(self) -> None:
        self.name = "nocase"
        self.value = None

    def __str__(self) -> str:
        return "nocase"
