"""Primitive type definitions."""

from __future__ import annotations

from dataclasses import dataclass

from ._registry_base import YaraType


@dataclass
class IntegerType(YaraType):
    """Integer type."""

    def __str__(self) -> str:
        return "integer"

    def is_compatible_with(self, other: YaraType) -> bool:
        return isinstance(other, IntegerType | DoubleType | FloatType)

    def is_numeric(self) -> bool:
        return True


@dataclass
class DoubleType(YaraType):
    """Double/float type."""

    def __str__(self) -> str:
        return "double"

    def is_compatible_with(self, other: YaraType) -> bool:
        return isinstance(other, IntegerType | DoubleType | FloatType)

    def is_numeric(self) -> bool:
        return True


@dataclass
class StringType(YaraType):
    """String type."""

    def __str__(self) -> str:
        return "string"

    def is_compatible_with(self, other: YaraType) -> bool:
        return isinstance(other, StringType)

    def is_string_like(self) -> bool:
        return True


@dataclass
class BooleanType(YaraType):
    """Boolean type."""

    def __str__(self) -> str:
        return "boolean"

    def is_compatible_with(self, other: YaraType) -> bool:
        return isinstance(other, BooleanType)


@dataclass
class RangeType(YaraType):
    """Range type."""

    def __str__(self) -> str:
        return "range"

    def is_compatible_with(self, other: YaraType) -> bool:
        return isinstance(other, RangeType)


@dataclass
class RegexType(YaraType):
    """Regex type."""

    def __str__(self) -> str:
        return "regex"

    def is_compatible_with(self, other: YaraType) -> bool:
        return isinstance(other, RegexType | StringType)

    def is_string_like(self) -> bool:
        return True


@dataclass
class StringIdentifierType(YaraType):
    """String identifier type ($a, $b, etc.)."""

    def __str__(self) -> str:
        return "string_identifier"

    def is_compatible_with(self, other: YaraType) -> bool:
        return isinstance(other, StringType | RegexType | StringIdentifierType | BooleanType)

    def is_string_like(self) -> bool:
        return True


@dataclass
class AnyType(YaraType):
    """Any type (variable or unspecified)."""

    def __str__(self) -> str:
        return "any"

    def is_compatible_with(self, other: YaraType) -> bool:
        return True


@dataclass
class FloatType(YaraType):
    """Float type (alias for double)."""

    def __str__(self) -> str:
        return "float"

    def is_compatible_with(self, other: YaraType) -> bool:
        return isinstance(other, FloatType | DoubleType | IntegerType)

    def is_numeric(self) -> bool:
        return True


@dataclass
class UnknownType(YaraType):
    """Unknown type (for unresolved references)."""

    def __str__(self) -> str:
        return "unknown"

    def is_compatible_with(self, other: YaraType) -> bool:
        return True
