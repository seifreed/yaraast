"""Collection type definitions."""

from __future__ import annotations

from dataclasses import dataclass, field

from ._registry_base import YaraType


@dataclass
class StringSetType(YaraType):
    """String set type (for string identifiers)."""

    def __str__(self) -> str:
        return "string_set"

    def is_compatible_with(self, other: YaraType) -> bool:
        return isinstance(other, StringSetType)


@dataclass
class ArrayType(YaraType):
    """Array type."""

    element_type: YaraType

    def __str__(self) -> str:
        return f"array[{self.element_type}]"

    def is_compatible_with(self, other: YaraType) -> bool:
        return isinstance(other, ArrayType) and self.element_type.is_compatible_with(
            other.element_type,
        )


@dataclass
class DictionaryType(YaraType):
    """Dictionary type."""

    key_type: YaraType
    value_type: YaraType

    def __str__(self) -> str:
        return f"dict[{self.key_type}, {self.value_type}]"

    def is_compatible_with(self, other: YaraType) -> bool:
        return (
            isinstance(other, DictionaryType)
            and self.key_type.is_compatible_with(other.key_type)
            and self.value_type.is_compatible_with(other.value_type)
        )


@dataclass
class StructType(YaraType):
    """Struct type with named fields."""

    fields: dict[str, YaraType] = field(default_factory=dict)

    def __str__(self) -> str:
        return f"struct({', '.join(f'{k}: {v}' for k, v in self.fields.items())})"

    def is_compatible_with(self, other: YaraType) -> bool:
        if not isinstance(other, StructType):
            return False
        if set(self.fields.keys()) != set(other.fields.keys()):
            return False
        return all(
            field_type.is_compatible_with(other.fields[field_name])
            for field_name, field_type in self.fields.items()
        )
