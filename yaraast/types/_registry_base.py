"""Base types for type registry."""

from __future__ import annotations

from abc import ABC, abstractmethod
from typing import ClassVar


class YaraType(ABC):
    """Base class for YARA types."""

    INTEGER: ClassVar[YaraType]
    STRING: ClassVar[YaraType]
    BOOLEAN: ClassVar[YaraType]
    DOUBLE: ClassVar[YaraType]
    REGEX: ClassVar[YaraType]
    UNKNOWN: ClassVar[YaraType]

    @abstractmethod
    def __str__(self) -> str:
        """String representation of the type."""

    @abstractmethod
    def is_compatible_with(self, other: YaraType) -> bool:
        """Check if this type is compatible with another."""

    def is_numeric(self) -> bool:
        """Check if this is a numeric type."""
        return False

    def is_string_like(self) -> bool:
        """Check if this is a string-like type."""
        return False
