"""YARA-X feature flags and configuration."""

from dataclasses import dataclass
from typing import Any


class FeatureFlags:
    """Legacy feature flags class for compatibility."""

    SUPPORTS_FLOAT_MODULUS = True
    SUPPORTS_TUPLE_INDEXING = True
    SUPPORTS_WITH_STATEMENT = True
    SUPPORTS_ARRAY_COMPREHENSION = True
    SUPPORTS_DICT_COMPREHENSION = True


@dataclass
class YaraXFeatures:
    """Configuration for YARA-X specific features."""

    # Syntax features
    strict_regex_escaping: bool = True
    validate_escape_sequences: bool = True
    minimum_base64_length: int = 3
    allow_with_statement: bool = True
    allow_tuple_of_expressions: bool = True

    # Validation features
    disallow_duplicate_modifiers: bool = True
    strict_xor_fullword: bool = True
    validate_hex_bounds: bool = True

    # Parser features
    enhanced_error_messages: bool = True
    modular_parser: bool = True

    # Deprecated features
    deprecated_features: set[str] | None = None

    def __post_init__(self) -> None:
        if self.deprecated_features is None:
            self.deprecated_features = {
                "process_scanning",  # Not yet implemented in YARA-X
                "legacy_escape_sequences",  # Stricter validation
            }

    @classmethod
    def yara_compatible(cls) -> "YaraXFeatures":
        """Create configuration for YARA compatibility mode."""
        return cls(
            strict_regex_escaping=False,
            validate_escape_sequences=False,
            minimum_base64_length=0,
            allow_with_statement=False,
            allow_tuple_of_expressions=False,
            disallow_duplicate_modifiers=False,
            strict_xor_fullword=False,
            validate_hex_bounds=False,
            enhanced_error_messages=False,
            modular_parser=False,
        )

    @classmethod
    def yarax_strict(cls) -> "YaraXFeatures":
        """Create configuration for strict YARA-X mode."""
        return cls()  # All defaults are YARA-X strict

    def to_dict(self) -> dict[str, Any]:
        """Convert to dictionary."""
        return {
            "strict_regex_escaping": self.strict_regex_escaping,
            "validate_escape_sequences": self.validate_escape_sequences,
            "minimum_base64_length": self.minimum_base64_length,
            "allow_with_statement": self.allow_with_statement,
            "allow_tuple_of_expressions": self.allow_tuple_of_expressions,
            "disallow_duplicate_modifiers": self.disallow_duplicate_modifiers,
            "strict_xor_fullword": self.strict_xor_fullword,
            "validate_hex_bounds": self.validate_hex_bounds,
            "enhanced_error_messages": self.enhanced_error_messages,
            "modular_parser": self.modular_parser,
            "deprecated_features": (
                list(self.deprecated_features) if self.deprecated_features else []
            ),
        }
