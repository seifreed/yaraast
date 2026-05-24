"""Models for round-trip serialization."""

from __future__ import annotations

from collections.abc import Mapping
from dataclasses import dataclass, field
from typing import Any

from yaraast.errors import SerializationError


def _deserialize_object(data: object, context: str) -> Mapping[str, object]:
    if isinstance(data, Mapping):
        return data
    msg = f"{context} must be an object"
    raise SerializationError(msg)


def _deserialize_string_field(
    data: Mapping[str, object],
    field_name: str,
    default: str,
    context: str,
) -> str:
    value = data.get(field_name, default)
    if isinstance(value, str):
        return value
    msg = f"{context} {field_name} must be a string"
    raise SerializationError(msg)


def _deserialize_nullable_string_field(
    data: Mapping[str, object],
    field_name: str,
    context: str,
) -> str | None:
    value = data.get(field_name)
    if value is None or isinstance(value, str):
        return value
    msg = f"{context} {field_name} must be a string"
    raise SerializationError(msg)


def _deserialize_int_field(
    data: Mapping[str, object],
    field_name: str,
    default: int,
    context: str,
) -> int:
    value = data.get(field_name, default)
    if isinstance(value, int) and not isinstance(value, bool):
        return value
    msg = f"{context} {field_name} must be an integer"
    raise SerializationError(msg)


def _deserialize_bool_field(
    data: Mapping[str, object],
    field_name: str,
    default: bool,
    context: str,
) -> bool:
    value = data.get(field_name, default)
    if isinstance(value, bool):
        return value
    msg = f"{context} {field_name} must be a boolean"
    raise SerializationError(msg)


@dataclass
class FormattingInfo:
    """Information about original formatting to preserve."""

    indent_size: int = 4
    indent_style: str = "spaces"  # "spaces" or "tabs"
    line_endings: str = "\n"  # "\n", "\r\n", or "\r"
    blank_lines_before_rule: int = 1
    blank_lines_after_imports: int = 1
    blank_lines_after_includes: int = 1
    comment_style: str = "line"  # "line" (//) or "block" (/* */)
    preserve_spacing: bool = True
    preserve_alignment: bool = True

    def to_dict(self) -> dict[str, Any]:
        """Convert to dictionary for serialization."""
        return {
            "indent_size": self.indent_size,
            "indent_style": self.indent_style,
            "line_endings": self.line_endings,
            "blank_lines_before_rule": self.blank_lines_before_rule,
            "blank_lines_after_imports": self.blank_lines_after_imports,
            "blank_lines_after_includes": self.blank_lines_after_includes,
            "comment_style": self.comment_style,
            "preserve_spacing": self.preserve_spacing,
            "preserve_alignment": self.preserve_alignment,
        }

    @classmethod
    def from_dict(cls, data: object) -> FormattingInfo:
        """Create from dictionary."""
        mapping = _deserialize_object(data, "FormattingInfo")
        defaults = cls()
        return cls(
            indent_size=_deserialize_int_field(
                mapping, "indent_size", defaults.indent_size, "FormattingInfo"
            ),
            indent_style=_deserialize_string_field(
                mapping, "indent_style", defaults.indent_style, "FormattingInfo"
            ),
            line_endings=_deserialize_string_field(
                mapping, "line_endings", defaults.line_endings, "FormattingInfo"
            ),
            blank_lines_before_rule=_deserialize_int_field(
                mapping,
                "blank_lines_before_rule",
                defaults.blank_lines_before_rule,
                "FormattingInfo",
            ),
            blank_lines_after_imports=_deserialize_int_field(
                mapping,
                "blank_lines_after_imports",
                defaults.blank_lines_after_imports,
                "FormattingInfo",
            ),
            blank_lines_after_includes=_deserialize_int_field(
                mapping,
                "blank_lines_after_includes",
                defaults.blank_lines_after_includes,
                "FormattingInfo",
            ),
            comment_style=_deserialize_string_field(
                mapping, "comment_style", defaults.comment_style, "FormattingInfo"
            ),
            preserve_spacing=_deserialize_bool_field(
                mapping, "preserve_spacing", defaults.preserve_spacing, "FormattingInfo"
            ),
            preserve_alignment=_deserialize_bool_field(
                mapping, "preserve_alignment", defaults.preserve_alignment, "FormattingInfo"
            ),
        )


@dataclass
class RoundTripMetadata:
    """Metadata for round-trip serialization."""

    original_source: str | None = None
    source_file: str | None = None
    parsed_at: str | None = None
    serializer_version: str = "1.0.0"
    formatting: FormattingInfo = field(default_factory=FormattingInfo)
    comments_preserved: bool = True
    formatting_preserved: bool = True
    parser_version: str | None = None

    def to_dict(self) -> dict[str, Any]:
        """Convert to dictionary for serialization."""
        return {
            "original_source": self.original_source,
            "source_file": self.source_file,
            "parsed_at": self.parsed_at,
            "serializer_version": self.serializer_version,
            "formatting": self.formatting.to_dict(),
            "comments_preserved": self.comments_preserved,
            "formatting_preserved": self.formatting_preserved,
            "parser_version": self.parser_version,
        }

    @classmethod
    def from_dict(cls, data: object) -> RoundTripMetadata:
        """Create from dictionary."""
        mapping = _deserialize_object(data, "RoundTripMetadata")
        formatting_data = mapping.get("formatting", {})
        formatting = FormattingInfo.from_dict(formatting_data)

        return cls(
            original_source=_deserialize_nullable_string_field(
                mapping, "original_source", "RoundTripMetadata"
            ),
            source_file=_deserialize_nullable_string_field(
                mapping, "source_file", "RoundTripMetadata"
            ),
            parsed_at=_deserialize_nullable_string_field(mapping, "parsed_at", "RoundTripMetadata"),
            serializer_version=_deserialize_string_field(
                mapping, "serializer_version", "1.0.0", "RoundTripMetadata"
            ),
            formatting=formatting,
            comments_preserved=_deserialize_bool_field(
                mapping, "comments_preserved", True, "RoundTripMetadata"
            ),
            formatting_preserved=_deserialize_bool_field(
                mapping, "formatting_preserved", True, "RoundTripMetadata"
            ),
            parser_version=_deserialize_nullable_string_field(
                mapping, "parser_version", "RoundTripMetadata"
            ),
        )
