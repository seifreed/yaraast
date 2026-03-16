"""Models for round-trip serialization."""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any


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
    def from_dict(cls, data: dict[str, Any]) -> FormattingInfo:
        """Create from dictionary."""
        return cls(**data)


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
    def from_dict(cls, data: dict[str, Any]) -> RoundTripMetadata:
        """Create from dictionary."""
        formatting_data = data.get("formatting", {})
        formatting = FormattingInfo.from_dict(formatting_data)

        return cls(
            original_source=data.get("original_source"),
            source_file=data.get("source_file"),
            parsed_at=data.get("parsed_at"),
            serializer_version=data.get("serializer_version", "1.0.0"),
            formatting=formatting,
            comments_preserved=data.get("comments_preserved", True),
            formatting_preserved=data.get("formatting_preserved", True),
            parser_version=data.get("parser_version"),
        )
