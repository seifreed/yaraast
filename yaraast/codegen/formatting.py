"""Formatting configuration for code generation."""

from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum


class IndentStyle(Enum):
    """Indentation style."""

    SPACES = "spaces"
    TABS = "tabs"


class BraceStyle(Enum):
    """Brace placement style."""

    SAME_LINE = "same_line"
    NEW_LINE = "new_line"
    K_AND_R = "k_and_r"


class StringStyle(Enum):
    """String definition style."""

    COMPACT = "compact"
    ALIGNED = "aligned"
    TABULAR = "tabular"


class HexStyle(Enum):
    """Hex string formatting style."""

    LOWERCASE = "lowercase"
    UPPERCASE = "uppercase"


@dataclass
class FormattingConfig:
    """Configuration for code formatting."""

    # Indentation
    indent_style: IndentStyle = IndentStyle.SPACES
    indent_size: int = 4

    # Brace style
    brace_style: BraceStyle = BraceStyle.SAME_LINE

    # Spacing
    space_before_colon: bool = True
    space_after_colon: bool = True
    space_around_operators: bool = True
    space_after_comma: bool = True

    # String formatting
    string_style: StringStyle = StringStyle.ALIGNED
    align_string_modifiers: bool = True

    # Hex formatting
    hex_style: HexStyle = HexStyle.LOWERCASE
    hex_group_size: int = 0  # 0 = no grouping

    # Line breaks
    blank_lines_between_rules: int = 1
    blank_lines_between_sections: int = 1
    max_line_length: int = 120

    # Sorting
    sort_imports: bool = False
    sort_rules: bool = False
    sort_meta: bool = False
    sort_strings: bool = False

    # Section order
    section_order: list[str] = field(
        default_factory=lambda: ["meta", "strings", "condition"],
    )

    # Comments
    preserve_comments: bool = True
    comment_style: str = "//"  # or "/*"

    def to_dict(self) -> dict:
        """Convert config to dictionary."""
        return {
            "indent_style": self.indent_style.value,
            "indent_size": self.indent_size,
            "brace_style": self.brace_style.value,
            "space_before_colon": self.space_before_colon,
            "space_after_colon": self.space_after_colon,
            "space_around_operators": self.space_around_operators,
            "space_after_comma": self.space_after_comma,
            "string_style": self.string_style.value,
            "align_string_modifiers": self.align_string_modifiers,
            "hex_style": self.hex_style.value,
            "hex_group_size": self.hex_group_size,
            "blank_lines_between_rules": self.blank_lines_between_rules,
            "blank_lines_between_sections": self.blank_lines_between_sections,
            "max_line_length": self.max_line_length,
            "sort_imports": self.sort_imports,
            "sort_rules": self.sort_rules,
            "sort_meta": self.sort_meta,
            "sort_strings": self.sort_strings,
            "section_order": self.section_order,
            "preserve_comments": self.preserve_comments,
            "comment_style": self.comment_style,
        }

    @classmethod
    def from_dict(cls, data: dict) -> FormattingConfig:
        """Create config from dictionary."""
        config = cls()

        if "indent_style" in data:
            config.indent_style = IndentStyle(data["indent_style"])
        if "indent_size" in data:
            config.indent_size = data["indent_size"]
        if "brace_style" in data:
            config.brace_style = BraceStyle(data["brace_style"])
        if "space_before_colon" in data:
            config.space_before_colon = data["space_before_colon"]
        if "space_after_colon" in data:
            config.space_after_colon = data["space_after_colon"]
        if "space_around_operators" in data:
            config.space_around_operators = data["space_around_operators"]
        if "space_after_comma" in data:
            config.space_after_comma = data["space_after_comma"]
        if "string_style" in data:
            config.string_style = StringStyle(data["string_style"])
        if "align_string_modifiers" in data:
            config.align_string_modifiers = data["align_string_modifiers"]
        if "hex_style" in data:
            config.hex_style = HexStyle(data["hex_style"])
        if "hex_group_size" in data:
            config.hex_group_size = data["hex_group_size"]
        if "blank_lines_between_rules" in data:
            config.blank_lines_between_rules = data["blank_lines_between_rules"]
        if "blank_lines_between_sections" in data:
            config.blank_lines_between_sections = data["blank_lines_between_sections"]
        if "max_line_length" in data:
            config.max_line_length = data["max_line_length"]
        if "sort_imports" in data:
            config.sort_imports = data["sort_imports"]
        if "sort_rules" in data:
            config.sort_rules = data["sort_rules"]
        if "sort_meta" in data:
            config.sort_meta = data["sort_meta"]
        if "sort_strings" in data:
            config.sort_strings = data["sort_strings"]
        if "section_order" in data:
            config.section_order = data["section_order"]
        if "preserve_comments" in data:
            config.preserve_comments = data["preserve_comments"]
        if "comment_style" in data:
            config.comment_style = data["comment_style"]

        return config


# Predefined styles
class PredefinedStyles:
    """Predefined formatting styles."""

    @staticmethod
    def compact() -> FormattingConfig:
        """Compact style - minimal spacing."""
        return FormattingConfig(
            indent_size=2,
            brace_style=BraceStyle.SAME_LINE,
            space_before_colon=False,
            space_after_colon=False,
            space_around_operators=False,
            space_after_comma=False,
            string_style=StringStyle.COMPACT,
            blank_lines_between_rules=0,
            blank_lines_between_sections=0,
        )

    @staticmethod
    def readable() -> FormattingConfig:
        """Readable style - balanced spacing."""
        return FormattingConfig(
            indent_size=4,
            brace_style=BraceStyle.SAME_LINE,
            space_before_colon=True,
            space_after_colon=True,
            space_around_operators=True,
            space_after_comma=True,
            string_style=StringStyle.ALIGNED,
            blank_lines_between_rules=1,
            blank_lines_between_sections=1,
        )

    @staticmethod
    def verbose() -> FormattingConfig:
        """Verbose style - maximum readability."""
        return FormattingConfig(
            indent_size=4,
            brace_style=BraceStyle.NEW_LINE,
            space_before_colon=True,
            space_after_colon=True,
            space_around_operators=True,
            space_after_comma=True,
            string_style=StringStyle.TABULAR,
            align_string_modifiers=True,
            blank_lines_between_rules=2,
            blank_lines_between_sections=1,
            sort_imports=True,
            sort_meta=True,
            sort_strings=True,
        )

    @staticmethod
    def yara_default() -> FormattingConfig:
        """Default YARA style."""
        return FormattingConfig(
            indent_size=2,
            brace_style=BraceStyle.SAME_LINE,
            space_before_colon=True,
            space_after_colon=True,
            space_around_operators=True,
            space_after_comma=True,
            string_style=StringStyle.ALIGNED,
        )
