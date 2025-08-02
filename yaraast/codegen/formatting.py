"""Formatting configuration for code generation."""

from dataclasses import dataclass, field
from enum import Enum
from typing import Any


class IndentStyle(Enum):
    """Indentation style."""

    SPACES = "spaces"
    TABS = "tabs"


class BraceStyle(Enum):
    """Brace placement style."""

    SAME_LINE = "same_line"  # rule test {
    NEW_LINE = "new_line"  # rule test\n{
    K_AND_R = "k_and_r"  # rule test\n{


class StringStyle(Enum):
    """String definition style."""

    COMPACT = "compact"  # $a="test" $b="test2"
    ALIGNED = "aligned"  # $a = "test"\n$b = "test2"
    TABULAR = "tabular"  # $a     = "test"\n$long  = "test2"


class HexStyle(Enum):
    """Hex string formatting style."""

    UPPERCASE = "uppercase"  # { 48 45 4C 4C 4F }
    LOWERCASE = "lowercase"  # { 48 65 6c 6c 6f }
    GROUPED = "grouped"  # { 48656C6C 6F }
    SPACED = "spaced"  # { 48 65 6C 6C 6F }


@dataclass
class FormattingConfig:
    """Configuration for code formatting."""

    # Indentation
    indent_style: IndentStyle = IndentStyle.SPACES
    indent_size: int = 4
    tab_size: int = 4

    # Braces
    brace_style: BraceStyle = BraceStyle.SAME_LINE

    # Spacing
    space_before_colon: bool = True  # rule test : tag
    space_after_colon: bool = True  # rule : tag
    space_around_operators: bool = True  # a and b vs a and b
    space_after_comma: bool = True  # (a, b) vs (a,b)
    blank_lines_between_rules: int = 2
    blank_lines_between_sections: int = 1

    # String formatting
    string_style: StringStyle = StringStyle.ALIGNED
    align_string_modifiers: bool = True
    max_line_length: int = 100

    # Hex formatting
    hex_style: HexStyle = HexStyle.UPPERCASE
    hex_bytes_per_line: int = 16
    hex_group_size: int = 0  # 0 = no grouping

    # Comments
    preserve_comments: bool = True
    comment_style: str = "//"  # or "/* */"

    # Ordering
    sort_imports: bool = True
    sort_rules: bool = False
    sort_strings: bool = False
    sort_meta: bool = False

    # Rule sections
    section_order: list[str] = field(default_factory=lambda: ["meta", "strings", "condition"])
    require_all_sections: bool = False

    @classmethod
    def compact(cls) -> "FormattingConfig":
        """Create compact formatting config."""
        return cls(
            indent_size=2,
            blank_lines_between_rules=1,
            blank_lines_between_sections=0,
            string_style=StringStyle.COMPACT,
            max_line_length=120,
        )

    @classmethod
    def expanded(cls) -> "FormattingConfig":
        """Create expanded formatting config."""
        return cls(
            indent_size=4,
            blank_lines_between_rules=3,
            blank_lines_between_sections=2,
            string_style=StringStyle.TABULAR,
            brace_style=BraceStyle.NEW_LINE,
        )

    @classmethod
    def k_and_r(cls) -> "FormattingConfig":
        """Create K&R style formatting config."""
        return cls(
            brace_style=BraceStyle.K_AND_R,
            space_before_colon=True,
            string_style=StringStyle.ALIGNED,
        )

    def to_dict(self) -> dict[str, Any]:
        """Convert config to dictionary."""
        return {
            "indent_style": self.indent_style.value,
            "indent_size": self.indent_size,
            "tab_size": self.tab_size,
            "brace_style": self.brace_style.value,
            "space_before_colon": self.space_before_colon,
            "space_after_colon": self.space_after_colon,
            "space_around_operators": self.space_around_operators,
            "space_after_comma": self.space_after_comma,
            "blank_lines_between_rules": self.blank_lines_between_rules,
            "blank_lines_between_sections": self.blank_lines_between_sections,
            "string_style": self.string_style.value,
            "align_string_modifiers": self.align_string_modifiers,
            "max_line_length": self.max_line_length,
            "hex_style": self.hex_style.value,
            "hex_bytes_per_line": self.hex_bytes_per_line,
            "hex_group_size": self.hex_group_size,
            "preserve_comments": self.preserve_comments,
            "comment_style": self.comment_style,
            "sort_imports": self.sort_imports,
            "sort_rules": self.sort_rules,
            "sort_strings": self.sort_strings,
            "sort_meta": self.sort_meta,
            "section_order": self.section_order,
            "require_all_sections": self.require_all_sections,
        }

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> "FormattingConfig":
        """Create config from dictionary."""
        config = cls()

        if "indent_style" in data:
            config.indent_style = IndentStyle(data["indent_style"])
        if "indent_size" in data:
            config.indent_size = data["indent_size"]
        if "tab_size" in data:
            config.tab_size = data["tab_size"]

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

        if "blank_lines_between_rules" in data:
            config.blank_lines_between_rules = data["blank_lines_between_rules"]
        if "blank_lines_between_sections" in data:
            config.blank_lines_between_sections = data["blank_lines_between_sections"]

        if "string_style" in data:
            config.string_style = StringStyle(data["string_style"])
        if "align_string_modifiers" in data:
            config.align_string_modifiers = data["align_string_modifiers"]
        if "max_line_length" in data:
            config.max_line_length = data["max_line_length"]

        if "hex_style" in data:
            config.hex_style = HexStyle(data["hex_style"])
        if "hex_bytes_per_line" in data:
            config.hex_bytes_per_line = data["hex_bytes_per_line"]
        if "hex_group_size" in data:
            config.hex_group_size = data["hex_group_size"]

        if "preserve_comments" in data:
            config.preserve_comments = data["preserve_comments"]
        if "comment_style" in data:
            config.comment_style = data["comment_style"]

        if "sort_imports" in data:
            config.sort_imports = data["sort_imports"]
        if "sort_rules" in data:
            config.sort_rules = data["sort_rules"]
        if "sort_strings" in data:
            config.sort_strings = data["sort_strings"]
        if "sort_meta" in data:
            config.sort_meta = data["sort_meta"]

        if "section_order" in data:
            config.section_order = data["section_order"]
        if "require_all_sections" in data:
            config.require_all_sections = data["require_all_sections"]

        return config
