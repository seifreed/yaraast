"""Formatting configuration for code generation."""

from __future__ import annotations

from collections.abc import Mapping
from dataclasses import dataclass, field
from enum import Enum


def _coerce_enum[EnumT: Enum](enum_type: type[EnumT], value: object, default: EnumT) -> EnumT:
    try:
        return enum_type(value)
    except (TypeError, ValueError):
        return default


def _coerce_bool(value: object, default: bool) -> bool:
    if isinstance(value, bool):
        return value
    return default


def _coerce_int(value: object, default: int, *, minimum: int | None = None) -> int:
    if isinstance(value, bool):
        return default
    if isinstance(value, int):
        result = value
    elif isinstance(value, str):
        try:
            result = int(value)
        except ValueError:
            return default
    else:
        return default
    if minimum is not None:
        return max(minimum, result)
    return result


_RULE_SECTIONS = frozenset({"meta", "strings", "condition"})


def _coerce_section_order(value: object, default: list[str]) -> list[str]:
    if (
        isinstance(value, list)
        and all(isinstance(section, str) for section in value)
        and len(value) == len(_RULE_SECTIONS)
        and set(value) == _RULE_SECTIONS
    ):
        return list(value)
    return default


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

    def to_dict(self) -> dict[str, object]:
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
    def from_dict(cls, data: object) -> FormattingConfig:
        """Create config from dictionary."""
        config = cls()
        if not isinstance(data, Mapping):
            return config

        if "indent_style" in data:
            config.indent_style = _coerce_enum(
                IndentStyle, data["indent_style"], config.indent_style
            )
        if "indent_size" in data:
            config.indent_size = _coerce_int(data["indent_size"], config.indent_size, minimum=0)
        if "brace_style" in data:
            config.brace_style = _coerce_enum(BraceStyle, data["brace_style"], config.brace_style)
        if "space_before_colon" in data:
            config.space_before_colon = _coerce_bool(
                data["space_before_colon"], config.space_before_colon
            )
        if "space_after_colon" in data:
            config.space_after_colon = _coerce_bool(
                data["space_after_colon"], config.space_after_colon
            )
        if "space_around_operators" in data:
            config.space_around_operators = _coerce_bool(
                data["space_around_operators"], config.space_around_operators
            )
        if "space_after_comma" in data:
            config.space_after_comma = _coerce_bool(
                data["space_after_comma"], config.space_after_comma
            )
        if "string_style" in data:
            config.string_style = _coerce_enum(
                StringStyle, data["string_style"], config.string_style
            )
        if "align_string_modifiers" in data:
            config.align_string_modifiers = _coerce_bool(
                data["align_string_modifiers"], config.align_string_modifiers
            )
        if "hex_style" in data:
            config.hex_style = _coerce_enum(HexStyle, data["hex_style"], config.hex_style)
        if "hex_group_size" in data:
            config.hex_group_size = _coerce_int(
                data["hex_group_size"], config.hex_group_size, minimum=0
            )
        if "blank_lines_between_rules" in data:
            config.blank_lines_between_rules = _coerce_int(
                data["blank_lines_between_rules"], config.blank_lines_between_rules, minimum=0
            )
        if "blank_lines_between_sections" in data:
            config.blank_lines_between_sections = _coerce_int(
                data["blank_lines_between_sections"],
                config.blank_lines_between_sections,
                minimum=0,
            )
        if "max_line_length" in data:
            config.max_line_length = _coerce_int(
                data["max_line_length"], config.max_line_length, minimum=1
            )
        if "sort_imports" in data:
            config.sort_imports = _coerce_bool(data["sort_imports"], config.sort_imports)
        if "sort_rules" in data:
            config.sort_rules = _coerce_bool(data["sort_rules"], config.sort_rules)
        if "sort_meta" in data:
            config.sort_meta = _coerce_bool(data["sort_meta"], config.sort_meta)
        if "sort_strings" in data:
            config.sort_strings = _coerce_bool(data["sort_strings"], config.sort_strings)
        if "section_order" in data:
            config.section_order = _coerce_section_order(
                data["section_order"], config.section_order
            )
        if "preserve_comments" in data:
            config.preserve_comments = _coerce_bool(
                data["preserve_comments"], config.preserve_comments
            )
        if "comment_style" in data:
            comment_style = data["comment_style"]
            if isinstance(comment_style, str):
                config.comment_style = comment_style

        return config

    @classmethod
    def compact(cls) -> FormattingConfig:
        """Create compact formatting config."""
        return PredefinedStyles.compact()


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
