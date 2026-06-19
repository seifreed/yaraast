"""Enhanced pretty printer for YARA rules with formatting preservation."""

from __future__ import annotations

from dataclasses import dataclass
from typing import TYPE_CHECKING

from yaraast.ast.base import require_yara_file
from yaraast.codegen.generator import CodeGenerator
from yaraast.codegen.generator_formatting import validate_yara_file_collections
from yaraast.codegen.options import GeneratorOptions

if TYPE_CHECKING:
    from yaraast.ast.base import YaraFile


@dataclass
class PrettyPrintOptions:
    """Options for pretty printing YARA rules."""

    # Indentation
    indent_size: int = 4
    indent_with_tabs: bool = False

    # Spacing
    blank_lines_before_rule: int = 2
    blank_lines_after_imports: int = 2
    blank_lines_after_includes: int = 1
    blank_lines_between_sections: int = 1
    space_around_operators: bool = True
    space_after_comma: bool = True

    # Alignment
    align_string_definitions: bool = True
    align_meta_values: bool = True
    align_comments: bool = True
    min_alignment_column: int = 40

    # Comments
    preserve_comments: bool = True
    comment_column: int = 60
    inline_comment_spacing: int = 2

    # String formatting
    quote_style: str = "double"  # "double", "single", "preserve"
    hex_uppercase: bool = True
    hex_spacing: bool = True

    # Line length and wrapping
    max_line_length: int = 120
    wrap_long_conditions: bool = True

    # Sorting
    sort_imports: bool = True
    sort_includes: bool = True
    sort_meta_keys: bool = False
    sort_tags: bool = True


class StylePresets:
    """Predefined style presets for different use cases."""

    @staticmethod
    def compact() -> PrettyPrintOptions:
        """Compact style for minimal whitespace."""
        return PrettyPrintOptions(
            blank_lines_before_rule=1,
            blank_lines_after_imports=1,
            blank_lines_after_includes=0,
            blank_lines_between_sections=0,
            align_string_definitions=False,
            align_meta_values=False,
            max_line_length=80,
        )

    @staticmethod
    def readable() -> PrettyPrintOptions:
        """Readable style with good spacing and alignment."""
        return PrettyPrintOptions(
            blank_lines_before_rule=2,
            blank_lines_after_imports=2,
            blank_lines_after_includes=1,
            blank_lines_between_sections=1,
            align_string_definitions=True,
            align_meta_values=True,
            align_comments=True,
            max_line_length=120,
        )

    @staticmethod
    def dense() -> PrettyPrintOptions:
        """Dense style for large files."""
        return PrettyPrintOptions(
            blank_lines_before_rule=1,
            blank_lines_after_imports=1,
            blank_lines_after_includes=0,
            blank_lines_between_sections=0,
            align_string_definitions=True,
            align_meta_values=False,
            max_line_length=100,
        )

    @staticmethod
    def verbose() -> PrettyPrintOptions:
        """Verbose style with extensive spacing."""
        return PrettyPrintOptions(
            blank_lines_before_rule=3,
            blank_lines_after_imports=3,
            blank_lines_after_includes=2,
            blank_lines_between_sections=2,
            align_string_definitions=True,
            align_meta_values=True,
            align_comments=True,
            max_line_length=140,
        )


# Convenience functions
def pretty_print(ast: YaraFile, options: PrettyPrintOptions | None = None) -> str:
    """Pretty print YARA AST with specified options."""
    ast = require_yara_file(ast, "ast")
    validate_yara_file_collections(ast)
    return CodeGenerator(options=GeneratorOptions(pretty=options or PrettyPrintOptions())).generate(
        ast
    )


def pretty_print_compact(ast: YaraFile) -> str:
    """Pretty print with compact style."""
    return pretty_print(ast, StylePresets.compact())


def pretty_print_readable(ast: YaraFile) -> str:
    """Pretty print with readable style."""
    return pretty_print(ast, StylePresets.readable())


def pretty_print_dense(ast: YaraFile) -> str:
    """Pretty print with dense style."""
    return pretty_print(ast, StylePresets.dense())


def pretty_print_verbose(ast: YaraFile) -> str:
    """Pretty print with verbose style."""
    return pretty_print(ast, StylePresets.verbose())
