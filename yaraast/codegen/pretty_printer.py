"""Enhanced pretty printer for YARA rules with formatting preservation."""

from __future__ import annotations

from dataclasses import dataclass
from io import StringIO
from typing import TYPE_CHECKING, Any

from yaraast.ast.strings import HexString, PlainString, RegexString, StringDefinition
from yaraast.codegen.comment_aware_generator import CommentAwareCodeGenerator
from yaraast.codegen.pretty_printer_helpers import (
    calculate_meta_alignment_column,
    calculate_string_alignment_column,
    expression_to_string,
)
from yaraast.codegen.pretty_printer_layout import visit_rule as layout_visit_rule
from yaraast.codegen.pretty_printer_layout import visit_yara_file as layout_visit_yara_file
from yaraast.codegen.pretty_printer_layout import (
    write_condition_section as layout_write_condition_section,
)
from yaraast.codegen.pretty_printer_layout import (
    write_string_definition as layout_write_string_definition,
)
from yaraast.codegen.pretty_printer_sections import (
    write_hex_string_aligned as section_write_hex_string_aligned,
)
from yaraast.codegen.pretty_printer_sections import write_meta_entry as section_write_meta_entry
from yaraast.codegen.pretty_printer_sections import write_meta_section as section_write_meta_section
from yaraast.codegen.pretty_printer_sections import (
    write_plain_string_aligned as section_write_plain_string_aligned,
)
from yaraast.codegen.pretty_printer_sections import (
    write_regex_string_aligned as section_write_regex_string_aligned,
)
from yaraast.codegen.pretty_printer_sections import (
    write_strings_section as section_write_strings_section,
)
from yaraast.codegen.pretty_printer_sections import (
    write_wrapped_condition as section_write_wrapped_condition,
)

if TYPE_CHECKING:
    from yaraast.ast.base import YaraFile
    from yaraast.ast.expressions import Expression
    from yaraast.ast.rules import Rule


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
    wrap_long_strings: bool = False

    # Sorting
    sort_imports: bool = True
    sort_includes: bool = True
    sort_meta_keys: bool = False
    sort_tags: bool = True

    # Style preferences
    compact_conditions: bool = False
    verbose_conditions: bool = False
    preserve_original_style: bool = False


class PrettyPrinter(CommentAwareCodeGenerator):
    """Enhanced pretty printer with advanced formatting options."""

    def __init__(self, options: PrettyPrintOptions | None = None) -> None:
        self.options = options or PrettyPrintOptions()
        super().__init__(
            indent_size=self.options.indent_size,
            preserve_comments=self.options.preserve_comments,
        )
        self._string_alignment_column = 0
        self._meta_alignment_column = 0

    def pretty_print(self, ast: YaraFile) -> str:
        """Pretty print the entire YARA file."""
        self.buffer = StringIO()
        self.indent_level = 0

        # Calculate alignment columns if needed
        if self.options.align_string_definitions:
            self._string_alignment_column = calculate_string_alignment_column(ast)
        if self.options.align_meta_values:
            self._meta_alignment_column = calculate_meta_alignment_column(
                ast,
                self.options.min_alignment_column,
            )

        return self.visit_yara_file(ast)

    def visit_yara_file(self, node: YaraFile) -> str:
        return layout_visit_yara_file(self, node)

    def visit_rule(self, node: Rule) -> str:
        return layout_visit_rule(self, node)

    def _write_meta_section(self, meta: dict[str, Any] | list[Any]) -> None:
        section_write_meta_section(self, meta)

    def _write_meta_entry(self, key: str, value: Any) -> None:
        section_write_meta_entry(self, key, value)

    def _write_strings_section(self, strings: list[StringDefinition]) -> None:
        section_write_strings_section(self, strings)

    def _write_string_definition(self, string_def: StringDefinition) -> None:
        layout_write_string_definition(self, string_def)

    def _write_plain_string_aligned(self, node: PlainString) -> None:
        section_write_plain_string_aligned(self, node)

    def _write_hex_string_aligned(self, node: HexString) -> None:
        section_write_hex_string_aligned(self, node)

    def _write_regex_string_aligned(self, node: RegexString) -> None:
        section_write_regex_string_aligned(self, node)

    def _write_condition_section(self, condition: Expression) -> None:
        layout_write_condition_section(self, condition)

    def _write_wrapped_condition(self, condition_str: str) -> None:
        section_write_wrapped_condition(self, condition_str)

    def _expression_to_string(self, expr: Expression) -> str:
        """Convert expression to string (simplified)."""
        # This is a simplified implementation
        # In practice, would use a separate visitor for expression serialization
        return expression_to_string(expr)


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
            compact_conditions=True,
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
            compact_conditions=True,
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
            verbose_conditions=True,
            max_line_length=140,
        )


# Convenience functions
def pretty_print(ast: YaraFile, options: PrettyPrintOptions | None = None) -> str:
    """Pretty print YARA AST with specified options."""
    printer = PrettyPrinter(options)
    return printer.pretty_print(ast)


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
