"""Pretty-printing layout strategy for the unified code generator.

Wraps the existing pretty_printer_* helper modules so the aligned/wrapped
pretty engine plugs into :class:`CodeGenerator` via composition
(``GeneratorOptions.pretty``). Alignment state and the rich pretty options live
on the layout; alignment columns are precomputed in :meth:`prepare`.
"""

from __future__ import annotations

from typing import TYPE_CHECKING, Any

from yaraast.codegen.generator_formatting import (
    format_meta_key,
    format_meta_literal,
    validate_yara_file_collections,
)
from yaraast.codegen.layouts import GeneratorLayout
from yaraast.codegen.pretty_printer_helpers import (
    calculate_meta_alignment_column,
    calculate_string_alignment_column,
    current_indent,
)
from yaraast.codegen.pretty_printer_layout import (
    visit_rule as layout_visit_rule,
    visit_yara_file as layout_visit_yara_file,
    write_condition_section as layout_write_condition_section,
)
from yaraast.codegen.pretty_printer_sections import (
    write_meta_section as section_write_meta_section,
    write_strings_section as section_write_strings_section,
)

if TYPE_CHECKING:
    from yaraast.ast.base import YaraFile
    from yaraast.ast.comments import Comment
    from yaraast.ast.meta import Meta
    from yaraast.ast.rules import Rule
    from yaraast.codegen.generator import CodeGenerator
    from yaraast.codegen.pretty_printer import PrettyPrintOptions


class PrettyLayout(GeneratorLayout):
    """Aligned/wrapped pretty-printing engine as a composed layout."""

    def __init__(self, options: PrettyPrintOptions) -> None:
        self.options = options
        self._string_alignment_column = 0
        self._meta_alignment_column = 0

    def prepare(self, gen: CodeGenerator, node: Any) -> None:
        from yaraast.ast.base import YaraFile

        if not isinstance(node, YaraFile):
            return
        validate_yara_file_collections(node)
        if self.options.align_string_definitions:
            self._string_alignment_column = calculate_string_alignment_column(node)
        if self.options.align_meta_values:
            self._meta_alignment_column = calculate_meta_alignment_column(
                node,
                self.options.min_alignment_column,
            )

    def indent_string(self, gen: CodeGenerator) -> str:
        return current_indent(gen)

    def visit_yara_file(self, gen: CodeGenerator, node: YaraFile) -> str:
        return layout_visit_yara_file(gen, node)

    def visit_rule(self, gen: CodeGenerator, node: Rule) -> str:
        return layout_visit_rule(gen, node)

    def visit_meta(self, gen: CodeGenerator, node: Meta) -> str:
        gen._write(self.indent_string(gen))
        gen._write(f"{format_meta_key(node.key, getattr(node, 'scope', None))} = ")
        gen._write(format_meta_literal(node.value))
        return ""

    def write_meta_section(self, gen: CodeGenerator, meta: Any) -> None:
        section_write_meta_section(gen, meta)

    def write_strings_section(
        self, gen: CodeGenerator, strings: Any, *, has_condition: bool = False
    ) -> None:
        section_write_strings_section(gen, strings)

    def write_condition_section(self, gen: CodeGenerator, condition: Any) -> None:
        layout_write_condition_section(gen, condition)

    def write_single_comment(
        self, gen: CodeGenerator, comment: Comment, inline: bool = False
    ) -> None:
        if not inline:
            super().write_single_comment(gen, comment, inline)
            return

        text = comment.text
        if text.startswith("//"):
            text = text[2:].strip()
        elif text.startswith("/*") and text.endswith("*/"):
            text = text[2:-2].strip()

        spacing = max(0, self.options.inline_comment_spacing)
        if self.options.align_comments:
            current_line = gen.buffer.getvalue().rsplit("\n", 1)[-1]
            spacing = max(spacing, self.options.comment_column - len(current_line))
        gen._write(f"{' ' * spacing}// {text}")
