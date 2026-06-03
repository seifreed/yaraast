"""Layout strategies for the unified code generator.

:class:`CodeGenerator` owns the expression/leaf visitors and the output buffer;
the *structural* skeleton (file/rule/meta and the indentation policy) is supplied
by a composed :class:`GeneratorLayout` selected from :class:`GeneratorOptions`.
This keeps the genuinely distinct formatting engines (plain, comment-aware, and
later pretty/advanced) as small cohesive strategies instead of a class hierarchy
or a single mode-branching god-class.
"""

from __future__ import annotations

from typing import TYPE_CHECKING, Any

from yaraast.codegen.generator_comment_sections import (
    comment_visit_rule,
    comment_visit_yara_file,
)
from yaraast.codegen.generator_formatting import format_meta_key, format_meta_literal
from yaraast.codegen.generator_leaf_visitors import visit_meta as render_meta
from yaraast.codegen.generator_sections import (
    write_condition_section as _plain_write_condition_section,
    write_hex_string as _plain_write_hex_string,
    write_meta_section as _plain_write_meta_section,
    write_plain_string as _plain_write_plain_string,
    write_regex_string as _plain_write_regex_string,
    write_strings_section as _plain_write_strings_section,
)
from yaraast.codegen.generator_structure_visitors import (
    visit_rule as render_rule,
    visit_yara_file as render_yara_file,
)

if TYPE_CHECKING:
    from yaraast.ast.base import YaraFile
    from yaraast.ast.meta import Meta
    from yaraast.ast.rules import Rule
    from yaraast.codegen.generator import CodeGenerator
    from yaraast.codegen.options import GeneratorOptions


class GeneratorLayout:
    """Structural rendering policy for :class:`CodeGenerator`.

    Defaults reproduce the plain engine; subclasses override the structural
    skeleton, the section writers, and the per-string renderers as needed.
    """

    def prepare(self, gen: CodeGenerator, node: Any) -> None:
        """Hook run by ``generate`` before visiting (alignment/state setup)."""

    def indent_string(self, gen: CodeGenerator) -> str:
        """Indentation prefix for the current depth."""
        return " " * (gen.indent_level * gen.indent_size)

    def visit_yara_file(self, gen: CodeGenerator, node: YaraFile) -> str:
        raise NotImplementedError

    def visit_rule(self, gen: CodeGenerator, node: Rule) -> str:
        raise NotImplementedError

    def visit_meta(self, gen: CodeGenerator, node: Meta) -> str:
        raise NotImplementedError

    # Section writers (plain defaults; advanced overrides)
    def write_meta_section(self, gen: CodeGenerator, meta: Any) -> None:
        _plain_write_meta_section(gen, meta)

    def write_strings_section(
        self, gen: CodeGenerator, strings: Any, *, has_condition: bool = False
    ) -> None:
        _plain_write_strings_section(gen, strings, has_condition=has_condition)

    def write_condition_section(self, gen: CodeGenerator, condition: Any) -> None:
        _plain_write_condition_section(gen, condition)

    # Per-string renderers (plain defaults; advanced overrides)
    def plain_string(self, gen: CodeGenerator, node: Any) -> str:
        return _plain_write_plain_string(gen, node)

    def hex_string(self, gen: CodeGenerator, node: Any) -> str:
        return _plain_write_hex_string(gen, node)

    def regex_string(self, gen: CodeGenerator, node: Any) -> str:
        return _plain_write_regex_string(gen, node)


class PlainLayout(GeneratorLayout):
    """Default layout: blank line between sections, raw comment passthrough."""

    def visit_yara_file(self, gen: CodeGenerator, node: YaraFile) -> str:
        return render_yara_file(gen, node)

    def visit_rule(self, gen: CodeGenerator, node: Rule) -> str:
        return render_rule(gen, node)

    def visit_meta(self, gen: CodeGenerator, node: Meta) -> str:
        return render_meta(node)


class CommentLayout(GeneratorLayout):
    """Comment-aware layout: preserves comments, no blank line between sections."""

    def visit_yara_file(self, gen: CodeGenerator, node: YaraFile) -> str:
        return comment_visit_yara_file(gen, node)

    def visit_rule(self, gen: CodeGenerator, node: Rule) -> str:
        return comment_visit_rule(gen, node)

    def visit_meta(self, gen: CodeGenerator, node: Meta) -> str:
        indent = self.indent_string(gen)
        gen._write(indent)
        gen._write(f"{format_meta_key(node.key, getattr(node, 'scope', None))} = ")
        gen._write(format_meta_literal(node.value))
        return ""


def select_layout(options: GeneratorOptions) -> GeneratorLayout:
    """Pick the structural layout strategy for the given options."""
    if options.advanced is not None:
        from yaraast.codegen.advanced_layout import AdvancedLayout

        return AdvancedLayout(options.advanced)
    if not options.blank_line_between_sections:
        return CommentLayout()
    return PlainLayout()
