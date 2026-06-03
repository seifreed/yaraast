"""Layout strategies for the unified code generator.

:class:`CodeGenerator` owns the expression/leaf visitors and the output buffer;
the *structural* skeleton (file/rule/meta and the indentation policy) is supplied
by a composed :class:`GeneratorLayout` selected from :class:`GeneratorOptions`.
This keeps the genuinely distinct formatting engines (plain, comment-aware, and
later pretty/advanced) as small cohesive strategies instead of a class hierarchy
or a single mode-branching god-class.
"""

from __future__ import annotations

from typing import TYPE_CHECKING

from yaraast.codegen.generator_comment_sections import (
    comment_visit_rule,
    comment_visit_yara_file,
)
from yaraast.codegen.generator_formatting import format_meta_key, format_meta_literal
from yaraast.codegen.generator_leaf_visitors import visit_meta as render_meta
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
    """Structural rendering policy for :class:`CodeGenerator`."""

    def indent_string(self, gen: CodeGenerator) -> str:
        """Indentation prefix for the current depth."""
        return " " * (gen.indent_level * gen.indent_size)

    def visit_yara_file(self, gen: CodeGenerator, node: YaraFile) -> str:
        raise NotImplementedError

    def visit_rule(self, gen: CodeGenerator, node: Rule) -> str:
        raise NotImplementedError

    def visit_meta(self, gen: CodeGenerator, node: Meta) -> str:
        raise NotImplementedError


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
    if not options.blank_line_between_sections:
        return CommentLayout()
    return PlainLayout()
