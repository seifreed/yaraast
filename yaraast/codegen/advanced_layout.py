"""Advanced layout strategy for the unified code generator.

Wraps the existing advanced_generator_* helper modules so that the configurable
formatting engine plugs into :class:`CodeGenerator` via composition
(``GeneratorOptions.advanced``) instead of a subclass. State (the formatting
config and the collected aligned-string table) lives on the layout.
"""

from __future__ import annotations

from typing import TYPE_CHECKING, Any

from yaraast.codegen.advanced_generator_helpers import (
    collect_string_definitions,
    format_hex_string,
    format_hex_token,
)
from yaraast.codegen.advanced_generator_helpers2 import (
    get_max_key_length,
    get_sorted_meta,
    process_meta_data,
    render_advanced_hex_string,
    render_advanced_plain_string,
    render_advanced_regex_string,
    write_meta_key,
    write_meta_value,
)
from yaraast.codegen.advanced_generator_layout import (
    generate_condition_string,
    visit_rule as render_advanced_rule,
    visit_yara_file as render_advanced_yara_file,
    write_aligned_strings as render_aligned_strings,
    write_condition_section as render_advanced_condition_section,
    write_strings_section as render_advanced_strings_section,
)
from yaraast.codegen.formatting import FormattingConfig, IndentStyle
from yaraast.codegen.generator_expression_visitors import (
    _render_binary_operator,
    validate_binary_expression_operands,
    validate_set_expression_elements,
)
from yaraast.codegen.generator_formatting import validate_rule_meta
from yaraast.codegen.generator_leaf_visitors import visit_meta as render_meta
from yaraast.codegen.layouts import GeneratorLayout

if TYPE_CHECKING:
    from yaraast.ast.base import YaraFile
    from yaraast.ast.meta import Meta
    from yaraast.ast.rules import Rule
    from yaraast.codegen.generator import CodeGenerator


class AdvancedLayout(GeneratorLayout):
    """Configurable advanced formatting engine as a composed layout."""

    custom_expressions = True

    def __init__(self, config: FormattingConfig | None = None) -> None:
        self.config = config or FormattingConfig()
        self._string_definitions: list[tuple[str, str, list[str]]] = []

    def prepare(self, gen: CodeGenerator, node: Any) -> None:
        self._string_definitions = []

    def indent_string(self, gen: CodeGenerator) -> str:
        if self.config.indent_style == IndentStyle.TABS:
            return "\t" * gen.indent_level
        return " " * (gen.indent_level * self.config.indent_size)

    # Structural
    def visit_yara_file(self, gen: CodeGenerator, node: YaraFile) -> str:
        return render_advanced_yara_file(gen, node)

    def visit_rule(self, gen: CodeGenerator, node: Rule) -> str:
        return render_advanced_rule(gen, node)

    def visit_meta(self, gen: CodeGenerator, node: Meta) -> str:
        return render_meta(node)

    # Section writers
    def write_meta_section(self, gen: CodeGenerator, meta: Any) -> None:
        validate_rule_meta(meta)
        gen._writeline("meta:")
        gen._indent()
        meta_list = process_meta_data(meta)
        meta_list = get_sorted_meta(meta_list, sort_meta=self.config.sort_meta)
        max_key_len = get_max_key_length(meta_list)
        for meta_item in meta_list:
            write_meta_key(gen, meta_item, max_key_len)
            write_meta_value(gen, meta_item)
            gen._writeline()
        gen._dedent()

    def write_strings_section(
        self, gen: CodeGenerator, strings: Any, *, has_condition: bool = False
    ) -> None:
        render_advanced_strings_section(gen, strings)

    def write_condition_section(self, gen: CodeGenerator, condition: Any) -> None:
        render_advanced_condition_section(gen, condition)

    # String renderers (used during file generation via gen.visit and directly)
    def plain_string(self, gen: CodeGenerator, node: Any) -> str:
        return render_advanced_plain_string(gen, node)

    def hex_string(self, gen: CodeGenerator, node: Any) -> str:
        return render_advanced_hex_string(gen, node)

    def regex_string(self, gen: CodeGenerator, node: Any) -> str:
        return render_advanced_regex_string(gen, node)

    # Expression renderers (advanced style; recursion routes back through gen)
    def binary_expression(self, gen: CodeGenerator, node: Any) -> str:
        validate_binary_expression_operands(node)
        left = gen.visit(node.left)
        right = gen.visit(node.right)
        operator = _render_binary_operator(node.operator)
        separator = " " if self.config.space_around_operators or operator.isalpha() else ""
        return f"({left}{separator}{operator}{separator}{right})"

    def set_expression(self, gen: CodeGenerator, node: Any) -> str:
        validate_set_expression_elements(node)
        separator = ", " if self.config.space_after_comma else ","
        return f"({separator.join(gen.visit(elem) for elem in node.elements)})"

    def yarax_expression(self, gen: CodeGenerator, node: Any) -> str:
        return generate_condition_string(node, self.config)

    # Advanced-internal helpers (referenced by the advanced helper modules + tests)
    def collect_string_definitions(self, strings: Any) -> None:
        self._string_definitions = collect_string_definitions(strings, self.config)

    def write_aligned_strings(self, gen: CodeGenerator) -> None:
        render_aligned_strings(gen)

    def get_max_key_length(self, meta_list: Any) -> int:
        return get_max_key_length(meta_list)

    def format_hex_string(self, node: Any) -> str:
        return format_hex_string(node, self.config)

    def format_hex_token(self, token: Any) -> str:
        return format_hex_token(token, self.config)
