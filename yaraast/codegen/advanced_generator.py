"""Advanced code generator (transitional shell over the composed AdvancedLayout).

The configurable formatting behaviour now lives in
:class:`yaraast.codegen.advanced_layout.AdvancedLayout`, selected via
``GeneratorOptions.advanced``. This subclass keeps the advanced-style direct
expression renderers (parenthesized binary/set and the YARA-X expression
shortcut) plus the few internal helpers exercised directly by tests; structural,
section, string, meta and indentation rendering are supplied by the layout.
"""

from __future__ import annotations

from typing import TYPE_CHECKING, Any, cast

from yaraast.codegen.advanced_generator_layout import generate_condition_string
from yaraast.codegen.formatting import FormattingConfig
from yaraast.codegen.generator import CodeGenerator
from yaraast.codegen.generator_expression_visitors import (
    _render_binary_operator,
    validate_set_expression_elements,
)
from yaraast.codegen.options import GeneratorOptions

if TYPE_CHECKING:
    from yaraast.ast.expressions import BinaryExpression, SetExpression
    from yaraast.codegen.advanced_layout import AdvancedLayout


class AdvancedCodeGenerator(CodeGenerator):
    """Advanced code generator with configurable formatting."""

    def __init__(self, config: FormattingConfig | None = None) -> None:
        self.config = config or FormattingConfig()
        super().__init__(
            options=GeneratorOptions(indent_size=self.config.indent_size, advanced=self.config)
        )

    # Advanced-style direct expression renderers
    def visit_binary_expression(self, node: BinaryExpression) -> str:
        """Generate binary expression with spacing."""
        left = self.visit(node.left)
        right = self.visit(node.right)
        operator = _render_binary_operator(node.operator)

        separator = " " if self.config.space_around_operators or operator.isalpha() else ""
        result = f"({left}{separator}{operator}{separator}{right})"

        self._write(result)
        return result

    def visit_set_expression(self, node: SetExpression) -> str:
        """Generate set expression with spacing."""
        validate_set_expression_elements(node)
        elements: list[str] = []
        for elem in node.elements:
            elem_str = self.visit(elem)
            elements.append(elem_str)

        if self.config.space_after_comma:
            result = f"({', '.join(elements)})"
        else:
            result = f"({','.join(elements)})"

        self._write(result)
        return result

    def _generate_yarax_expression(self, node: Any) -> str:
        return generate_condition_string(node, self.config)

    def visit_with_statement(self, node: Any) -> str:
        return self._generate_yarax_expression(node)

    def visit_with_declaration(self, node: Any) -> str:
        return self._generate_yarax_expression(node)

    def visit_array_comprehension(self, node: Any) -> str:
        return self._generate_yarax_expression(node)

    def visit_dict_comprehension(self, node: Any) -> str:
        return self._generate_yarax_expression(node)

    def visit_tuple_expression(self, node: Any) -> str:
        return self._generate_yarax_expression(node)

    def visit_tuple_indexing(self, node: Any) -> str:
        return self._generate_yarax_expression(node)

    def visit_list_expression(self, node: Any) -> str:
        return self._generate_yarax_expression(node)

    def visit_dict_expression(self, node: Any) -> str:
        return self._generate_yarax_expression(node)

    def visit_dict_item(self, node: Any) -> str:
        return self._generate_yarax_expression(node)

    def visit_slice_expression(self, node: Any) -> str:
        return self._generate_yarax_expression(node)

    def visit_lambda_expression(self, node: Any) -> str:
        return self._generate_yarax_expression(node)

    def visit_pattern_match(self, node: Any) -> str:
        return self._generate_yarax_expression(node)

    def visit_match_case(self, node: Any) -> str:
        return self._generate_yarax_expression(node)

    def visit_spread_operator(self, node: Any) -> str:
        return self._generate_yarax_expression(node)

    # Internal helpers exercised directly by tests (delegate to the layout)
    def _get_max_key_length(self, meta_list: list[Any]) -> int:
        return cast("AdvancedLayout", self._layout).get_max_key_length(meta_list)

    def _write_aligned_strings(self) -> None:
        cast("AdvancedLayout", self._layout).write_aligned_strings(self)

    def _format_hex_token(self, token: Any) -> str:
        return cast("AdvancedLayout", self._layout).format_hex_token(token)
