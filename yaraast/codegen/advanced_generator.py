"""Advanced code generator with formatting options."""

from __future__ import annotations

from io import StringIO
from typing import TYPE_CHECKING, Any

from yaraast.ast.strings import HexString, HexToken, PlainString, RegexString, StringDefinition
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
    write_aligned_strings as write_advanced_aligned_strings,
    write_condition_section as write_advanced_condition_section,
    write_strings_section as write_advanced_strings_section,
)
from yaraast.codegen.formatting import FormattingConfig, IndentStyle
from yaraast.codegen.generator import CodeGenerator

if TYPE_CHECKING:
    from yaraast.ast.base import ASTNode, YaraFile
    from yaraast.ast.expressions import BinaryExpression, Expression, SetExpression
    from yaraast.ast.meta import Meta
    from yaraast.ast.rules import Import, Include, Rule


class AdvancedCodeGenerator(CodeGenerator):
    """Advanced code generator with configurable formatting."""

    def __init__(self, config: FormattingConfig | None = None) -> None:
        self.config = config or FormattingConfig()
        super().__init__(self.config.indent_size)
        self._string_definitions: list[tuple[str, Any]] = []

    def generate(self, node: ASTNode) -> str:
        """Generate code with advanced formatting."""
        self.buffer = StringIO()
        self.indent_level = 0
        self._string_definitions = []
        self.visit(node)
        return self.buffer.getvalue()

    def _get_indent(self) -> str:
        """Get indentation string."""
        if self.config.indent_style == IndentStyle.TABS:
            return "\t" * self.indent_level
        return " " * (self.indent_level * self.config.indent_size)

    def _write(self, text: str) -> None:
        """Write text to buffer."""
        self.buffer.write(text)

    def _writeline(self, text: str = "") -> None:
        """Write line with proper indentation."""
        if text:
            self.buffer.write(self._get_indent())
            self.buffer.write(text)
        self.buffer.write("\n")

    def _write_blank_lines(self, count: int) -> None:
        """Write blank lines."""
        for _ in range(count):
            self.buffer.write("\n")

    def visit_yara_file(self, node: YaraFile) -> str:
        return render_advanced_yara_file(self, node)

    def visit_rule(self, node: Rule) -> str:
        return render_advanced_rule(self, node)

    def _process_meta_data(self, meta_data: dict[str, Any] | list) -> list:
        """Process meta data into normalized format."""
        return process_meta_data(meta_data)

    def _get_sorted_meta(self, meta_list: list) -> list:
        """Sort meta list if configured."""
        return get_sorted_meta(meta_list, sort_meta=self.config.sort_meta)

    def _get_max_key_length(self, meta_list: list) -> int:
        """Get maximum key length for alignment."""
        return get_max_key_length(meta_list)

    def _write_meta_key(self, meta, max_key_len: int) -> None:
        """Write meta key with proper formatting."""
        write_meta_key(self, meta, max_key_len)

    def _write_meta_value(self, meta) -> None:
        """Write meta value with proper formatting."""
        write_meta_value(self, meta)

    def _write_meta_section(self, meta_data: dict[str, Any] | list[Meta]) -> None:
        """Write meta section with formatting."""
        self._writeline("meta:")
        self._indent()

        # Process and sort meta data
        meta_list = self._process_meta_data(meta_data)
        meta_list = self._get_sorted_meta(meta_list)
        max_key_len = self._get_max_key_length(meta_list)

        for meta in meta_list:
            # Ensure we have a proper meta object
            if not hasattr(meta, "key"):
                continue

            self._write_meta_key(meta, max_key_len)
            self._write_meta_value(meta)
            self._writeline()

        self._dedent()

    def _write_strings_section(self, strings: list[StringDefinition]) -> None:
        write_advanced_strings_section(self, strings)

    def _collect_string_definitions(self, strings: list[StringDefinition]) -> None:
        """Collect string definitions for alignment."""
        self._string_definitions = collect_string_definitions(strings, self.config)

    def _write_aligned_strings(self) -> None:
        write_advanced_aligned_strings(self)

    def _format_hex_string(self, node: HexString) -> str:
        """Format hex string according to style."""
        return format_hex_string(node, self.config)

    def _format_hex_token(self, token: HexToken) -> str:
        """Format individual hex token."""
        return format_hex_token(token, self.config)

    def _write_condition_section(self, condition: Expression) -> None:
        write_advanced_condition_section(self, condition)

    def _generate_condition_string(self, expr: Expression) -> str:
        return generate_condition_string(expr)

    def _write_wrapped_condition(self, condition: str) -> None:
        """Write wrapped condition for long lines."""
        # Simple wrapping at operators
        # This is a simplified implementation
        self._writeline(condition)

    # Operator formatting
    def visit_binary_expression(self, node: BinaryExpression) -> str:
        """Generate binary expression with spacing."""
        left = self.visit(node.left)
        right = self.visit(node.right)

        if self.config.space_around_operators:
            result = f"({left} {node.operator} {right})"
        else:
            result = f"({left}{node.operator}{right})"

        self._write(result)
        return result

    def visit_set_expression(self, node: SetExpression) -> str:
        """Generate set expression with spacing."""
        elements = []
        for elem in node.elements:
            elem_str = self.visit(elem)
            elements.append(elem_str)

        if self.config.space_after_comma:
            result = f"({', '.join(elements)})"
        else:
            result = f"({','.join(elements)})"

        self._write(result)
        return result

    # Default visit methods (delegate to parent)
    def visit_import(self, node: Import) -> str:
        self._writeline(f'import "{node.module}"')
        return ""

    def visit_include(self, node: Include) -> str:
        self._writeline(f'include "{node.path}"')
        return ""

    def visit_plain_string(self, node: PlainString) -> str:
        result = render_advanced_plain_string(self, node)
        for modifier in node.modifiers:
            self.visit(modifier)
        return result

    def visit_hex_string(self, node: HexString) -> str:
        result = render_advanced_hex_string(self, node)
        for modifier in node.modifiers:
            self.visit(modifier)
        return result

    def visit_regex_string(self, node: RegexString) -> str:
        result = render_advanced_regex_string(self, node)
        for modifier in node.modifiers:
            self.visit(modifier)
        return result
