"""Code generator for converting AST back to YARA rules."""

from __future__ import annotations

from io import StringIO

from yaraast.ast.base import ASTNode, YaraFile
from yaraast.ast.conditions import (
    AtExpression,
    Condition,
    ForExpression,
    ForOfExpression,
    InExpression,
    OfExpression,
)
from yaraast.ast.expressions import (
    ArrayAccess,
    BinaryExpression,
    BooleanLiteral,
    DoubleLiteral,
    Expression,
    FunctionCall,
    Identifier,
    IntegerLiteral,
    MemberAccess,
    ParenthesesExpression,
    RangeExpression,
    RegexLiteral,
    SetExpression,
    StringCount,
    StringIdentifier,
    StringLength,
    StringLiteral,
    StringOffset,
    StringWildcard,
    UnaryExpression,
)
from yaraast.ast.meta import Meta
from yaraast.ast.modifiers import StringModifier
from yaraast.ast.operators import DefinedExpression, StringOperatorExpression
from yaraast.ast.rules import Import, Include, Rule, Tag
from yaraast.ast.strings import (
    HexAlternative,
    HexByte,
    HexJump,
    HexString,
    HexToken,
    HexWildcard,
    PlainString,
    RegexString,
    StringDefinition,
)
from yaraast.codegen.generator_expression_visitors import visit_array_access as render_array_access
from yaraast.codegen.generator_expression_visitors import (
    visit_at_expression as render_at_expression,
)
from yaraast.codegen.generator_expression_visitors import (
    visit_binary_expression as render_binary_expression,
)
from yaraast.codegen.generator_expression_visitors import (
    visit_for_expression as render_for_expression,
)
from yaraast.codegen.generator_expression_visitors import (
    visit_function_call as render_function_call,
)
from yaraast.codegen.generator_expression_visitors import (
    visit_member_access as render_member_access,
)
from yaraast.codegen.generator_expression_visitors import (
    visit_parentheses_expression as render_parentheses_expression,
)
from yaraast.codegen.generator_expression_visitors import (
    visit_range_expression as render_range_expression,
)
from yaraast.codegen.generator_expression_visitors import (
    visit_set_expression as render_set_expression,
)
from yaraast.codegen.generator_expression_visitors import (
    visit_unary_expression as render_unary_expression,
)
from yaraast.codegen.generator_expressions import (
    render_for_of_expression,
    render_in_expression,
    render_of_expression,
)
from yaraast.codegen.generator_formatting import (
    format_meta_value,
    format_rule_modifiers,
    format_rule_tags,
)
from yaraast.codegen.generator_helpers import escape_plain_string_value, format_modifiers
from yaraast.codegen.generator_leaf_visitors import visit_boolean_literal as render_boolean_literal
from yaraast.codegen.generator_leaf_visitors import visit_comment as render_comment
from yaraast.codegen.generator_leaf_visitors import visit_comment_group as render_comment_group
from yaraast.codegen.generator_leaf_visitors import (
    visit_defined_expression as render_defined_expression,
)
from yaraast.codegen.generator_leaf_visitors import (
    visit_dictionary_access as render_dictionary_access,
)
from yaraast.codegen.generator_leaf_visitors import visit_double_literal as render_double_literal
from yaraast.codegen.generator_leaf_visitors import visit_extern_import as render_extern_import
from yaraast.codegen.generator_leaf_visitors import (
    visit_extern_namespace as render_extern_namespace,
)
from yaraast.codegen.generator_leaf_visitors import visit_extern_rule as render_extern_rule
from yaraast.codegen.generator_leaf_visitors import (
    visit_extern_rule_reference as render_extern_rule_reference,
)
from yaraast.codegen.generator_leaf_visitors import visit_hex_alternative as render_hex_alternative
from yaraast.codegen.generator_leaf_visitors import visit_hex_byte as render_hex_byte
from yaraast.codegen.generator_leaf_visitors import visit_hex_jump as render_hex_jump_leaf
from yaraast.codegen.generator_leaf_visitors import visit_hex_nibble as render_hex_nibble
from yaraast.codegen.generator_leaf_visitors import visit_hex_wildcard as render_hex_wildcard
from yaraast.codegen.generator_leaf_visitors import visit_identifier as render_identifier
from yaraast.codegen.generator_leaf_visitors import visit_in_rule_pragma as render_in_rule_pragma
from yaraast.codegen.generator_leaf_visitors import visit_integer_literal as render_integer_literal
from yaraast.codegen.generator_leaf_visitors import visit_meta as render_meta
from yaraast.codegen.generator_leaf_visitors import (
    visit_module_reference as render_module_reference,
)
from yaraast.codegen.generator_leaf_visitors import visit_pragma as render_pragma
from yaraast.codegen.generator_leaf_visitors import visit_pragma_block as render_pragma_block
from yaraast.codegen.generator_leaf_visitors import visit_regex_literal as render_regex_literal
from yaraast.codegen.generator_leaf_visitors import visit_string_count as render_string_count
from yaraast.codegen.generator_leaf_visitors import (
    visit_string_identifier as render_string_identifier,
)
from yaraast.codegen.generator_leaf_visitors import visit_string_length as render_string_length
from yaraast.codegen.generator_leaf_visitors import visit_string_literal as render_string_literal
from yaraast.codegen.generator_leaf_visitors import visit_string_offset as render_string_offset
from yaraast.codegen.generator_leaf_visitors import (
    visit_string_operator_expression as render_string_operator_expression,
)
from yaraast.codegen.generator_leaf_visitors import visit_string_wildcard as render_string_wildcard
from yaraast.codegen.generator_sections import (
    write_condition_section,
    write_hex_string,
    write_meta_section,
    write_plain_string,
    write_regex_string,
    write_strings_section,
)
from yaraast.codegen.generator_structure_visitors import visit_import as render_import
from yaraast.codegen.generator_structure_visitors import visit_include as render_include
from yaraast.codegen.generator_structure_visitors import visit_rule as render_rule
from yaraast.codegen.generator_structure_visitors import (
    visit_string_definition as render_string_definition,
)
from yaraast.codegen.generator_structure_visitors import visit_tag as render_tag
from yaraast.codegen.generator_structure_visitors import visit_yara_file as render_yara_file
from yaraast.visitor.visitor import ASTVisitor


class CodeGenerator(ASTVisitor[str]):
    """Generate YARA code from AST nodes."""

    def __init__(self, indent_size: int = 4) -> None:
        self.indent_size = indent_size
        self.indent_level = 0
        self.buffer = StringIO()

    def generate(self, node: ASTNode) -> str:
        """Generate code for the given AST node."""
        self.buffer = StringIO()
        self.visit(node)
        return self.buffer.getvalue()

    def _write(self, text: str) -> None:
        """Write text to buffer."""
        self.buffer.write(text)

    def _writeline(self, text: str = "") -> None:
        """Write line with proper indentation."""
        if text:
            self.buffer.write(" " * (self.indent_level * self.indent_size))
            self.buffer.write(text)
        self.buffer.write("\n")

    def _indent(self) -> None:
        """Increase indentation level."""
        self.indent_level += 1

    def _dedent(self) -> None:
        """Decrease indentation level."""
        self.indent_level = max(0, self.indent_level - 1)

    def _write_modifiers(self, modifiers) -> None:
        """Write string modifiers to buffer.

        Handles modifiers in various forms: list/tuple, string, or AST nodes.
        """
        self._write(format_modifiers(modifiers, self.visit))

    def _escape_plain_string_value(self, value: str) -> str:
        """Expose plain-string escaping for extracted rendering helpers."""
        return escape_plain_string_value(value)

    # Visit methods
    def visit_yara_file(self, node: YaraFile) -> str:
        """Generate code for YaraFile."""
        return render_yara_file(self, node)

    def visit_import(self, node: Import) -> str:
        """Generate code for Import."""
        self._write(render_import(node))
        return ""

    def visit_include(self, node: Include) -> str:
        """Generate code for Include."""
        self._write(render_include(node))
        return ""

    def visit_rule(self, node: Rule) -> str:
        """Generate code for Rule."""
        return render_rule(self, node)

    def _write_rule_header(self, node: Rule) -> None:
        """Write rule header with modifiers, name and tags."""
        modifiers = self._format_rule_modifiers(node)
        if modifiers:
            self._write(f"{modifiers} ")

        self._write(f"rule {node.name}")
        self._write_rule_tags(node.tags)

    def _format_rule_modifiers(self, node: Rule) -> str:
        """Format rule modifiers as string."""
        if not hasattr(node, "modifiers"):
            return ""
        return format_rule_modifiers(node.modifiers)

    def _write_rule_tags(self, tags) -> None:
        """Write rule tags."""
        tag_value = format_rule_tags(tags)
        if not tag_value:
            return
        self._write(" : ")
        self._write(tag_value)

    def _write_meta_section(self, meta) -> None:
        """Write meta section if present."""
        write_meta_section(self, meta)

    def _write_meta_dict(self, meta: dict) -> None:
        """Write meta entries from dictionary."""
        for key, value in meta.items():
            self._writeline(self._format_meta_value(key, value))

    def _write_meta_list(self, meta: list) -> None:
        """Write meta entries from list of Meta objects."""
        for m in meta:
            if hasattr(m, "key") and hasattr(m, "value"):
                self._writeline(self._format_meta_value(m.key, m.value))

    def _format_meta_value(self, key: str, value) -> str:
        """Format a single meta key-value pair."""
        return format_meta_value(key, value)

    def _write_strings_section(self, strings, *, has_condition: bool) -> None:
        """Write strings section if present."""
        write_strings_section(self, strings, has_condition=has_condition)

    def _write_condition_section(self, condition) -> None:
        """Write condition section if present."""
        write_condition_section(self, condition)

    def visit_tag(self, node: Tag) -> str:
        """Generate code for Tag."""
        return render_tag(node)

    def visit_string_definition(self, node: StringDefinition) -> str:
        """Generate code for StringDefinition."""
        return render_string_definition(node)

    def visit_plain_string(self, node: PlainString) -> str:
        """Generate code for PlainString."""
        return write_plain_string(self, node)

    def visit_hex_string(self, node: HexString) -> str:
        """Generate code for HexString."""
        return write_hex_string(self, node)

    def visit_regex_string(self, node: RegexString) -> str:
        """Generate code for RegexString."""
        return write_regex_string(self, node)

    def visit_string_modifier(self, node: StringModifier) -> str:
        """Generate code for StringModifier."""
        if node.value is not None:
            if isinstance(node.value, tuple):
                return f"{node.name}({node.value[0]}-{node.value[1]})"
            # String values (e.g., base64 custom alphabet) need quotes
            if isinstance(node.value, str):
                return f'{node.name}("{node.value}")'
            return f"{node.name}({node.value})"
        return node.name

    def visit_hex_token(self, node: HexToken) -> str:
        """Generate code for HexToken."""
        return ""  # Should not be called directly

    def visit_hex_byte(self, node: HexByte) -> str:
        return render_hex_byte(node)

    def visit_hex_wildcard(self, node: HexWildcard) -> str:
        return render_hex_wildcard(node)

    def visit_hex_jump(self, node: HexJump) -> str:
        return render_hex_jump_leaf(node)

    def visit_hex_alternative(self, node: HexAlternative) -> str:
        return render_hex_alternative(self, node)

    def visit_hex_nibble(self, node) -> str:
        return render_hex_nibble(node)

    def visit_expression(self, node: Expression) -> str:
        """Generate code for Expression."""
        return ""  # Should not be called directly

    def visit_identifier(self, node: Identifier) -> str:
        return render_identifier(node)

    def visit_string_identifier(self, node: StringIdentifier) -> str:
        return render_string_identifier(node)

    def visit_string_wildcard(self, node: StringWildcard) -> str:
        return render_string_wildcard(node)

    def visit_string_count(self, node: StringCount) -> str:
        return render_string_count(node)

    def visit_string_offset(self, node: StringOffset) -> str:
        return render_string_offset(self, node)

    def visit_string_length(self, node: StringLength) -> str:
        return render_string_length(self, node)

    def visit_integer_literal(self, node: IntegerLiteral) -> str:
        return render_integer_literal(node)

    def visit_double_literal(self, node: DoubleLiteral) -> str:
        return render_double_literal(node)

    def visit_string_literal(self, node: StringLiteral) -> str:
        return render_string_literal(node)

    def visit_regex_literal(self, node: RegexLiteral) -> str:
        return render_regex_literal(node)

    def visit_boolean_literal(self, node: BooleanLiteral) -> str:
        return render_boolean_literal(node)

    def visit_binary_expression(self, node: BinaryExpression) -> str:
        return render_binary_expression(self, node)

    def visit_unary_expression(self, node: UnaryExpression) -> str:
        return render_unary_expression(self, node)

    def visit_parentheses_expression(self, node: ParenthesesExpression) -> str:
        return render_parentheses_expression(self, node)

    def visit_set_expression(self, node: SetExpression) -> str:
        return render_set_expression(self, node)

    def visit_range_expression(self, node: RangeExpression) -> str:
        return render_range_expression(self, node)

    def visit_function_call(self, node: FunctionCall) -> str:
        return render_function_call(self, node)

    def visit_array_access(self, node: ArrayAccess) -> str:
        return render_array_access(self, node)

    def visit_member_access(self, node: MemberAccess) -> str:
        return render_member_access(self, node)

    def visit_condition(self, node: Condition) -> str:
        """Generate code for Condition."""
        return ""  # Should not be called directly

    def visit_for_expression(self, node: ForExpression) -> str:
        return render_for_expression(self, node)

    def visit_for_of_expression(self, node: ForOfExpression) -> str:
        """Generate code for ForOfExpression."""
        return render_for_of_expression(self, node)

    def visit_at_expression(self, node: AtExpression) -> str:
        return render_at_expression(self, node)

    def visit_in_expression(self, node: InExpression) -> str:
        """Generate code for InExpression."""
        return render_in_expression(self, node)

    def visit_of_expression(self, node: OfExpression) -> str:
        """Generate code for OfExpression."""
        return render_of_expression(self, node)

    def visit_meta(self, node: Meta) -> str:
        return render_meta(node)

    def visit_module_reference(self, node) -> str:
        return render_module_reference(node)

    def visit_dictionary_access(self, node) -> str:
        return render_dictionary_access(self, node)

    def visit_defined_expression(self, node: DefinedExpression) -> str:
        return render_defined_expression(self, node)

    def visit_string_operator_expression(self, node: StringOperatorExpression) -> str:
        return render_string_operator_expression(self, node)

    def visit_comment(self, node) -> str:
        return render_comment(node)

    def visit_comment_group(self, node) -> str:
        return render_comment_group(node)

    def visit_extern_import(self, node) -> str:
        return render_extern_import(node)

    def visit_extern_namespace(self, node) -> str:
        return render_extern_namespace(node)

    def visit_extern_rule(self, node) -> str:
        return render_extern_rule(node)

    def visit_extern_rule_reference(self, node) -> str:
        return render_extern_rule_reference(node)

    def visit_in_rule_pragma(self, node) -> str:
        return render_in_rule_pragma(node)

    def visit_pragma(self, node) -> str:
        return render_pragma(node)

    def visit_pragma_block(self, node) -> str:
        return render_pragma_block(self, node)
