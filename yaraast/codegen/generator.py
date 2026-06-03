"""Code generator for converting AST back to YARA rules."""

from __future__ import annotations

from io import StringIO
from typing import TYPE_CHECKING, Any

from yaraast.ast.base import ASTNode, YaraFile
from yaraast.ast.comments import Comment, CommentGroup
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
    HexNegatedByte,
    HexNibble,
    HexString,
    HexToken,
    HexWildcard,
    PlainString,
    RegexString,
    StringDefinition,
)
from yaraast.codegen.generator_expression_visitors import (
    validate_expression_collection,
    visit_array_access as render_array_access,
    visit_at_expression as render_at_expression,
    visit_binary_expression as render_binary_expression,
    visit_for_expression as render_for_expression,
    visit_function_call as render_function_call,
    visit_member_access as render_member_access,
    visit_parentheses_expression as render_parentheses_expression,
    visit_range_expression as render_range_expression,
    visit_set_expression as render_set_expression,
    visit_unary_expression as render_unary_expression,
)
from yaraast.codegen.generator_expressions import (
    render_for_of_expression,
    render_in_expression,
    render_of_expression,
)
from yaraast.codegen.generator_formatting import (
    format_meta_key,
    format_meta_literal,
    format_meta_value,
    format_rule_modifiers,
    format_rule_tags,
    validate_yara_identifier,
)
from yaraast.codegen.generator_helpers import (
    escape_plain_string_value,
    format_hex_negated_value,
    format_modifier,
    format_modifiers,
)
from yaraast.codegen.generator_leaf_visitors import (
    visit_boolean_literal as render_boolean_literal,
    visit_comment as render_comment,
    visit_comment_group as render_comment_group,
    visit_defined_expression as render_defined_expression,
    visit_dictionary_access as render_dictionary_access,
    visit_double_literal as render_double_literal,
    visit_extern_import as render_extern_import,
    visit_extern_namespace as render_extern_namespace,
    visit_extern_rule as render_extern_rule,
    visit_extern_rule_reference as render_extern_rule_reference,
    visit_hex_alternative as render_hex_alternative,
    visit_hex_byte as render_hex_byte,
    visit_hex_jump as render_hex_jump_leaf,
    visit_hex_nibble as render_hex_nibble,
    visit_hex_wildcard as render_hex_wildcard,
    visit_identifier as render_identifier,
    visit_in_rule_pragma as render_in_rule_pragma,
    visit_integer_literal as render_integer_literal,
    visit_module_reference as render_module_reference,
    visit_pragma as render_pragma,
    visit_pragma_block as render_pragma_block,
    visit_regex_literal as render_regex_literal,
    visit_string_count as render_string_count,
    visit_string_identifier as render_string_identifier,
    visit_string_length as render_string_length,
    visit_string_literal as render_string_literal,
    visit_string_offset as render_string_offset,
    visit_string_operator_expression as render_string_operator_expression,
    visit_string_wildcard as render_string_wildcard,
)
from yaraast.codegen.generator_structure_visitors import (
    visit_import as render_import,
    visit_include as render_include,
    visit_string_definition as render_string_definition,
    visit_tag as render_tag,
)
from yaraast.codegen.layouts import select_layout
from yaraast.codegen.options import GeneratorOptions
from yaraast.visitor.visitor import ASTVisitor

if TYPE_CHECKING:
    from yaraast.yarax.ast_nodes import (
        ArrayComprehension,
        DictComprehension,
        DictExpression,
        DictItem,
        LambdaExpression,
        ListExpression,
        MatchCase,
        PatternMatch,
        SliceExpression,
        SpreadOperator,
        TupleExpression,
        TupleIndexing,
        WithDeclaration,
        WithStatement,
    )


class CodeGenerator(ASTVisitor[str]):
    """Generates YARA source code from an AST.

    Examples:
        >>> from yaraast.parser import Parser
        >>> from yaraast.codegen.generator import CodeGenerator
        >>> ast = Parser().parse('rule test { condition: true }')
        >>> gen = CodeGenerator()
        >>> code = gen.generate(ast)
        >>> 'rule test' in code
        True
    """

    def __init__(
        self,
        indent_size: int = 4,
        *,
        options: GeneratorOptions | None = None,
    ) -> None:
        resolved = options or GeneratorOptions(indent_size=indent_size)
        self.indent_size = resolved.indent_size
        self.preserve_comments = resolved.preserve_comments
        self.blank_line_between_sections = resolved.blank_line_between_sections
        self._layout = select_layout(resolved)
        self._custom_expressions = self._layout.custom_expressions
        self.indent_level = 0
        self.buffer = StringIO()

    def generate(self, node: ASTNode) -> str:
        """Generate code for the given AST node."""
        self.buffer = StringIO()
        self.indent_level = 0
        self._layout.prepare(self, node)
        result = self.visit(node)
        if result:
            return result
        return self.buffer.getvalue()

    def _write(self, text: str) -> None:
        """Write text to buffer."""
        self.buffer.write(text)

    def _get_indent(self) -> str:
        """Indentation prefix for the current depth (layout-aware)."""
        return self._layout.indent_string(self)

    def _write_blank_lines(self, count: int) -> None:
        """Write ``count`` blank lines."""
        for _ in range(count):
            self.buffer.write("\n")

    def _writeline(self, text: str = "") -> None:
        """Write line with proper indentation."""
        if text:
            self.buffer.write(self._layout.indent_string(self))
            self.buffer.write(text)
        self.buffer.write("\n")

    def _indent(self) -> None:
        """Increase indentation level."""
        self.indent_level += 1

    def _dedent(self) -> None:
        """Decrease indentation level."""
        self.indent_level = max(0, self.indent_level - 1)

    def _write_modifiers(self, modifiers: object) -> None:
        """Write string modifiers to buffer.

        Handles modifiers in various forms: list/tuple, string, or AST nodes.
        """
        self._write(format_modifiers(modifiers, self.visit))

    def _escape_plain_string_value(self, value: str) -> str:
        """Expose plain-string escaping for extracted rendering helpers."""
        return escape_plain_string_value(value)

    # Comment-aware primitives (active when ``preserve_comments`` is set)
    def _write_comment(
        self,
        comment: Comment | CommentGroup | None,
        inline: bool = False,
    ) -> None:
        """Write a single comment or comment group."""
        if not self.preserve_comments or not comment:
            return

        if isinstance(comment, CommentGroup):
            for c in comment.comments:
                self._write_single_comment(c, inline)
        else:
            self._write_single_comment(comment, inline)

    def _write_comments(self, comments: list[Comment | CommentGroup] | None) -> None:
        """Write a list of comments."""
        if not self.preserve_comments or not comments:
            return

        for comment in comments:
            self._write_comment(comment)

    def _write_single_comment(self, comment: Comment, inline: bool = False) -> None:
        """Write a single comment."""
        text = comment.text

        # Clean up comment text
        if text.startswith("//"):
            text = text[2:].strip()
        elif text.startswith("/*") and text.endswith("*/"):
            text = text[2:-2].strip()

        if inline:
            self._write(f"  // {text}")
        # Check if it's a multi-line comment
        elif "\n" in text or len(text) > 80:
            self._writeline("/*")
            for line in text.split("\n"):
                self._writeline(f" * {line.strip()}")
            self._writeline(" */")
        else:
            self._writeline(f"// {text}")

    def _write_leading_comments(self, comments: list[Comment]) -> None:
        """Write leading comments."""
        if not self.preserve_comments or not comments:
            return

        for comment in comments:
            self._write_comment(comment, inline=False)

    def _write_meta_item(self, key: str, value: Any, scope: object | None = None) -> None:
        """Write a meta item (comment-aware mode)."""
        indent = " " * (self.indent_level * self.indent_size)
        self._write(indent)
        self._write(f"{format_meta_key(key, scope)} = ")
        self._write(format_meta_literal(value))

    # Visit methods
    def visit_yara_file(self, node: YaraFile) -> str:
        """Generate code for YaraFile."""
        return self._layout.visit_yara_file(self, node)

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
        return self._layout.visit_rule(self, node)

    def _write_rule_header(self, node: Rule) -> None:
        """Write rule header with modifiers, name and tags."""
        modifiers = self._format_rule_modifiers(node)
        if modifiers:
            self._write(f"{modifiers} ")

        rule_name = validate_yara_identifier(node.name, "rule")
        self._write(f"rule {rule_name}")
        self._write_rule_tags(node.tags)

    def _format_rule_modifiers(self, node: Rule) -> str:
        """Format rule modifiers as string."""
        if not hasattr(node, "modifiers"):
            return ""
        return format_rule_modifiers(node.modifiers)

    def _write_rule_tags(self, tags: list[Any] | tuple[Any, ...] | None) -> None:
        """Write rule tags."""
        tag_value = format_rule_tags(tags)
        if not tag_value:
            return
        self._write(" : ")
        self._write(tag_value)

    def _write_meta_section(
        self,
        meta: object,
    ) -> None:
        """Write meta section if present."""
        self._layout.write_meta_section(self, meta)

    def _write_meta_dict(self, meta: dict[str, Any]) -> None:
        """Write meta entries from dictionary."""
        for key, value in meta.items():
            self._writeline(self._format_meta_value(key, value))

    def _write_meta_list(self, meta: list[Any]) -> None:
        """Write meta entries from list of Meta objects."""
        for m in meta:
            if hasattr(m, "key") and hasattr(m, "value"):
                self._writeline(self._format_meta_value(m.key, m.value, getattr(m, "scope", None)))

    def _format_meta_value(self, key: str, value: Any, scope: object | None = None) -> str:
        """Format a single meta key-value pair."""
        return format_meta_value(key, value, scope)

    def _write_strings_section(
        self,
        strings: list[Any] | tuple[Any, ...],
        *,
        has_condition: bool = False,
    ) -> None:
        """Write strings section if present."""
        self._layout.write_strings_section(self, strings, has_condition=has_condition)

    def _write_condition_section(self, condition: Any) -> None:
        """Write condition section if present."""
        self._layout.write_condition_section(self, condition)

    def visit_tag(self, node: Tag) -> str:
        """Generate code for Tag."""
        return render_tag(node)

    def visit_string_definition(self, node: StringDefinition) -> str:
        """Generate code for StringDefinition."""
        return render_string_definition(node)

    def visit_plain_string(self, node: PlainString) -> str:
        """Generate code for PlainString."""
        return self._layout.plain_string(self, node)

    def visit_hex_string(self, node: HexString) -> str:
        """Generate code for HexString."""
        return self._layout.hex_string(self, node)

    def visit_regex_string(self, node: RegexString) -> str:
        """Generate code for RegexString."""
        return self._layout.regex_string(self, node)

    def visit_string_modifier(self, node: StringModifier) -> str:
        """Generate code for StringModifier."""
        return format_modifier(node)

    def visit_hex_token(self, node: HexToken) -> str:
        """Generate code for HexToken."""
        return ""  # Should not be called directly

    def visit_hex_byte(self, node: HexByte) -> str:
        return render_hex_byte(node)

    def visit_hex_negated_byte(self, node: HexNegatedByte) -> str:
        value = format_hex_negated_value(
            node.value,
            uppercase=True,
        )
        return f"~{value}"

    def visit_hex_wildcard(self, node: HexWildcard) -> str:
        return render_hex_wildcard(node)

    def visit_hex_jump(self, node: HexJump) -> str:
        return render_hex_jump_leaf(node)

    def visit_hex_alternative(self, node: HexAlternative) -> str:
        return render_hex_alternative(self, node)

    def visit_hex_nibble(self, node: HexNibble) -> str:
        return render_hex_nibble(node)

    def visit_expression(self, node: Expression) -> str:
        """Generate code for Expression."""
        return ""  # Should not be called directly

    def visit_identifier(self, node: Identifier) -> str:
        return render_identifier(node)

    def visit_string_identifier(self, node: StringIdentifier) -> str:
        return render_string_identifier(
            node,
            allow_placeholder=getattr(self, "_allow_string_placeholder", False),
        )

    def visit_string_wildcard(self, node: StringWildcard) -> str:
        return render_string_wildcard(node)

    def visit_string_count(self, node: StringCount) -> str:
        return render_string_count(
            node,
            allow_placeholder=getattr(self, "_allow_string_placeholder", False),
        )

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
        if self._custom_expressions:
            return self._layout.binary_expression(self, node)
        return render_binary_expression(self, node)

    def visit_unary_expression(self, node: UnaryExpression) -> str:
        return render_unary_expression(self, node)

    def visit_parentheses_expression(self, node: ParenthesesExpression) -> str:
        return render_parentheses_expression(self, node)

    def visit_set_expression(self, node: SetExpression) -> str:
        if self._custom_expressions:
            return self._layout.set_expression(self, node)
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
        return self._layout.visit_meta(self, node)

    def visit_module_reference(self, node: Any) -> str:
        return render_module_reference(node)

    def visit_dictionary_access(self, node: Any) -> str:
        return render_dictionary_access(self, node)

    def visit_defined_expression(self, node: DefinedExpression) -> str:
        return render_defined_expression(self, node)

    def visit_string_operator_expression(self, node: StringOperatorExpression) -> str:
        return render_string_operator_expression(self, node)

    def visit_comment(self, node: Any) -> str:
        return render_comment(node)

    def visit_comment_group(self, node: Any) -> str:
        return render_comment_group(node)

    def visit_extern_import(self, node: Any) -> str:
        return render_extern_import(node)

    def visit_extern_namespace(self, node: Any) -> str:
        return render_extern_namespace(node)

    def visit_extern_rule(self, node: Any) -> str:
        return render_extern_rule(node)

    def visit_extern_rule_reference(self, node: Any) -> str:
        return render_extern_rule_reference(node)

    def visit_in_rule_pragma(self, node: Any) -> str:
        return render_in_rule_pragma(node)

    def visit_pragma(self, node: Any) -> str:
        return render_pragma(node)

    def visit_pragma_block(self, node: Any) -> str:
        return render_pragma_block(self, node)

    # YARA-X extended-syntax visitors
    def visit_with_statement(self, node: WithStatement) -> str:
        if self._custom_expressions:
            return self._layout.yarax_expression(self, node)
        validate_expression_collection(node.declarations, "WithStatement declarations")
        declarations = ", ".join(self.visit(declaration) for declaration in node.declarations)
        return f"with {declarations}: {self.visit(node.body)}"

    def visit_with_declaration(self, node: WithDeclaration) -> str:
        if self._custom_expressions:
            return self._layout.yarax_expression(self, node)
        return f"{node.identifier} = {self.visit(node.value)}"

    def visit_array_comprehension(self, node: ArrayComprehension) -> str:
        if self._custom_expressions:
            return self._layout.yarax_expression(self, node)
        if node.expression is None or node.iterable is None:
            msg = "Array comprehension requires expression and iterable for libyara output"
            raise ValueError(msg)
        result = (
            f"[{self.visit(node.expression)} for {node.variable} " f"in {self.visit(node.iterable)}"
        )
        if node.condition is not None:
            result += f" if {self.visit(node.condition)}"
        return result + "]"

    def visit_dict_comprehension(self, node: DictComprehension) -> str:
        if self._custom_expressions:
            return self._layout.yarax_expression(self, node)
        if node.key_expression is None or node.value_expression is None or node.iterable is None:
            msg = "Dict comprehension requires key, value, and iterable for libyara output"
            raise ValueError(msg)
        variables = (
            f"{node.key_variable}, {node.value_variable}"
            if node.value_variable
            else node.key_variable
        )
        result = (
            f"{{{self.visit(node.key_expression)}: {self.visit(node.value_expression)} "
            f"for {variables} in {self.visit(node.iterable)}"
        )
        if node.condition is not None:
            result += f" if {self.visit(node.condition)}"
        return result + "}"

    def visit_tuple_expression(self, node: TupleExpression) -> str:
        if self._custom_expressions:
            return self._layout.yarax_expression(self, node)
        validate_expression_collection(node.elements, "TupleExpression elements")
        if not node.elements:
            return "()"
        elements = [self.visit(element) for element in node.elements]
        if len(elements) == 1:
            return f"({elements[0]},)"
        return f"({', '.join(elements)})"

    def visit_tuple_indexing(self, node: TupleIndexing) -> str:
        if self._custom_expressions:
            return self._layout.yarax_expression(self, node)
        from yaraast.ast.expressions import FunctionCall, Identifier
        from yaraast.yarax.ast_nodes import TupleExpression

        tuple_str = self.visit(node.tuple_expr)
        index_str = self.visit(node.index)
        if isinstance(node.tuple_expr, FunctionCall | Identifier | TupleExpression):
            return f"{tuple_str}[{index_str}]"
        return f"({tuple_str})[{index_str}]"

    def visit_list_expression(self, node: ListExpression) -> str:
        if self._custom_expressions:
            return self._layout.yarax_expression(self, node)
        validate_expression_collection(node.elements, "ListExpression elements")
        return f"[{', '.join(self.visit(element) for element in node.elements)}]"

    def visit_dict_expression(self, node: DictExpression) -> str:
        if self._custom_expressions:
            return self._layout.yarax_expression(self, node)
        from yaraast.yarax.ast_nodes import SpreadOperator

        validate_expression_collection(node.items, "DictExpression items")
        items = [
            self.visit(item.value) if isinstance(item.value, SpreadOperator) else self.visit(item)
            for item in node.items
        ]
        return f"{{{', '.join(items)}}}"

    def visit_dict_item(self, node: DictItem) -> str:
        if self._custom_expressions:
            return self._layout.yarax_expression(self, node)
        return f"{self.visit(node.key)}: {self.visit(node.value)}"

    def visit_slice_expression(self, node: SliceExpression) -> str:
        if self._custom_expressions:
            return self._layout.yarax_expression(self, node)
        parts = [
            self.visit(node.start) if node.start is not None else "",
            self.visit(node.stop) if node.stop is not None else "",
        ]
        if node.step is not None:
            parts.append(self.visit(node.step))
        return f"{self.visit(node.target)}[{':'.join(parts)}]"

    def visit_lambda_expression(self, node: LambdaExpression) -> str:
        if self._custom_expressions:
            return self._layout.yarax_expression(self, node)
        validate_expression_collection(node.parameters, "LambdaExpression parameters")
        parameters = ", ".join(node.parameters)
        if parameters:
            return f"lambda {parameters}: {self.visit(node.body)}"
        return f"lambda: {self.visit(node.body)}"

    def visit_pattern_match(self, node: PatternMatch) -> str:
        if self._custom_expressions:
            return self._layout.yarax_expression(self, node)
        validate_expression_collection(node.cases, "PatternMatch cases")
        lines = [f"match {self.visit(node.value)} {{"]
        case_indent = " " * self.indent_size
        lines.extend(f"{case_indent}{self.visit(case)}," for case in node.cases)
        default = node.default
        if default is not None:
            default_str = self._indent_continuation_lines(self.visit(default))
            lines.append(f"{case_indent}_ => {default_str},")
        lines.append("}")
        return "\n".join(lines)

    def visit_match_case(self, node: MatchCase) -> str:
        if self._custom_expressions:
            return self._layout.yarax_expression(self, node)
        result = self._indent_continuation_lines(self.visit(node.result))
        return f"{self.visit(node.pattern)} => {result}"

    def _indent_continuation_lines(self, text: str) -> str:
        continuation_indent = " " * self.indent_size
        return text.replace("\n", f"\n{continuation_indent}")

    def visit_spread_operator(self, node: SpreadOperator) -> str:
        if self._custom_expressions:
            return self._layout.yarax_expression(self, node)
        prefix = "**" if node.is_dict else "..."
        return f"{prefix}{self.visit(node.expression)}"
