"""Comment-aware code generator for YARA rules."""

from __future__ import annotations

from typing import TYPE_CHECKING, Any

from yaraast.ast.comments import Comment, CommentGroup
from yaraast.codegen.generator import CodeGenerator
from yaraast.codegen.generator_formatting import (
    format_meta_key,
    format_meta_literal,
    format_rule_modifiers,
    format_rule_tags,
    validate_rule_identifiers,
    validate_yara_identifier,
)
from yaraast.codegen.generator_helpers import (
    escape_regex_delimiter,
    format_regex_modifiers,
    output_string_identifier,
    validate_hex_string_modifiers,
    validate_plain_string_modifiers,
    validate_regex_string_modifiers,
    validate_string_identifiers,
)

if TYPE_CHECKING:
    from yaraast.ast.base import ASTNode, YaraFile
    from yaraast.ast.meta import Meta
    from yaraast.ast.rules import Rule
    from yaraast.ast.strings import HexString, PlainString, RegexString
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


class CommentAwareCodeGenerator(CodeGenerator):
    """Generate YARA code with preserved comments."""

    def __init__(self, indent_size: int = 4, preserve_comments: bool = True) -> None:
        super().__init__(indent_size)
        self.preserve_comments = preserve_comments

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

    def _write_top_level_node(self, node: Any) -> None:
        """Write a file-level node with preserved comments."""
        self._write_leading_comments(getattr(node, "leading_comments", []))
        rendered = self.visit(node)
        if rendered:
            self._write(rendered)
        trailing_comment = getattr(node, "trailing_comment", None)
        if trailing_comment:
            self._write_comment(trailing_comment, inline=True)
        self._writeline()

    def _write_top_level_section(self, nodes: list[Any]) -> None:
        if not nodes:
            return
        for node in nodes:
            self._write_top_level_node(node)
        self._writeline()

    def generate(self, node: ASTNode) -> str:
        """Generate code with comments."""
        self.buffer.seek(0)
        self.buffer.truncate()
        self.indent_level = 0

        # Visit the AST
        result = self.visit(node)

        # Get the generated code
        if result:
            return result
        return self.buffer.getvalue()

    def visit_yara_file(self, node: YaraFile) -> str:
        """Generate code for YaraFile with comments."""
        validate_rule_identifiers(node.rules)
        # Write leading comments
        self._write_leading_comments(node.leading_comments)

        self._write_top_level_section(node.pragmas)
        self._write_top_level_section(node.imports)
        self._write_top_level_section(node.extern_imports)
        self._write_top_level_section(node.includes)
        self._write_top_level_section(node.namespaces)
        self._write_top_level_section(node.extern_rules)

        # Write rules
        for i, rule in enumerate(node.rules):
            if i > 0:
                self._writeline()
            self.visit(rule)

        # Write trailing comment
        if node.trailing_comment:
            self._writeline()
            self._write_comment(node.trailing_comment)

        return self.buffer.getvalue()

    def visit_rule(self, node: Rule) -> str:
        """Generate code for Rule with comments."""
        # Write leading comments
        self._write_leading_comments(node.leading_comments)

        self._write_rule_header(node)
        self._writeline()
        self._indent()

        self._write_meta_section(node)
        self._write_rule_pragmas(node, "before_strings")
        self._write_strings_section(node)
        self._write_rule_pragmas(node, "after_strings")
        self._write_rule_pragmas(node, "before_condition")
        self._write_condition_section(node)

        # Close rule
        self._writeline("}")

        return ""

    def _write_rule_header(self, node: Rule) -> None:
        """Write rule modifiers, name, tags, and opening brace."""
        modifiers = format_rule_modifiers(node.modifiers)
        if modifiers:
            self._write(f"{modifiers} ")

        rule_name = validate_yara_identifier(node.name, "rule")
        self._write(f"rule {rule_name}")

        if node.tags:
            self._write(" : ")
            self._write(format_rule_tags(node.tags))

        self._write(" {")

        if node.trailing_comment:
            self._write_comment(node.trailing_comment, inline=True)

    def _write_rule_pragmas(self, node: Rule, position: str) -> None:
        for pragma in node.pragmas:
            if pragma.position != position:
                continue
            self._write_leading_comments(getattr(pragma, "leading_comments", []))
            rendered = self.visit(pragma)
            if rendered:
                self._writeline(rendered)
            trailing = getattr(pragma, "trailing_comment", None)
            if trailing:
                self._write_comment(trailing, inline=True)

    def _write_meta_section(self, node: Rule) -> None:
        """Write the meta section with comments."""
        if not node.meta:
            return

        self._writeline("meta:")
        self._indent()

        for meta in node.meta:
            leading = getattr(meta, "leading_comments", [])
            self._write_leading_comments(leading)
            if hasattr(meta, "accept"):
                self.visit(meta)
            elif hasattr(meta, "key"):
                self._write_meta_item(meta.key, meta.value, getattr(meta, "scope", None))
            trailing = getattr(meta, "trailing_comment", None)
            if trailing:
                self._write_comment(trailing, inline=True)
            self._writeline()

        self._dedent()

    def _write_strings_section(self, node: Rule) -> None:
        """Write the strings section with comments."""
        if not node.strings:
            return
        validate_string_identifiers(node.strings)

        self._writeline("strings:")
        self._indent()

        for string_def in node.strings:
            self._write_leading_comments(string_def.leading_comments)
            self.visit(string_def)
            if string_def.trailing_comment:
                self._write_comment(string_def.trailing_comment, inline=True)
            self._writeline()

        self._dedent()

    def _write_condition_section(self, node: Rule) -> None:
        """Write the condition section with comments."""
        if not node.condition:
            return

        self._writeline("condition:")
        self._indent()

        if hasattr(node.condition, "leading_comments"):
            self._write_leading_comments(node.condition.leading_comments)

        condition_str = self.visit(node.condition)
        trailing = getattr(node.condition, "trailing_comment", None)
        if condition_str:
            indent = " " * (self.indent_level * self.indent_size)
            if "\n" in condition_str:
                lines = condition_str.splitlines()
                for index, line in enumerate(lines):
                    self._write(indent)
                    self._write(line)
                    if trailing and index == len(lines) - 1:
                        self._write_comment(trailing, inline=True)
                    self._writeline()
            else:
                self._write(indent)
                self._write(condition_str)
                if trailing:
                    self._write_comment(trailing, inline=True)
                self._writeline()
        elif trailing:
            self._write_comment(trailing)
        else:
            self._writeline()

        self._dedent()

    def _write_meta_item(self, key: str, value: any, scope: object | None = None) -> None:
        """Write a meta item."""
        # Add indentation manually
        indent = " " * (self.indent_level * self.indent_size)
        self._write(indent)
        self._write(f"{format_meta_key(key, scope)} = ")
        self._write(format_meta_literal(value, preserve_quoted=True))

    def visit_plain_string(self, node: PlainString) -> str:
        """Generate code for PlainString with comments."""
        from yaraast.codegen.generator_helpers import escape_plain_string_value

        validate_plain_string_modifiers(node.modifiers)

        # Add indentation manually
        indent = " " * (self.indent_level * self.indent_size)
        self._write(indent)
        identifier = output_string_identifier(node)
        self._write(f'{identifier} = "{escape_plain_string_value(node.value)}"')

        # Write modifiers
        for modifier in node.modifiers:
            self._write(" ")
            modifier_str = self.visit(modifier)
            self._write(modifier_str)

        return ""

    def visit_hex_string(self, node: HexString) -> str:
        """Generate code for HexString with comments."""
        validate_hex_string_modifiers(node.modifiers)

        # Add indentation manually
        indent = " " * (self.indent_level * self.indent_size)
        self._write(indent)
        self._write(f"{output_string_identifier(node)} = {{ ")

        # Generate hex tokens
        for i, token in enumerate(node.tokens):
            if i > 0:
                self._write(" ")
            token_str = self.visit(token)
            self._write(token_str)

        self._write(" }")

        # Write modifiers
        for modifier in node.modifiers:
            self._write(" ")
            modifier_str = self.visit(modifier)
            self._write(modifier_str)

        return ""

    def visit_regex_string(self, node: RegexString) -> str:
        """Generate code for RegexString with comments."""
        validate_regex_string_modifiers(node.modifiers)

        # Add indentation manually
        indent = " " * (self.indent_level * self.indent_size)
        self._write(indent)
        regex = escape_regex_delimiter(node.regex)
        self._write(f"{output_string_identifier(node)} = /{regex}/")

        # Write regex modifiers
        if node.modifiers:
            self._write(format_regex_modifiers(node.modifiers, self.visit))

        return ""

    def visit_meta(self, node: Meta) -> str:
        """Generate code for Meta with comments."""
        # Add indentation manually
        indent = " " * (self.indent_level * self.indent_size)
        self._write(indent)
        self._write(f"{format_meta_key(node.key, getattr(node, 'scope', None))} = ")
        self._write(format_meta_literal(node.value, preserve_quoted=True))

        return ""

    def visit_with_statement(self, node: WithStatement) -> str:
        declarations = ", ".join(self.visit(declaration) for declaration in node.declarations)
        return f"with {declarations}: {self.visit(node.body)}"

    def visit_with_declaration(self, node: WithDeclaration) -> str:
        return f"{node.identifier} = {self.visit(node.value)}"

    def visit_array_comprehension(self, node: ArrayComprehension) -> str:
        result = (
            f"[{self.visit(node.expression)} for {node.variable} " f"in {self.visit(node.iterable)}"
        )
        if node.condition:
            result += f" if {self.visit(node.condition)}"
        return result + "]"

    def visit_dict_comprehension(self, node: DictComprehension) -> str:
        variables = (
            f"{node.key_variable}, {node.value_variable}"
            if node.value_variable
            else node.key_variable
        )
        result = (
            f"{{{self.visit(node.key_expression)}: {self.visit(node.value_expression)} "
            f"for {variables} in {self.visit(node.iterable)}"
        )
        if node.condition:
            result += f" if {self.visit(node.condition)}"
        return result + "}"

    def visit_tuple_expression(self, node: TupleExpression) -> str:
        if not node.elements:
            return "()"
        elements = [self.visit(element) for element in node.elements]
        if len(elements) == 1:
            return f"({elements[0]},)"
        return f"({', '.join(elements)})"

    def visit_tuple_indexing(self, node: TupleIndexing) -> str:
        from yaraast.ast.expressions import FunctionCall, Identifier
        from yaraast.yarax.ast_nodes import TupleExpression

        tuple_str = self.visit(node.tuple_expr)
        index_str = self.visit(node.index)
        if isinstance(node.tuple_expr, FunctionCall | Identifier | TupleExpression):
            return f"{tuple_str}[{index_str}]"
        return f"({tuple_str})[{index_str}]"

    def visit_list_expression(self, node: ListExpression) -> str:
        return f"[{', '.join(self.visit(element) for element in node.elements)}]"

    def visit_dict_expression(self, node: DictExpression) -> str:
        from yaraast.yarax.ast_nodes import SpreadOperator

        items = [
            self.visit(item.value) if isinstance(item.value, SpreadOperator) else self.visit(item)
            for item in node.items
        ]
        return f"{{{', '.join(items)}}}"

    def visit_dict_item(self, node: DictItem) -> str:
        return f"{self.visit(node.key)}: {self.visit(node.value)}"

    def visit_slice_expression(self, node: SliceExpression) -> str:
        parts = [
            self.visit(node.start) if node.start is not None else "",
            self.visit(node.stop) if node.stop is not None else "",
        ]
        if node.step is not None:
            parts.append(self.visit(node.step))
        return f"{self.visit(node.target)}[{':'.join(parts)}]"

    def visit_lambda_expression(self, node: LambdaExpression) -> str:
        parameters = ", ".join(node.parameters)
        if parameters:
            return f"lambda {parameters}: {self.visit(node.body)}"
        return f"lambda: {self.visit(node.body)}"

    def visit_pattern_match(self, node: PatternMatch) -> str:
        lines = [f"match {self.visit(node.value)} {{"]
        case_indent = " " * self.indent_size
        lines.extend(f"{case_indent}{self.visit(case)}," for case in node.cases)
        if node.default:
            lines.append(f"{case_indent}_ => {self.visit(node.default)},")
        lines.append("}")
        return "\n".join(lines)

    def visit_match_case(self, node: MatchCase) -> str:
        return f"{self.visit(node.pattern)} => {self.visit(node.result)}"

    def visit_spread_operator(self, node: SpreadOperator) -> str:
        prefix = "**" if node.is_dict else "..."
        return f"{prefix}{self.visit(node.expression)}"
