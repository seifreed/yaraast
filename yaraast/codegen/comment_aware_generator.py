"""Comment-aware code generator for YARA rules."""

from __future__ import annotations

from typing import TYPE_CHECKING

from yaraast.ast.comments import Comment, CommentGroup
from yaraast.codegen.generator import CodeGenerator
from yaraast.codegen.generator_helpers import escape_regex_delimiter, format_regex_modifiers

if TYPE_CHECKING:
    from yaraast.ast.base import YaraFile
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

    def generate(self, node: YaraFile) -> str:
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
        # Write leading comments
        self._write_leading_comments(node.leading_comments)

        # Write imports
        for imp in node.imports:
            self._write_leading_comments(imp.leading_comments)
            self.visit(imp)
            if imp.trailing_comment:
                self._write_comment(imp.trailing_comment, inline=True)
            self._writeline()

        if node.imports:
            self._writeline()

        # Write includes
        for inc in node.includes:
            self._write_leading_comments(inc.leading_comments)
            self.visit(inc)
            if inc.trailing_comment:
                self._write_comment(inc.trailing_comment, inline=True)
            self._writeline()

        if node.includes:
            self._writeline()

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
        self._write_strings_section(node)
        self._write_condition_section(node)

        # Close rule
        self._writeline("}")

        return ""

    def _write_rule_header(self, node: Rule) -> None:
        """Write rule modifiers, name, tags, and opening brace."""
        if node.modifiers:
            self._write(" ".join(str(m) for m in node.modifiers) + " ")

        self._write(f"rule {node.name}")

        if node.tags:
            self._write(" : ")
            self._write(
                " ".join(tag.name if hasattr(tag, "name") else str(tag) for tag in node.tags),
            )

        self._write(" {")

        if node.trailing_comment:
            self._write_comment(node.trailing_comment, inline=True)

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
                self._write_meta_item(meta.key, meta.value)
            trailing = getattr(meta, "trailing_comment", None)
            if trailing:
                self._write_comment(trailing, inline=True)
            self._writeline()

        self._dedent()

    def _write_strings_section(self, node: Rule) -> None:
        """Write the strings section with comments."""
        if not node.strings:
            return

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

    def _write_meta_item(self, key: str, value: any) -> None:
        """Write a meta item."""
        from yaraast.codegen.generator_helpers import escape_plain_string_value

        # Add indentation manually
        indent = " " * (self.indent_level * self.indent_size)
        self._write(indent)
        self._write(f"{key} = ")

        if isinstance(value, str):
            # Check if already quoted
            if not (value.startswith('"') and value.endswith('"')):
                self._write(f'"{escape_plain_string_value(value)}"')
            else:
                self._write(value)
        elif isinstance(value, bool):
            self._write("true" if value else "false")
        else:
            self._write(str(value))

    def visit_plain_string(self, node: PlainString) -> str:
        """Generate code for PlainString with comments."""
        from yaraast.codegen.generator_helpers import escape_plain_string_value

        # Add indentation manually
        indent = " " * (self.indent_level * self.indent_size)
        self._write(indent)
        self._write(f'{node.identifier} = "{escape_plain_string_value(node.value)}"')

        # Write modifiers
        for modifier in node.modifiers:
            self._write(" ")
            modifier_str = self.visit(modifier)
            self._write(modifier_str)

        return ""

    def visit_hex_string(self, node: HexString) -> str:
        """Generate code for HexString with comments."""
        # Add indentation manually
        indent = " " * (self.indent_level * self.indent_size)
        self._write(indent)
        self._write(f"{node.identifier} = {{ ")

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
        # Add indentation manually
        indent = " " * (self.indent_level * self.indent_size)
        self._write(indent)
        regex = escape_regex_delimiter(node.regex)
        self._write(f"{node.identifier} = /{regex}/")

        # Write regex modifiers
        if node.modifiers:
            self._write(format_regex_modifiers(node.modifiers, self.visit))

        return ""

    def visit_meta(self, node: Meta) -> str:
        """Generate code for Meta with comments."""
        from yaraast.codegen.generator_helpers import escape_plain_string_value

        # Add indentation manually
        indent = " " * (self.indent_level * self.indent_size)
        self._write(indent)
        self._write(f"{node.key} = ")

        if isinstance(node.value, str):
            if not (node.value.startswith('"') and node.value.endswith('"')):
                self._write(f'"{escape_plain_string_value(node.value)}"')
            else:
                self._write(node.value)
        elif isinstance(node.value, bool):
            self._write("true" if node.value else "false")
        else:
            self._write(str(node.value))

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
        lines.extend(f"    {self.visit(case)}," for case in node.cases)
        if node.default:
            lines.append(f"    _ => {self.visit(node.default)},")
        lines.append("}")
        return "\n".join(lines)

    def visit_match_case(self, node: MatchCase) -> str:
        return f"{self.visit(node.pattern)} => {self.visit(node.result)}"

    def visit_spread_operator(self, node: SpreadOperator) -> str:
        prefix = "**" if node.is_dict else "..."
        return f"{prefix}{self.visit(node.expression)}"
