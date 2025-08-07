"""Comment-aware code generator for YARA rules."""

from __future__ import annotations

from typing import TYPE_CHECKING

from yaraast.ast.comments import Comment, CommentGroup
from yaraast.codegen.generator import CodeGenerator

if TYPE_CHECKING:
    from yaraast.ast.base import YaraFile
    from yaraast.ast.meta import Meta
    from yaraast.ast.rules import Rule
    from yaraast.ast.strings import HexString, PlainString, RegexString


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

        # Write rule header
        if node.modifiers:
            self._write(" ".join(node.modifiers) + " ")

        self._write(f"rule {node.name}")

        # Write tags
        if node.tags:
            self._write(" : ")
            self._write(
                " ".join(tag.name if hasattr(tag, "name") else str(tag) for tag in node.tags),
            )

        # Write opening brace
        self._write(" {")

        # Write trailing comment for rule header
        if node.trailing_comment:
            self._write_comment(node.trailing_comment, inline=True)

        self._writeline()
        self._indent()

        # Write meta section
        if node.meta:
            self._writeline("meta:")
            self._indent()

            if isinstance(node.meta, dict):
                for key, value in node.meta.items():
                    self._write_meta_item(key, value)
            else:
                for meta in node.meta:
                    self._write_leading_comments(meta.leading_comments)
                    self.visit(meta)
                    if meta.trailing_comment:
                        self._write_comment(meta.trailing_comment, inline=True)
                    self._writeline()

            self._dedent()
            self._writeline()

        # Write strings section
        if node.strings:
            self._writeline("strings:")
            self._indent()

            for string_def in node.strings:
                self._write_leading_comments(string_def.leading_comments)
                self.visit(string_def)
                if string_def.trailing_comment:
                    self._write_comment(string_def.trailing_comment, inline=True)
                self._writeline()

            self._dedent()
            self._writeline()

        # Write condition
        self._writeline("condition:")
        self._indent()

        # Check if condition has comments
        if hasattr(node.condition, "leading_comments"):
            self._write_leading_comments(node.condition.leading_comments)

        self._write("")
        condition_str = self.visit(node.condition)
        self._write(condition_str)

        if hasattr(node.condition, "trailing_comment") and node.condition.trailing_comment:
            self._write_comment(node.condition.trailing_comment, inline=True)

        self._writeline()
        self._dedent()

        # Close rule
        self._write("}")
        self._writeline()

        return ""

    def _write_meta_item(self, key: str, value: any) -> None:
        """Write a meta item."""
        self._write(f"{key} = ")

        if isinstance(value, str):
            # Check if already quoted
            if not (value.startswith('"') and value.endswith('"')):
                self._write(f'"{value}"')
            else:
                self._write(value)
        elif isinstance(value, bool):
            self._write("true" if value else "false")
        else:
            self._write(str(value))

        self._writeline()

    def visit_plain_string(self, node: PlainString) -> str:
        """Generate code for PlainString with comments."""
        self._write(f'{node.identifier} = "{node.value}"')

        # Write modifiers
        for modifier in node.modifiers:
            self._write(" ")
            modifier_str = self.visit(modifier)
            self._write(modifier_str)

        return ""

    def visit_hex_string(self, node: HexString) -> str:
        """Generate code for HexString with comments."""
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
        self._write(f"{node.identifier} = /{node.regex}/")

        # Write regex modifiers
        if node.modifiers:
            for mod in node.modifiers:
                if isinstance(mod, str):
                    self._write(mod)
                else:
                    self._write(" ")
                    mod_str = self.visit(mod)
                    self._write(mod_str)

        return ""

    def visit_meta(self, node: Meta) -> str:
        """Generate code for Meta with comments."""
        self._write(f"{node.key} = ")

        if isinstance(node.value, str):
            if not (node.value.startswith('"') and node.value.endswith('"')):
                self._write(f'"{node.value}"')
            else:
                self._write(node.value)
        elif isinstance(node.value, bool):
            self._write("true" if node.value else "false")
        else:
            self._write(str(node.value))

        return ""


# Alias for compatibility
CommentAwareGenerator = CommentAwareCodeGenerator
