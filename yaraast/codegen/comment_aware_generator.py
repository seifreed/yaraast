"""Comment-aware code generator for YARA rules."""

from io import StringIO
from typing import Any, Dict, List, Optional, Set, Tuple, Union

from yaraast.ast.base import ASTNode, Location, YaraFile
from yaraast.ast.comments import Comment
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
    SetExpression,
    StringCount,
    StringIdentifier,
    StringLength,
    StringLiteral,
    StringOffset,
    UnaryExpression,
)
from yaraast.ast.meta import Meta
from yaraast.ast.modules import DictionaryAccess, ModuleReference
from yaraast.ast.rules import Import, Include, Rule, Tag
from yaraast.ast.strings import (
    HexAlternative,
    HexByte,
    HexJump,
    HexNibble,
    HexString,
    HexToken,
    HexWildcard,
    PlainString,
    RegexString,
    StringDefinition,
    StringModifier,
)
from yaraast.codegen.generator import CodeGenerator


class CommentAwareCodeGenerator(CodeGenerator):
    """Generate YARA code with preserved comments."""

    def __init__(self, indent_size: int = 4, preserve_comments: bool = True):
        super().__init__(indent_size)
        self.preserve_comments = preserve_comments

    def _write_comments(self, comments: List[Comment], inline: bool = False) -> None:
        """Write comments to output."""
        if not self.preserve_comments or not comments:
            return

        for comment in comments:
            if inline:
                self._write(f"  // {comment.text}")
            else:
                if comment.is_multiline:
                    self._writeline(f"/* {comment.text} */")
                else:
                    self._writeline(f"// {comment.text}")

    def _write_trailing_comment(self, comment: Optional[Comment]) -> None:
        """Write trailing comment."""
        if not self.preserve_comments or not comment:
            return

        if comment.is_multiline:
            self._write(f"  /* {comment.text} */")
        else:
            self._write(f"  // {comment.text}")

    def visit_rule(self, node: Rule) -> str:
        """Generate code for Rule with comments."""
        # Write leading comments
        self._write_comments(node.leading_comments)

        # Write rule declaration
        if node.modifiers:
            self._write(" ".join(node.modifiers) + " ")

        self._write(f"rule {node.name}")

        if node.tags:
            self._write(" : " + " ".join(node.tags))

        self._writeline(" {")
        self._indent()

        # Meta section
        if node.meta:
            self._writeline("meta:")
            self._indent()
            for meta in node.meta:
                self.visit(meta)
            self._dedent()
            self._writeline()

        # Strings section
        if node.strings:
            self._writeline("strings:")
            self._indent()
            for string in node.strings:
                # Check for leading comments on string definition
                if hasattr(string, 'leading_comments'):
                    self._write_comments(string.leading_comments)

                self.visit(string)

                # Check for trailing comment on string definition
                if hasattr(string, 'trailing_comment') and string.trailing_comment:
                    self._write_trailing_comment(string.trailing_comment)

                self._writeline()
            self._dedent()
            self._writeline()

        # Condition section
        self._writeline("condition:")
        self._indent()
        self.visit(node.condition)
        self._dedent()

        self._dedent()
        self._write("}")

        return self.buffer.getvalue()

    def visit_meta(self, node: Meta) -> str:
        """Generate code for Meta with comments."""
        # Write leading comments
        self._write_comments(node.leading_comments)

        self._write(f"{node.key} = ")
        self.visit(node.value)

        # Write trailing comment
        if node.trailing_comment:
            self._write_trailing_comment(node.trailing_comment)

        return self.buffer.getvalue()

    def visit_plain_string(self, node: PlainString) -> str:
        """Generate code for PlainString with comments."""
        self._write(f'{node.identifier} = "{node.value}"')

        if node.modifiers:
            for modifier in node.modifiers:
                self._write(" ")
                self.visit(modifier)

        return self.buffer.getvalue()

    def visit_hex_string(self, node: HexString) -> str:
        """Generate code for HexString with comments."""
        self._write(f"{node.identifier} = {{ ")

        for i, token in enumerate(node.tokens):
            if i > 0:
                self._write(" ")
            self.visit(token)

        self._write(" }")

        if node.modifiers:
            for modifier in node.modifiers:
                self._write(" ")
                self.visit(modifier)

        return self.buffer.getvalue()

    def visit_regex_string(self, node: RegexString) -> str:
        """Generate code for RegexString with comments."""
        self._write(f'{node.identifier} = /{node.regex}/')

        if node.modifiers:
            for modifier in node.modifiers:
                self._write(" ")
                self.visit(modifier)

        return self.buffer.getvalue()
