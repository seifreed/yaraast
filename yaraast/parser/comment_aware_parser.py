"""Comment-aware YARA parser."""

from __future__ import annotations

from typing import TYPE_CHECKING

from yaraast.ast.base import ASTNode, Location, YaraFile
from yaraast.ast.comments import Comment, CommentGroup
from yaraast.ast.meta import Meta
from yaraast.lexer.comment_preserving_lexer import CommentPreservingLexer
from yaraast.lexer.tokens import Token, TokenType
from yaraast.parser.better_parser import Parser

if TYPE_CHECKING:
    from yaraast.ast.rules import Rule
    from yaraast.ast.strings import StringDefinition


class CommentAwareParser(Parser):
    """Parser that preserves and attaches comments to AST nodes."""

    def __init__(self) -> None:
        super().__init__()
        self.pending_comments: list[Token] = []
        self.comment_tokens: list[Token] = []

    def parse(self, text: str) -> YaraFile:
        """Parse YARA rule text with comment preservation."""
        lexer = CommentPreservingLexer(text)
        self.tokens = lexer.tokenize()
        self.position = 0
        self.text = text

        # Separate comment tokens
        self._extract_comment_tokens()

        # Parse the file
        yara_file = self._parse_yara_file()

        # Attach any remaining comments
        if self.pending_comments:
            self._attach_trailing_comments(yara_file)

        return yara_file

    def _extract_comment_tokens(self) -> None:
        """Extract comment tokens from the token stream."""
        non_comment_tokens = []

        for token in self.tokens:
            if token.type == TokenType.COMMENT:
                self.comment_tokens.append(token)
            else:
                non_comment_tokens.append(token)

        self.tokens = non_comment_tokens

    def _collect_leading_comments(self, end_line: int) -> list[Comment]:
        """Collect comments that appear before the given line."""
        comments = []

        for token in self.comment_tokens:
            if token.line < end_line:
                comment = Comment(
                    text=token.value,
                    is_multiline=token.value.startswith("/*"),
                )
                # Set location separately
                comment.location = Location(line=token.line, column=token.column)
                comments.append(comment)

        # Remove collected comments from the list
        self.comment_tokens = [token for token in self.comment_tokens if token.line >= end_line]

        return comments

    def _collect_trailing_comment(self, start_line: int) -> Comment | None:
        """Collect a comment on the same line."""
        for i, token in enumerate(self.comment_tokens):
            if token.line == start_line:
                comment = Comment(
                    text=token.value,
                    is_multiline=token.value.startswith("/*"),
                )
                # Set location separately
                comment.location = Location(line=token.line, column=token.column)
                # Remove from list
                self.comment_tokens.pop(i)
                return comment
        return None

    def _parse_rule(self) -> Rule:
        """Parse a rule with comment preservation."""
        start_token = self._current_token()
        start_line = start_token.line if start_token else 1

        # Collect leading comments
        leading_comments = self._collect_leading_comments(start_line)

        # Parse the rule normally
        rule = super()._parse_rule()

        # Attach leading comments
        if leading_comments:
            rule.leading_comments = leading_comments

        # Check for trailing comment
        if start_token:
            trailing = self._collect_trailing_comment(start_token.line)
            if trailing:
                rule.trailing_comment = trailing

        return rule

    def _parse_string_definition(self) -> StringDefinition:
        """Parse string definition with comments."""
        start_token = self._current_token()
        start_line = start_token.line if start_token else 1

        # Collect leading comments
        leading_comments = self._collect_leading_comments(start_line)

        # Parse the string normally
        string_def = super()._parse_string_definition()

        # Attach comments
        if leading_comments:
            string_def.leading_comments = leading_comments

        # Check for trailing comment
        if start_token:
            trailing = self._collect_trailing_comment(start_token.line)
            if trailing:
                string_def.trailing_comment = trailing

        return string_def

    def _parse_meta_item(self) -> Meta:
        """Parse meta item with comments."""
        start_token = self._current_token()
        start_line = start_token.line if start_token else 1

        # Collect leading comments
        leading_comments = self._collect_leading_comments(start_line)

        # Parse the meta normally
        key = self._current_token().value
        self._advance()

        if not self._match(TokenType.ASSIGN):
            msg = "Expected '=' in meta"
            raise Exception(msg)

        # Parse value
        if self._match(TokenType.STRING) or self._match(TokenType.INTEGER):
            value = self._previous().value
        elif self._match(TokenType.BOOLEAN_TRUE):
            value = True
        elif self._match(TokenType.BOOLEAN_FALSE):
            value = False
        else:
            msg = "Expected meta value"
            raise Exception(msg)

        meta = Meta(key=key, value=value)

        # Attach comments
        if leading_comments:
            meta.leading_comments = leading_comments

        # Check for trailing comment
        if start_token:
            trailing = self._collect_trailing_comment(start_token.line)
            if trailing:
                meta.trailing_comment = trailing

        return meta

    def _attach_trailing_comments(self, node: ASTNode) -> None:
        """Attach any remaining comments as trailing comments."""
        if self.comment_tokens:
            comments = []
            for token in self.comment_tokens:
                comment = Comment(
                    text=token.value,
                    is_multiline=token.value.startswith("/*"),
                )
                # Set location separately
                comment.location = Location(line=token.line, column=token.column)
                comments.append(comment)

            if len(comments) == 1:
                node.trailing_comment = comments[0]
            else:
                node.trailing_comment = CommentGroup(comments=comments)

            self.comment_tokens.clear()
