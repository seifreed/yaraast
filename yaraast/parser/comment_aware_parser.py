"""Comment-aware YARA parser."""

from __future__ import annotations

from typing import TYPE_CHECKING

from yaraast.ast.base import ASTNode, Location, YaraFile
from yaraast.ast.comments import Comment, CommentGroup
from yaraast.ast.meta import Meta
from yaraast.lexer.comment_preserving_lexer import CommentPreservingLexer
from yaraast.lexer.tokens import Token, TokenType
from yaraast.parser.parser import Parser

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
        self.current = 0
        self.lexer = lexer

        # Separate comment tokens
        self._extract_comment_tokens()

        # Parse the file (same logic as base Parser.parse)
        imports = []
        includes = []
        rules = []

        while not self._is_at_end():
            if self._match(TokenType.IMPORT):
                imports.append(self._parse_import())
            elif self._match(TokenType.INCLUDE):
                includes.append(self._parse_include())
            elif (
                self._check(TokenType.RULE)
                or self._check(TokenType.PRIVATE)
                or self._check(TokenType.GLOBAL)
            ):
                rules.append(self._parse_rule())
            else:
                from yaraast.parser.parser import ParserError

                msg = f"Unexpected token: {self._peek().value}"
                raise ParserError(msg, self._peek())

        yara_file = YaraFile(imports=imports, includes=includes, rules=rules)

        # Attach any remaining comments
        if self.comment_tokens:
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
        from yaraast.lexer.tokens import TokenType

        start_token = self._peek()
        start_line = start_token.line if start_token else 1

        # Collect leading comments
        leading_comments = self._collect_leading_comments(start_line)

        # Parse modifiers
        modifiers = []
        while self._peek() and self._peek().type in (
            TokenType.PRIVATE,
            TokenType.GLOBAL,
        ):
            modifiers.append(self._peek().value)
            self._advance()

        # Expect 'rule'
        if not self._match(TokenType.RULE):
            msg = "Expected 'rule'"
            raise Exception(msg)

        # Parse rule name
        if not self._peek() or self._peek().type != TokenType.IDENTIFIER:
            msg = "Expected rule name"
            raise Exception(msg)

        name = self._peek().value
        self._advance()

        # Parse tags
        tags = []
        if self._match(TokenType.COLON):
            while self._peek() and self._peek().type == TokenType.IDENTIFIER:
                from yaraast.ast.rules import Tag

                tags.append(Tag(name=self._peek().value))
                self._advance()

        # Expect '{'
        if not self._match(TokenType.LBRACE):
            msg = "Expected '{'"
            raise Exception(msg)

        # Parse sections
        meta = []  # Keep as list instead of dict
        strings = []
        condition = None

        while not self._check(TokenType.RBRACE) and not self._is_at_end():
            if self._match(TokenType.META):
                if not self._match(TokenType.COLON):
                    msg = "Expected ':' after 'meta'"
                    raise Exception(msg)
                meta = self._parse_meta_section()  # Returns list of Meta objects with comments
            elif self._match(TokenType.STRINGS):
                if not self._match(TokenType.COLON):
                    msg = "Expected ':' after 'strings'"
                    raise Exception(msg)
                strings = self._parse_strings_section()
            elif self._match(TokenType.CONDITION):
                if not self._match(TokenType.COLON):
                    msg = "Expected ':' after 'condition'"
                    raise Exception(msg)

                # Collect comments before condition
                cond_start_token = self._peek()
                cond_start_line = cond_start_token.line if cond_start_token else 1
                cond_leading_comments = self._collect_leading_comments(cond_start_line)

                condition = self._parse_condition()

                # Attach comments to condition (dynamic attribute)
                if cond_leading_comments:
                    condition.leading_comments = cond_leading_comments
            else:
                # Try to skip unrecognized tokens
                if self._peek() and self._peek().type != TokenType.RBRACE:
                    self._advance()
                    continue
                break

        # Expect '}'
        if not self._match(TokenType.RBRACE):
            # Try to recover
            attempts = 0
            while not self._is_at_end() and attempts < 1000:
                if self._match(TokenType.RBRACE):
                    break
                self._advance()
                attempts += 1

        # Condition is required
        if condition is None:
            from yaraast.ast.expressions import BooleanLiteral

            condition = BooleanLiteral(value=True)

        from yaraast.ast.rules import Rule

        rule = Rule(
            name=name,
            modifiers=modifiers,
            tags=tags,
            meta=meta,  # Keep as list to preserve comments
            strings=strings,
            condition=condition,
        )

        # Attach leading comments
        if leading_comments:
            rule.leading_comments = leading_comments

        # Check for trailing comment
        if start_token:
            trailing = self._collect_trailing_comment(start_token.line)
            if trailing:
                rule.trailing_comment = trailing

        return rule

    def _parse_strings_section(self) -> list[StringDefinition]:
        """Parse strings section with comment preservation."""
        from yaraast.ast.strings import HexString, PlainString, RegexString
        from yaraast.lexer.tokens import TokenType

        strings = []
        anonymous_counter = 0

        while self._peek() and self._peek().type == TokenType.STRING_IDENTIFIER:
            start_token = self._peek()
            start_line = start_token.line if start_token else 1

            # Collect leading comments
            leading_comments = self._collect_leading_comments(start_line)

            identifier = self._peek().value
            self._advance()

            # Generate unique identifier for anonymous strings
            if identifier == "$":
                anonymous_counter += 1
                identifier = f"$anon_{anonymous_counter}"

            if not self._match(TokenType.ASSIGN):
                msg = "Expected '='"
                raise Exception(msg)

            # Parse string value
            string_def = None
            if self._match(TokenType.STRING):
                value = self._previous().value
                modifiers = self._parse_string_modifiers()
                string_def = PlainString(identifier=identifier, value=value, modifiers=modifiers)
            elif self._match(TokenType.HEX_STRING):
                hex_content = self._previous().value.strip()
                hex_tokens = self._parse_hex_tokens(hex_content)
                string_def = HexString(identifier=identifier, tokens=hex_tokens)
            elif self._match(TokenType.REGEX):
                regex_val = self._previous().value
                pattern, modifiers = self._parse_regex_value(regex_val)
                # Parse additional YARA modifiers
                modifiers.extend(self._parse_string_modifiers())
                string_def = RegexString(identifier=identifier, regex=pattern, modifiers=modifiers)
            else:
                msg = "Expected string value"
                raise Exception(msg)

            # Attach comments to string definition
            if leading_comments:
                string_def.leading_comments = leading_comments

            # Check for trailing comment on same line
            trailing = self._collect_trailing_comment(start_line)
            if trailing:
                string_def.trailing_comment = trailing

            strings.append(string_def)

        return strings

    def _parse_string_modifiers(self) -> list:
        """Parse string modifiers (nocase, wide, etc.)."""
        from yaraast.ast.strings import StringModifier
        from yaraast.lexer.tokens import TokenType

        modifiers = []
        while self._peek() and self._peek().type in (
            TokenType.NOCASE,
            TokenType.WIDE,
            TokenType.ASCII,
            TokenType.FULLWORD,
            TokenType.BASE64,
            TokenType.BASE64WIDE,
            TokenType.XOR_MOD,
        ):
            mod_name = self._peek().value
            self._advance()

            # Handle XOR with optional parameters
            if mod_name.lower() == "xor" and self._peek() and self._peek().type == TokenType.LPAREN:
                self._advance()  # consume '('
                depth = 1
                while depth > 0 and self._peek():
                    if self._peek().type == TokenType.LPAREN:
                        depth += 1
                    elif self._peek().type == TokenType.RPAREN:
                        depth -= 1
                    self._advance()
                modifiers.append(StringModifier(name="xor"))
            else:
                modifiers.append(StringModifier(name=mod_name))

        return modifiers

    def _parse_hex_tokens(self, hex_content: str):
        """Parse hex string tokens."""
        from yaraast.ast.strings import HexByte, HexWildcard

        hex_tokens = []
        hex_clean = hex_content.replace(" ", "").replace("\t", "").replace("\n", "")

        i = 0
        while i < len(hex_clean):
            if i + 1 < len(hex_clean):
                two_chars = hex_clean[i : i + 2]
                if two_chars == "??":
                    hex_tokens.append(HexWildcard())
                    i += 2
                elif all(c in "0123456789ABCDEFabcdef" for c in two_chars):
                    hex_tokens.append(HexByte(value=int(two_chars, 16)))
                    i += 2
                else:
                    i += 1
            else:
                i += 1

        return hex_tokens

    def _parse_regex_value(self, regex_val: str):
        """Parse regex value and extract modifiers."""
        from yaraast.ast.strings import StringModifier

        pattern = regex_val
        modifiers = []

        # The lexer returns pattern or pattern\x00modifiers
        if "\x00" in regex_val:
            parts = regex_val.split("\x00", 1)
            pattern = parts[0]
            mod_str = parts[1] if len(parts) > 1 else ""
            for m in mod_str:
                if m == "i":
                    modifiers.append(StringModifier(name="nocase"))
                elif m == "s":
                    modifiers.append(StringModifier(name="dotall"))

        return pattern, modifiers

    def _parse_meta_section(self) -> list[Meta]:
        """Parse meta section with comment preservation."""
        from yaraast.lexer.tokens import TokenType

        meta_list = []

        while self._peek() and self._peek().type == TokenType.IDENTIFIER:
            start_token = self._peek()
            start_line = start_token.line if start_token else 1

            # Collect leading comments
            leading_comments = self._collect_leading_comments(start_line)

            key = self._peek().value
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
            trailing = self._collect_trailing_comment(start_line)
            if trailing:
                meta.trailing_comment = trailing

            meta_list.append(meta)

        return meta_list

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
