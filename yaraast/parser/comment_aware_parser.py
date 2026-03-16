"""Comment-aware YARA parser."""

from __future__ import annotations

from typing import TYPE_CHECKING

from yaraast.ast.base import ASTNode, Location, YaraFile
from yaraast.ast.comments import Comment, CommentGroup
from yaraast.ast.meta import Meta
from yaraast.lexer.comment_preserving_lexer import CommentPreservingLexer
from yaraast.lexer.tokens import Token, TokenType
from yaraast.parser.comment_aware_helpers import (
    collect_leading_comments,
    collect_trailing_comment,
    extract_comment_tokens,
    parse_hex_tokens,
    parse_regex_value,
)
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
        if imports or includes or rules:
            start_node = imports[0] if imports else includes[0] if includes else rules[0]
            end_node = rules[-1] if rules else includes[-1] if includes else imports[-1]
            self._set_node_location_from_nodes(yara_file, start_node, end_node)

        # Attach any remaining comments
        if self.comment_tokens:
            self._attach_trailing_comments(yara_file)

        return yara_file

    def _extract_comment_tokens(self) -> None:
        """Extract comment tokens from the token stream."""
        non_comment_tokens, comment_tokens = extract_comment_tokens(self.tokens)
        self.tokens = non_comment_tokens
        self.comment_tokens = comment_tokens

    def _collect_leading_comments(self, end_line: int) -> list[Comment]:
        """Collect comments that appear before the given line."""
        comments = collect_leading_comments(self.comment_tokens, end_line)
        self.comment_tokens = [token for token in self.comment_tokens if token.line >= end_line]
        return comments

    def _collect_trailing_comment(self, start_line: int) -> Comment | None:
        """Collect a comment on the same line."""
        comment, remaining = collect_trailing_comment(self.comment_tokens, start_line)
        self.comment_tokens = remaining
        return comment

    def _parse_rule(self) -> Rule:
        """Parse a rule with comment preservation."""
        from yaraast.ast.rules import Rule

        start_token = self._peek()
        start_line = start_token.line if start_token else 1
        leading_comments = self._collect_leading_comments(start_line)

        modifiers = self._parse_rule_modifiers_with_comments()
        name = self._parse_rule_name_with_comments()
        tags = self._parse_rule_tags_with_comments()

        self._expect_lbrace()
        meta, strings, condition = self._parse_rule_sections_with_comments()
        self._expect_rbrace_with_recovery()
        condition = self._ensure_condition(condition)

        rule = Rule(
            name=name,
            modifiers=modifiers,
            tags=tags,
            meta=meta,
            strings=strings,
            condition=condition,
        )
        self._set_node_location_from_tokens(rule, start_token, self._previous())

        self._attach_rule_comments(rule, leading_comments, start_token)
        return rule

    def _parse_rule_modifiers_with_comments(self) -> list[str]:
        """Parse rule modifiers (private, global) with comment preservation."""
        modifiers = []
        while self._peek() and self._peek().type in (
            TokenType.PRIVATE,
            TokenType.GLOBAL,
        ):
            modifiers.append(self._peek().value)
            self._advance()
        return modifiers

    def _parse_rule_name_with_comments(self) -> str:
        """Parse rule name with comment preservation."""
        if not self._match(TokenType.RULE):
            msg = "Expected 'rule'"
            raise Exception(msg)

        if not self._peek() or self._peek().type != TokenType.IDENTIFIER:
            msg = "Expected rule name"
            raise Exception(msg)

        name = self._peek().value
        self._advance()
        return name

    def _parse_rule_tags_with_comments(self) -> list:
        """Parse rule tags with comment preservation."""
        from yaraast.ast.rules import Tag

        tags = []
        if self._match(TokenType.COLON):
            while self._peek() and self._peek().type == TokenType.IDENTIFIER:
                tags.append(
                    self._set_node_location_from_token(Tag(name=self._peek().value), self._peek())
                )
                self._advance()
        return tags

    def _expect_lbrace(self) -> None:
        """Expect and consume left brace."""
        if not self._match(TokenType.LBRACE):
            msg = "Expected '{'"
            raise Exception(msg)

    def _parse_rule_sections_with_comments(self) -> tuple:
        """Parse rule sections (meta, strings, condition) with comments."""
        meta = []
        strings = []
        condition = None

        while not self._check(TokenType.RBRACE) and not self._is_at_end():
            if self._match(TokenType.META):
                self._expect_section_colon("meta")
                meta = self._parse_meta_section()
            elif self._match(TokenType.STRINGS):
                self._expect_section_colon("strings")
                strings = self._parse_strings_section()
            elif self._match(TokenType.CONDITION):
                self._expect_section_colon("condition")
                condition = self._parse_condition_with_comments()
            else:
                # Inside this loop, the current token is neither RBRACE nor EOF, so
                # recovery can always make progress by consuming one token.
                self._skip_unrecognized_token()

        return meta, strings, condition

    def _expect_section_colon(self, section_name: str) -> None:
        """Expect and consume colon after section name."""
        if not self._match(TokenType.COLON):
            msg = f"Expected ':' after '{section_name}'"
            raise Exception(msg)

    def _parse_condition_with_comments(self):
        """Parse condition section with comment preservation."""
        cond_start_token = self._peek()
        cond_start_line = cond_start_token.line if cond_start_token else 1
        cond_leading_comments = self._collect_leading_comments(cond_start_line)

        condition = self._parse_condition()

        if cond_leading_comments:
            condition.leading_comments = cond_leading_comments

        return condition

    def _skip_unrecognized_token(self) -> bool:
        """Skip unrecognized token. Returns False if should break loop."""
        if self._peek() and self._peek().type != TokenType.RBRACE:
            self._advance()
            return True
        return False

    def _expect_rbrace_with_recovery(self) -> None:
        """Expect right brace with error recovery."""
        if not self._match(TokenType.RBRACE):
            attempts = 0
            while not self._is_at_end() and attempts < 1000:
                if self._match(TokenType.RBRACE):
                    break
                self._advance()
                attempts += 1

    def _ensure_condition(self, condition):
        """Ensure condition is not None, defaulting to true."""
        if condition is None:
            from yaraast.ast.expressions import BooleanLiteral

            literal = BooleanLiteral(value=True)
            if self._peek() is not None:
                self._set_node_location_from_token(literal, self._peek())
            return literal
        return condition

    def _attach_rule_comments(self, rule, leading_comments, start_token) -> None:
        """Attach leading and trailing comments to rule."""
        if leading_comments:
            rule.leading_comments = leading_comments

        if start_token:
            trailing = self._collect_trailing_comment(start_token.line)
            if trailing:
                rule.trailing_comment = trailing

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
            self._set_node_location_from_tokens(string_def, start_token, self._previous())

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
        from yaraast.ast.modifiers import StringModifier
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
                modifiers.append(StringModifier.from_name_value("xor"))
            else:
                modifiers.append(StringModifier.from_name_value(mod_name))

        return modifiers

    def _parse_hex_tokens(self, hex_content: str):
        """Parse hex string tokens."""
        return parse_hex_tokens(hex_content)

    def _parse_regex_value(self, regex_val: str):
        """Parse regex value and extract modifiers."""
        return parse_regex_value(regex_val)

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
            self._set_node_location_from_tokens(meta, start_token, self._previous())

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
        """Attach any remaining comments as trailing comments on the file node."""
        if self.comment_tokens:
            from yaraast.ast.comments import Comment

            comments = []
            for token in self.comment_tokens:
                comment = Comment(
                    text=token.value,
                    is_multiline=token.value.startswith("/*"),
                )
                comment.location = Location(
                    line=token.line,
                    column=token.column,
                    end_line=token.line,
                    end_column=token.column + len(token.value),
                )
                comments.append(comment)

            if len(comments) == 1:
                node.trailing_comment = comments[0]
            else:
                node.trailing_comment = CommentGroup(comments=comments)

            self.comment_tokens.clear()
