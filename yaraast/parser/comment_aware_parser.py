"""Comment-aware YARA parser."""

from __future__ import annotations

from typing import TYPE_CHECKING, Any, cast

from yaraast.ast.base import ASTNode, Location, YaraFile
from yaraast.ast.comments import Comment, CommentGroup
from yaraast.ast.extern import ExternImport
from yaraast.ast.meta import Meta
from yaraast.ast.modifiers import MetaScope
from yaraast.lexer.comment_preserving_lexer import CommentPreservingLexer
from yaraast.lexer.tokens import Token, TokenType
from yaraast.parser._shared import ParserError
from yaraast.parser.comment_aware_helpers import (
    collect_leading_comments,
    collect_trailing_comment,
    extract_comment_tokens,
    parse_regex_value,
)
from yaraast.parser.hex_parser import HexParseError, HexStringParser
from yaraast.parser.parser import Parser

if TYPE_CHECKING:
    from yaraast.ast.expressions import Expression
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
        extern_imports = []
        extern_rules = []
        namespaces = []
        pragmas = []
        top_level_nodes = []
        self._extern_rule_names = set()

        while not self._is_at_end():
            if self._check_file_pragma():
                pragma = self._parse_file_pragma()
                pragmas.append(pragma)
                top_level_nodes.append(pragma)
            elif self._match(TokenType.IMPORT):
                parsed_import = self._parse_import()
                if isinstance(parsed_import, ExternImport):
                    extern_imports.append(parsed_import)
                    self._register_extern_import(parsed_import)
                else:
                    imports.append(parsed_import)
                top_level_nodes.append(parsed_import)
            elif self._match(TokenType.INCLUDE):
                include = self._parse_include()
                includes.append(include)
                top_level_nodes.append(include)
            elif self._check_identifier_value("namespace"):
                namespace = self._parse_extern_namespace()
                namespaces.append(namespace)
                top_level_nodes.append(namespace)
            elif self._check_identifier_value("extern"):
                extern_rule = self._parse_extern_rule()
                self._append_extern_rule(namespaces, extern_rules, extern_rule)
                self._register_extern_rule(extern_rule)
                top_level_nodes.append(extern_rule)
            elif (
                self._check(TokenType.RULE)
                or self._check(TokenType.PRIVATE)
                or self._check(TokenType.GLOBAL)
            ):
                rule = self._parse_rule()
                rules.append(rule)
                top_level_nodes.append(rule)
            else:
                from yaraast.parser.parser import ParserError

                msg = f"Unexpected token: {self._peek().value}"
                raise ParserError(msg, self._peek())

        yara_file = YaraFile(
            imports=imports,
            includes=includes,
            rules=rules,
            extern_rules=extern_rules,
            extern_imports=extern_imports,
            pragmas=pragmas,
            namespaces=namespaces,
        )
        if top_level_nodes:
            self._set_node_location_from_nodes(yara_file, top_level_nodes[0], top_level_nodes[-1])

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
        self._parsed_rule_pragmas = []
        meta, strings, condition = self._parse_rule_sections_with_comments()
        pragmas = self._parsed_rule_pragmas
        if condition is None:
            msg = "Expected condition section"
            raise ParserError(msg, self._peek())
        self._expect_rbrace_with_recovery()
        condition = self._ensure_condition(condition)

        rule = Rule(
            name=name,
            modifiers=modifiers,
            tags=tags,
            meta=meta,
            strings=strings,
            condition=condition,
            pragmas=pragmas,
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
            if not self._peek() or self._peek().type != TokenType.IDENTIFIER:
                msg = "Expected tag name after ':'"
                raise ParserError(msg, self._peek())
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
        seen_meta = False
        seen_strings = False
        seen_condition = False

        while not self._check(TokenType.RBRACE) and not self._is_at_end():
            if self._match(TokenType.META):
                section_token = self._previous()
                if seen_meta:
                    msg = "Duplicate meta section"
                    raise ParserError(msg, section_token)
                if seen_strings or seen_condition:
                    msg = "Unexpected meta section"
                    raise ParserError(msg, section_token)
                self._expect_section_colon("meta")
                meta = self._parse_meta_section()
                if not meta:
                    msg = "Expected meta entry"
                    raise ParserError(msg, self._peek())
                seen_meta = True
            elif self._match(TokenType.STRINGS):
                section_token = self._previous()
                if seen_strings:
                    msg = "Duplicate strings section"
                    raise ParserError(msg, section_token)
                if seen_condition:
                    msg = "Unexpected strings section"
                    raise ParserError(msg, section_token)
                self._expect_section_colon("strings")
                strings = self._parse_strings_section()
                if not strings:
                    msg = "Expected string definition"
                    raise ParserError(msg, self._peek())
                seen_strings = True
            elif self._check_file_pragma():
                self._parse_in_rule_pragma(strings)
            elif self._match(TokenType.CONDITION):
                section_token = self._previous()
                if seen_condition:
                    msg = "Duplicate condition section"
                    raise ParserError(msg, section_token)
                self._expect_section_colon("condition")
                condition = self._parse_condition_with_comments()
                seen_condition = True
            else:
                msg = f"Unexpected section: {self._peek().value}"
                raise ParserError(msg, self._peek())

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
        if self._match(TokenType.RBRACE):
            return

        error_token = self._peek()
        attempts = 0
        while not self._is_at_end() and attempts < 1000:
            if self._match(TokenType.RBRACE):
                return
            self._advance()
            attempts += 1

        msg = "Expected '}' at end of rule"
        raise ParserError(msg, error_token)

    def _ensure_condition(self, condition: Expression | None) -> Expression:
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
        used_identifiers = self._reserved_string_identifiers()

        while self._peek() and self._peek().type == TokenType.STRING_IDENTIFIER:
            start_token = self._peek()
            start_line = start_token.line if start_token else 1

            # Collect leading comments
            leading_comments = self._collect_leading_comments(start_line)

            identifier = self._peek().value
            self._advance()

            # Generate unique identifier for anonymous strings
            is_anonymous = identifier == "$"
            if is_anonymous:
                identifier, anonymous_counter = self._next_anonymous_identifier(
                    anonymous_counter,
                    used_identifiers,
                )

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
                if not hex_tokens:
                    msg = "Empty hex string"
                    raise ParserError(msg, self._previous())
                modifiers = self._parse_string_modifiers()
                string_def = HexString(
                    identifier=identifier, tokens=hex_tokens, modifiers=modifiers
                )
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

            if is_anonymous:
                string_def.is_anonymous = True

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
        from yaraast.parser._shared import ParserError

        modifiers: list[StringModifier] = []
        while self._peek() and self._peek().type in (
            TokenType.NOCASE,
            TokenType.WIDE,
            TokenType.ASCII,
            TokenType.FULLWORD,
            TokenType.BASE64,
            TokenType.BASE64WIDE,
            TokenType.XOR_MOD,
            TokenType.PRIVATE,
        ):
            mod_name = self._peek().value
            self._advance()
            mod_name_lower = str(mod_name).lower()

            if mod_name_lower in {"xor", "base64", "base64wide"} and self._match(TokenType.LPAREN):
                value = self._parse_string_modifier_parameter(mod_name_lower)

                if not self._match(TokenType.RPAREN):
                    msg = f"Expected ')' after {mod_name_lower} parameter"
                    raise ParserError(msg, self._peek())
                modifiers.append(StringModifier.from_name_value(mod_name_lower, value))
            else:
                modifiers.append(StringModifier.from_name_value(mod_name))

        return modifiers

    def _parse_string_modifier_parameter(self, mod_name: str) -> object:
        from yaraast.lexer.tokens import TokenType
        from yaraast.parser._shared import ParserError

        if mod_name != "xor":
            if self._match(TokenType.STRING):
                return self._previous().value
            msg = f"Expected string in {mod_name} parameter"
            raise ParserError(msg, self._peek())

        if not self._match(TokenType.INTEGER):
            msg = "Expected integer or range in xor"
            raise ParserError(msg, self._peek())

        min_val = self._previous().value
        if not self._match(TokenType.MINUS):
            return min_val

        if not self._match(TokenType.INTEGER):
            msg = "Expected integer after '-'"
            raise ParserError(msg, self._peek())

        max_val = self._previous().value
        return (min_val, max_val)

    def _parse_hex_tokens(self, hex_content: str):
        """Parse hex string tokens."""
        try:
            return HexStringParser(error_token=self._peek()).parse(hex_content)
        except HexParseError as e:
            raise ParserError(str(e), self._peek()) from e

    def _parse_regex_value(self, regex_val: str):
        """Parse regex value and extract modifiers."""
        return parse_regex_value(regex_val)

    def _parse_meta_section(self) -> list[Meta]:
        """Parse meta section with comment preservation."""
        from yaraast.lexer.tokens import TokenType

        meta_list = []

        while self._peek() and self._check_meta_entry_start():
            start_token = self._peek()
            start_line = start_token.line if start_token else 1

            # Collect leading comments
            leading_comments = self._collect_leading_comments(start_line)

            scope = self._parse_meta_scope_prefix()

            if not self._match(TokenType.IDENTIFIER):
                msg = "Expected meta key after scope"
                raise Exception(msg)

            key = str(self._previous().value)

            if not self._match(TokenType.ASSIGN):
                msg = "Expected '=' in meta"
                raise Exception(msg)

            # Parse value
            if self._match(TokenType.MINUS):
                if self._match(TokenType.INTEGER):
                    value = -self._previous().value
                else:
                    msg = "Expected integer after '-' in meta value"
                    raise Exception(msg)
            elif self._match(TokenType.STRING) or self._match(TokenType.INTEGER):
                value = self._previous().value
            elif self._match(TokenType.BOOLEAN_TRUE):
                value = True
            elif self._match(TokenType.BOOLEAN_FALSE):
                value = False
            else:
                msg = "Expected meta value"
                raise Exception(msg)

            meta = Meta(key=key, value=value)
            cast(Any, meta).scope = MetaScope.from_string(scope) if scope else MetaScope.PUBLIC
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

    def _check_meta_entry_start(self) -> bool:
        from yaraast.lexer.tokens import TokenType

        if self._check(TokenType.IDENTIFIER):
            return True
        return self._check(TokenType.PRIVATE)

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
