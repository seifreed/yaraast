"""Rule and section parsing helpers."""

from __future__ import annotations

from typing import Any

from yaraast.ast.conditions import Condition
from yaraast.ast.extern import ExternImport, ExternNamespace, ExternRule
from yaraast.ast.modifiers import RuleModifier
from yaraast.ast.pragmas import (
    ConditionalDirective,
    DefineDirective,
    IncludeOncePragma,
    Pragma,
    PragmaType,
    UndefDirective,
)
from yaraast.ast.rules import Import, Include, Rule, Tag
from yaraast.ast.strings import StringDefinition
from yaraast.lexer import TokenType

from ._shared import ParserError


class RuleParsingMixin:
    """Mixin with rule, import, include, and meta parsing."""

    def _parse_import(self) -> Import | ExternImport:
        """Parse import statement."""
        start_token = self._previous()
        if not self._match(TokenType.STRING):
            msg = "Expected module name after 'import'"
            raise ParserError(msg, self._peek())

        module = self._previous().value
        rules = self._parse_import_rule_list()
        alias = None

        # Check for 'as alias'
        if self._match(TokenType.AS):
            if not self._match(TokenType.IDENTIFIER):
                msg = "Expected alias after 'as'"
                raise ParserError(msg, self._peek())
            alias = self._previous().value

        if rules is not None:
            return self._set_node_location_from_tokens(
                ExternImport(module_path=module, alias=alias, rules=rules),
                start_token,
                self._previous(),
            )
        return self._set_node_location_from_tokens(
            Import(module=module, alias=alias), start_token, self._previous()
        )

    def _parse_import_rule_list(self) -> list[str] | None:
        """Parse optional selective external import rule list."""
        if not self._match(TokenType.LPAREN):
            return None
        if self._check(TokenType.RPAREN):
            msg = "Expected rule name in import rule list"
            raise ParserError(msg, self._peek())

        rules = []
        while True:
            rules.append(self._parse_qualified_identifier("Expected rule name in import rule list"))
            if not self._match(TokenType.COMMA):
                break

        if not self._match(TokenType.RPAREN):
            msg = "Expected ')' after import rule list"
            raise ParserError(msg, self._peek())
        return rules

    def _parse_include(self) -> Include:
        """Parse include statement."""
        start_token = self._previous()
        if not self._match(TokenType.STRING):
            msg = "Expected file path after 'include'"
            raise ParserError(msg, self._peek())

        path = self._previous().value
        return self._set_node_location_from_tokens(
            Include(path=path), start_token, self._previous()
        )

    def _check_file_pragma(self) -> bool:
        return self._check(TokenType.STRING_COUNT) and str(self._peek().value).startswith("#")

    def _parse_file_pragma(self) -> Pragma:
        """Parse a top-level preprocessor directive or pragma."""
        start_token = self._advance()
        directive = str(start_token.value)[1:]
        arguments = self._parse_pragma_line_arguments(start_token.line)
        end_token = self._previous()

        if directive == "include_once":
            pragma = IncludeOncePragma()
        elif directive == "define":
            pragma = self._parse_define_directive(arguments)
        elif directive == "undef":
            pragma = self._parse_undef_directive(arguments)
        elif directive in {"ifdef", "ifndef"}:
            pragma = self._parse_conditional_directive(directive, arguments)
        elif directive == "endif":
            pragma = ConditionalDirective.endif()
        elif directive == "pragma":
            pragma = self._parse_named_pragma(arguments)
        else:
            pragma = Pragma(
                pragma_type=PragmaType.from_string(directive),
                name=directive,
                arguments=arguments,
            )

        return self._set_node_location_from_tokens(pragma, start_token, end_token)

    def _parse_pragma_line_arguments(self, line: int) -> list[str]:
        arguments = []
        while not self._is_at_end() and self._peek().line == line:
            arguments.append(str(self._advance().value))
        return arguments

    def _parse_define_directive(self, arguments: list[str]) -> DefineDirective:
        if not arguments:
            msg = "Expected macro name after '#define'"
            raise ParserError(msg, self._peek())
        macro_value = " ".join(arguments[1:]) if len(arguments) > 1 else None
        return DefineDirective(arguments[0], macro_value)

    def _parse_undef_directive(self, arguments: list[str]) -> UndefDirective:
        if not arguments:
            msg = "Expected macro name after '#undef'"
            raise ParserError(msg, self._peek())
        return UndefDirective(arguments[0])

    def _parse_conditional_directive(
        self, directive: str, arguments: list[str]
    ) -> ConditionalDirective:
        if not arguments:
            msg = f"Expected condition after '#{directive}'"
            raise ParserError(msg, self._peek())
        pragma_type = PragmaType.IFDEF if directive == "ifdef" else PragmaType.IFNDEF
        return ConditionalDirective(pragma_type, arguments[0])

    def _parse_named_pragma(self, arguments: list[str]) -> Pragma:
        if not arguments:
            msg = "Expected pragma name after '#pragma'"
            raise ParserError(msg, self._peek())
        return Pragma(
            pragma_type=PragmaType.PRAGMA,
            name=arguments[0],
            arguments=arguments[1:],
        )

    def _check_identifier_value(self, value: str) -> bool:
        return self._check(TokenType.IDENTIFIER) and self._peek().value == value

    def _register_extern_import(self, extern_import: ExternImport) -> None:
        for rule_name in extern_import.rules:
            namespace, name = self._split_qualified_rule_name(rule_name)
            self._extern_rule_names.add((namespace, name))
            if extern_import.alias:
                self._extern_rule_names.add((extern_import.alias, name))

    def _register_extern_rule(self, extern_rule: ExternRule) -> None:
        self._extern_rule_names.add((extern_rule.namespace, extern_rule.name))

    def _is_extern_rule_reference(self, rule_name: str, namespace: str | None = None) -> bool:
        return (namespace, rule_name) in self._extern_rule_names

    def _parse_extern_namespace(self) -> ExternNamespace:
        """Parse a top-level namespace declaration."""
        start_token = self._advance()
        name = self._parse_qualified_identifier("Expected namespace name")
        return self._set_node_location_from_tokens(
            ExternNamespace(name=name), start_token, self._previous()
        )

    def _parse_extern_rule(self) -> ExternRule:
        """Parse a top-level external rule declaration."""
        start_token = self._advance()
        if not self._match(TokenType.RULE):
            msg = "Expected 'rule' after 'extern'"
            raise ParserError(msg, self._peek())

        modifiers = []
        while self._match(TokenType.PRIVATE, TokenType.GLOBAL):
            modifiers.append(RuleModifier.from_string(str(self._previous().value)))

        qualified_name = self._parse_qualified_identifier("Expected extern rule name")
        namespace, name = self._split_qualified_rule_name(qualified_name)
        return self._set_node_location_from_tokens(
            ExternRule(name=name, modifiers=modifiers, namespace=namespace),
            start_token,
            self._previous(),
        )

    def _parse_qualified_identifier(self, error_message: str) -> str:
        if not self._match(TokenType.IDENTIFIER):
            raise ParserError(error_message, self._peek())

        parts = [str(self._previous().value)]
        while self._match(TokenType.DOT):
            if not self._match(TokenType.IDENTIFIER):
                msg = "Expected identifier after '.'"
                raise ParserError(msg, self._peek())
            parts.append(str(self._previous().value))
        return ".".join(parts)

    def _split_qualified_rule_name(self, qualified_name: str) -> tuple[str | None, str]:
        if "." not in qualified_name:
            return None, qualified_name
        namespace, name = qualified_name.rsplit(".", maxsplit=1)
        return namespace, name

    def _parse_rule(self) -> Rule:
        """Parse rule definition."""
        start_token = self._peek()
        modifiers = self._parse_rule_modifiers()
        name = self._parse_rule_name()
        tags = self._parse_rule_tags()

        if not self._match(TokenType.LBRACE):
            msg = "Expected '{' after rule name"
            raise ParserError(msg, self._peek())

        meta, strings, condition = self._parse_rule_sections()

        if not self._match(TokenType.RBRACE):
            msg = "Expected '}' at end of rule"
            raise ParserError(msg, self._peek())

        return self._set_node_location_from_tokens(
            Rule(
                name=name,
                modifiers=modifiers,
                tags=tags,
                meta=meta,
                strings=strings,
                condition=condition,
            ),
            start_token,
            self._previous(),
        )

    def _parse_rule_modifiers(self) -> list[str]:
        """Parse rule modifiers (private, global)."""
        modifiers = []
        while self._match(TokenType.PRIVATE, TokenType.GLOBAL):
            modifiers.append(self._previous().value.lower())
        return modifiers

    def _parse_rule_name(self) -> str:
        """Parse rule name identifier."""
        if not self._match(TokenType.RULE):
            msg = "Expected 'rule' keyword"
            raise ParserError(msg, self._peek())

        if not self._match(TokenType.IDENTIFIER):
            msg = "Expected rule name"
            raise ParserError(msg, self._peek())

        return self._previous().value

    def _parse_rule_tags(self) -> list[Tag]:
        """Parse rule tags after colon."""
        tags = []
        if self._match(TokenType.COLON):
            while self._check(TokenType.IDENTIFIER):
                tag_token = self._advance()
                tags.append(
                    self._set_node_location_from_token(Tag(name=tag_token.value), tag_token)
                )
        return tags

    def _parse_rule_sections(
        self,
    ) -> tuple[dict[str, Any], list[StringDefinition], Condition | None]:
        """Parse rule sections (meta, strings, condition)."""
        meta: dict[str, Any] = {}
        strings: list[StringDefinition] = []
        condition: Condition | None = None

        while not self._check(TokenType.RBRACE) and not self._is_at_end():
            if self._match(TokenType.META):
                self._expect_colon("meta")
                meta = self._parse_meta_section()
            elif self._match(TokenType.STRINGS):
                self._expect_colon("strings")
                strings = self._parse_strings_section()
            elif self._match(TokenType.CONDITION):
                self._expect_colon("condition")
                condition = self._parse_condition()
            else:
                msg = f"Unexpected section: {self._peek().value}"
                raise ParserError(msg, self._peek())

        return meta, strings, condition

    def _expect_colon(self, section_name: str) -> None:
        """Expect and consume a colon after section name."""
        if not self._match(TokenType.COLON):
            msg = f"Expected ':' after '{section_name}'"
            raise ParserError(msg, self._peek())

    def _parse_meta_section(self) -> dict[str, Any]:
        """Parse meta section."""
        meta: dict[str, Any] = {}

        while not self._check_any(
            TokenType.STRINGS,
            TokenType.CONDITION,
            TokenType.RBRACE,
        ):
            if not self._check(TokenType.IDENTIFIER):
                break

            key = self._advance().value

            if not self._match(TokenType.ASSIGN):
                msg = "Expected '=' after meta key"
                raise ParserError(msg, self._peek())

            # Parse meta value
            # Handle negative numbers: -159 or -3.14
            if self._match(TokenType.MINUS):
                if self._match(TokenType.INTEGER) or self._match(TokenType.DOUBLE):
                    value = -self._previous().value
                else:
                    msg = "Expected number after '-' in meta value"
                    raise ParserError(msg, self._peek())
            elif self._match(TokenType.STRING) or self._match(TokenType.INTEGER):
                value = self._previous().value
            elif self._match(TokenType.BOOLEAN_TRUE):
                value = True
            elif self._match(TokenType.BOOLEAN_FALSE):
                value = False
            else:
                msg = "Invalid meta value"
                raise ParserError(msg, self._peek())

            meta[key] = value

        return meta
