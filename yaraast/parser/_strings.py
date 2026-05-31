"""String parsing helpers."""

from __future__ import annotations

from yaraast.ast.modifiers import StringModifier, StringModifierType
from yaraast.ast.strings import HexString, HexToken, PlainString, RegexString, StringDefinition
from yaraast.lexer import TokenType
from yaraast.parser.hex_parser import HexParseError, HexStringParser

from ._shared import ParserError, parse_regex_value, validate_string_modifiers

HEX_STRING_MODIFIER_TYPES = frozenset({StringModifierType.PRIVATE})
REGEX_STRING_MODIFIER_TYPES = frozenset(
    {
        StringModifierType.ASCII,
        StringModifierType.WIDE,
        StringModifierType.NOCASE,
        StringModifierType.FULLWORD,
        StringModifierType.PRIVATE,
    }
)


class StringParsingMixin:
    """Mixin with string parsing helpers."""

    def _reserved_string_identifiers(self) -> set[str]:
        reserved = set()
        for token in self.tokens[self.current :]:
            if token.type in (TokenType.CONDITION, TokenType.RBRACE, TokenType.EOF):
                break
            if token.type == TokenType.STRING_IDENTIFIER and token.value != "$":
                reserved.add(str(token.value))
        return reserved

    @staticmethod
    def _next_anonymous_identifier(counter: int, used_identifiers: set[str]) -> tuple[str, int]:
        while True:
            counter += 1
            identifier = f"$anon_{counter}"
            if identifier not in used_identifiers:
                used_identifiers.add(identifier)
                return identifier, counter

    def _parse_strings_section(self) -> list[StringDefinition]:
        """Parse strings section."""
        strings: list[StringDefinition] = []
        anonymous_counter = 0
        used_identifiers = self._reserved_string_identifiers()

        while not self._check_any(TokenType.CONDITION, TokenType.RBRACE):
            if not self._check(TokenType.STRING_IDENTIFIER):
                break

            start_token = self._advance()
            identifier = start_token.value

            # Handle anonymous strings (just "$")
            is_anonymous = identifier == "$"
            if is_anonymous:
                identifier, anonymous_counter = self._next_anonymous_identifier(
                    anonymous_counter,
                    used_identifiers,
                )

            if not self._match(TokenType.ASSIGN):
                msg = "Expected '=' after string identifier"
                raise ParserError(msg, self._peek())

            # Parse string value
            if self._match(TokenType.STRING):
                value = self._previous().value
                modifiers = self._parse_string_modifiers()
                string_def = self._set_node_location_from_tokens(
                    PlainString(identifier=identifier, value=value, modifiers=modifiers),
                    start_token,
                    self._previous(),
                )
                if is_anonymous:
                    string_def.is_anonymous = True
                strings.append(string_def)
            elif self._match(TokenType.HEX_STRING):
                hex_value = self._previous().value
                tokens = self._parse_hex_string(hex_value)
                modifiers = self._parse_string_modifiers(
                    allowed_modifier_types=HEX_STRING_MODIFIER_TYPES,
                    modifier_context="hex strings",
                )
                string_def = self._set_node_location_from_tokens(
                    HexString(identifier=identifier, tokens=tokens, modifiers=modifiers),
                    start_token,
                    self._previous(),
                )
                if is_anonymous:
                    string_def.is_anonymous = True
                strings.append(string_def)
            elif self._match(TokenType.REGEX):
                try:
                    regex, regex_modifiers = parse_regex_value(self._previous().value)
                except ValueError as e:
                    raise ParserError(str(e), self._previous()) from e
                parsed_modifiers = self._parse_string_modifiers(
                    allowed_modifier_types=REGEX_STRING_MODIFIER_TYPES,
                    modifier_context="regex strings",
                )
                modifiers = [*regex_modifiers, *parsed_modifiers]
                string_def = self._set_node_location_from_tokens(
                    RegexString(identifier=identifier, regex=regex, modifiers=modifiers),
                    start_token,
                    self._previous(),
                )
                if is_anonymous:
                    string_def.is_anonymous = True
                strings.append(string_def)
            else:
                msg = "Invalid string value"
                raise ParserError(msg, self._peek())

        return strings

    def _parse_string_modifiers(
        self,
        *,
        allowed_modifier_types: frozenset[StringModifierType] | None = None,
        modifier_context: str = "strings",
    ) -> list[StringModifier]:
        """Parse string modifiers."""
        modifiers: list[StringModifier] = []

        while self._check_any(
            TokenType.NOCASE,
            TokenType.WIDE,
            TokenType.ASCII,
            TokenType.XOR_MOD,
            TokenType.BASE64,
            TokenType.BASE64WIDE,
            TokenType.FULLWORD,
            TokenType.PRIVATE,
        ):
            mod_token = self._advance()
            mod_name = mod_token.value.lower()
            modifier_type = StringModifierType.from_string(mod_name)
            if allowed_modifier_types is not None and modifier_type not in allowed_modifier_types:
                msg = f"String modifier '{mod_name}' is not valid on {modifier_context}"
                raise ParserError(msg, mod_token)

            # Some modifiers can have parameters
            if mod_name in ("xor", "base64", "base64wide") and self._match(TokenType.LPAREN):
                # Parse modifier parameters
                value = None
                if mod_name == "xor":
                    # xor takes integer or range: xor(0x01-0xff)
                    if self._match(TokenType.INTEGER):
                        min_val = self._previous().value
                        if self._match(TokenType.MINUS):
                            if self._match(TokenType.INTEGER):
                                max_val = self._previous().value
                                value = (min_val, max_val)
                            else:
                                msg = "Expected integer after '-'"
                                raise ParserError(msg, self._peek())
                        else:
                            value = min_val
                    else:
                        msg = "Expected integer or range in xor"
                        raise ParserError(msg, self._peek())
                else:
                    # base64/base64wide takes optional custom alphabet string
                    if self._match(TokenType.STRING):
                        value = self._previous().value
                    else:
                        msg = f"Expected string in {mod_name} parameter"
                        raise ParserError(msg, self._peek())

                if not self._match(TokenType.RPAREN):
                    msg = f"Expected ')' after {mod_name} parameter"
                    raise ParserError(msg, self._peek())

                modifiers.append(StringModifier.from_name_value(mod_name, value))
            else:
                modifiers.append(StringModifier.from_name_value(mod_name))

        try:
            validate_string_modifiers(modifiers)
        except ValueError as e:
            raise ParserError(str(e), self._previous()) from e
        return modifiers

    def _parse_hex_string(self, hex_content: str) -> list[HexToken]:
        """Parse hex string content into tokens.

        Delegates to HexStringParser for the actual parsing logic.
        Converts HexParseError to ParserError for consistent error handling.
        """
        try:
            hex_parser = HexStringParser(error_token=self._peek())
            return hex_parser.parse(hex_content)
        except HexParseError as e:
            raise ParserError(str(e), self._peek()) from e
