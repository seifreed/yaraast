"""String parsing helpers."""

from __future__ import annotations

from yaraast.ast.modifiers import StringModifier
from yaraast.ast.strings import HexString, HexToken, PlainString, RegexString, StringDefinition
from yaraast.lexer import TokenType
from yaraast.parser.hex_parser import HexParseError, HexStringParser

from ._shared import ParserError


class StringParsingMixin:
    """Mixin with string parsing helpers."""

    def _parse_strings_section(self) -> list[StringDefinition]:
        """Parse strings section."""
        strings: list[StringDefinition] = []
        anonymous_counter = 0

        while not self._check_any(TokenType.CONDITION, TokenType.RBRACE):
            if not self._check(TokenType.STRING_IDENTIFIER):
                break

            start_token = self._advance()
            identifier = start_token.value

            # Handle anonymous strings (just "$")
            if identifier == "$":
                anonymous_counter += 1
                identifier = f"$anon_{anonymous_counter}"

            if not self._match(TokenType.ASSIGN):
                msg = "Expected '=' after string identifier"
                raise ParserError(msg, self._peek())

            # Parse string value
            if self._match(TokenType.STRING):
                value = self._previous().value
                modifiers = self._parse_string_modifiers()
                strings.append(
                    self._set_node_location_from_tokens(
                        PlainString(identifier=identifier, value=value, modifiers=modifiers),
                        start_token,
                        self._previous(),
                    )
                )
            elif self._match(TokenType.HEX_STRING):
                hex_value = self._previous().value
                tokens = self._parse_hex_string(hex_value)
                modifiers = self._parse_string_modifiers()
                strings.append(
                    self._set_node_location_from_tokens(
                        HexString(identifier=identifier, tokens=tokens, modifiers=modifiers),
                        start_token,
                        self._previous(),
                    )
                )
            elif self._match(TokenType.REGEX):
                regex = self._previous().value
                modifiers = self._parse_string_modifiers()
                strings.append(
                    self._set_node_location_from_tokens(
                        RegexString(identifier=identifier, regex=regex, modifiers=modifiers),
                        start_token,
                        self._previous(),
                    )
                )
            else:
                msg = "Invalid string value"
                raise ParserError(msg, self._peek())

        return strings

    def _parse_string_modifiers(self) -> list[StringModifier]:
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

                if not self._match(TokenType.RPAREN):
                    msg = f"Expected ')' after {mod_name} parameter"
                    raise ParserError(msg, self._peek())

                modifiers.append(StringModifier.from_name_value(mod_name, value))
            else:
                modifiers.append(StringModifier.from_name_value(mod_name))

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
