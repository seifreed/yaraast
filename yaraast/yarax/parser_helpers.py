"""Helper mixins and constants for YARA-X parser."""

from __future__ import annotations

from typing import TYPE_CHECKING

from yaraast.lexer.tokens import TokenType

if TYPE_CHECKING:
    from yaraast.lexer.lexer import Token

ERROR_EXPECTED_VARIABLE = "Expected variable name"
ERROR_EXPECTED_BRACKET_CLOSE = "Expected ']'"
ERROR_EXPECTED_COLON_DICT = "Expected ':' in dict"
ERROR_EXPECTED_BRACE_CLOSE = "Expected '}'"


class YaraXParserHelpersMixin:
    """Helper methods for YARA-X parser."""

    def _check_keyword(self, keyword: str) -> bool:
        """Check if current token is a specific keyword."""
        if self._is_at_end():
            return False
        token = self._peek()
        return token.type == TokenType.IDENTIFIER and token.value == keyword

    def _consume_keyword(self, keyword: str) -> Token:
        """Consume a specific keyword token."""
        if not self._check_keyword(keyword):
            from yaraast.parser.parser import ParserError

            raise ParserError(f"Expected keyword '{keyword}'", self._peek())
        return self._advance()

    def _consume_arrow(self) -> None:
        """Consume the '=>' arrow token sequence."""
        from yaraast.parser.parser import ParserError

        if not self._match(TokenType.ASSIGN):
            raise ParserError("Expected '=>'", self._peek())
        if not self._match(TokenType.GT):
            raise ParserError("Expected '>' after '=' in '=>'", self._peek())

    def _peek_ahead(self, n: int) -> Token | None:
        """Peek ahead n tokens."""
        index = self.current + n
        if index < len(self.tokens):
            return self.tokens[index]
        return None

    def _consume(self, token_type: TokenType, error_message: str) -> Token:
        """Consume token of expected type or raise error."""
        if self._check(token_type):
            return self._advance()

        current = self._peek()
        from yaraast.parser.parser import ParserError

        raise ParserError(error_message, current)
