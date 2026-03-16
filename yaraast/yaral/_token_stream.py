"""Token stream helpers for YARA-L parser."""

from __future__ import annotations

from yaraast.lexer.tokens import TokenType as BaseTokenType

from ._shared import YaraLParserError
from .lexer import YaraLToken
from .tokens import YaraLTokenType


class TokenStreamMixin:
    """Mixin providing token access helpers."""

    tokens: list[YaraLToken]
    current: int

    def _check_section_keyword(self) -> bool:
        """Check if current token is a section keyword."""
        return any(
            self._check_keyword(kw)
            for kw in ["meta", "events", "match", "condition", "outcome", "options"]
        )

    def _check_keyword(self, keyword: str) -> bool:
        """Check if current token is a specific keyword."""
        if self._is_at_end():
            return False
        token = self._peek()
        return token.value and token.value.lower() == keyword.lower()

    def _check_yaral_type(self, yaral_type: YaraLTokenType) -> bool:
        """Check if current token has specific YARA-L type."""
        if self._is_at_end():
            return False
        token = self._peek()
        return hasattr(token, "yaral_type") and token.yaral_type == yaral_type

    def _consume_keyword(self, keyword: str, message: str | None = None) -> YaraLToken:
        """Consume a specific keyword."""
        if not self._check_keyword(keyword):
            msg = message or f"Expected '{keyword}'"
            raise YaraLParserError(msg, self._peek())
        return self._advance()

    def _check(self, token_type: BaseTokenType) -> bool:
        """Check if current token is of given type."""
        if self._is_at_end():
            return False
        return self._peek().type == token_type

    def _consume(self, token_type: BaseTokenType, message: str) -> YaraLToken:
        """Consume token of given type."""
        if not self._check(token_type):
            raise YaraLParserError(message, self._peek())
        return self._advance()

    def _advance(self) -> YaraLToken:
        """Advance to next token."""
        if not self._is_at_end():
            self.current += 1
        return self._previous()

    def _peek(self) -> YaraLToken:
        """Peek at current token."""
        return self.tokens[self.current]

    def _previous(self) -> YaraLToken:
        """Get previous token."""
        return self.tokens[self.current - 1]

    def _is_at_end(self) -> bool:
        """Check if at end of tokens."""
        return self.current >= len(self.tokens) or self._peek().type == BaseTokenType.EOF
