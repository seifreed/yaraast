"""Helper mixins and constants for YARA-X parser."""

from __future__ import annotations

from collections.abc import Iterator
from contextlib import contextmanager
from typing import Any, cast

from yaraast.lexer.tokens import Token, TokenType
from yaraast.parser._shared import ParserError

ERROR_EXPECTED_VARIABLE = "Expected variable name"
ERROR_EXPECTED_BRACKET_CLOSE = "Expected ']'"
ERROR_EXPECTED_COLON_DICT = "Expected ':' in dict"
ERROR_EXPECTED_BRACE_CLOSE = "Expected '}'"
_CONTEXTUAL_LOCAL_IDENTIFIER_TOKENS = (TokenType.IDENTIFIER, TokenType.AS, TokenType.INCLUDE)


class YaraXParserHelpersMixin:
    """Helper methods for YARA-X parser."""

    def _check_keyword(self: Any, keyword: str) -> bool:
        """Check if current token is a specific keyword."""
        if self._is_at_end():
            return False
        token = self._peek()
        return bool(token.type == TokenType.IDENTIFIER and token.value == keyword)

    def _consume_keyword(self: Any, keyword: str) -> Token:
        """Consume a specific keyword token."""
        if not self._check_keyword(keyword):
            raise ParserError(f"Expected keyword '{keyword}'", self._peek())
        return cast(Token, self._advance())

    def _consume_arrow(self: Any) -> None:
        """Consume the '=>' arrow token sequence."""
        if not self._check(TokenType.ASSIGN):
            raise ParserError("Expected '=>'", self._peek())
        assign_token = self._advance()
        if not self._check(TokenType.GT):
            raise ParserError("Expected '>' after '=' in '=>'", self._peek())
        gt_token = self._peek()
        if not self._tokens_are_adjacent(assign_token, gt_token):
            raise ParserError("Expected contiguous '=>'", gt_token)
        self._advance()

    def _consume_local_identifier(self: Any, error_message: str) -> Token:
        if any(self._check(token_type) for token_type in _CONTEXTUAL_LOCAL_IDENTIFIER_TOKENS):
            return cast(Token, self._advance())
        raise ParserError(error_message, self._peek())

    def _consume_with_local_identifier(self: Any, error_message: str) -> Token:
        if self._check(TokenType.STRING_IDENTIFIER):
            return cast(Token, self._advance())
        return cast(Token, self._consume_local_identifier(error_message))

    def _local_identifier_scope_names(self: Any, *names: object) -> set[str]:
        return {name for name in names if isinstance(name, str) and not name.startswith("$")}

    def _is_contextual_local_identifier_bound(self: Any, name: str) -> bool:
        local_frames = getattr(self, "_contextual_local_identifiers", [])
        return any(name in frame for frame in reversed(local_frames))

    @contextmanager
    def _contextual_local_identifier_scope(self: Any, local_names: set[str]) -> Iterator[None]:
        self._contextual_local_identifiers.append(local_names)
        try:
            yield
        finally:
            self._contextual_local_identifiers.pop()

    def _tokens_are_adjacent(self: Any, left: Token, right: Token) -> bool:
        return left.line == right.line and left.column + left.length == right.column

    def _peek_ahead(self: Any, n: int) -> Token | None:
        """Peek ahead n tokens."""
        index = self.current + n
        if index < len(self.tokens):
            return cast(Token, self.tokens[index])
        return None

    def _consume(self: Any, token_type: TokenType, error_message: str) -> Token:
        """Consume token of expected type or raise error."""
        if self._check(token_type):
            return cast(Token, self._advance())

        current = self._peek()
        raise ParserError(error_message, current)
