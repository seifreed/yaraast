"""Token stream helpers for parser mixins."""

from __future__ import annotations

from yaraast.ast.base import ASTNode, Location
from yaraast.interfaces import IToken
from yaraast.lexer import TokenType


class TokenStreamMixin:
    """Mixin providing token stream helpers."""

    tokens: list[IToken]
    current: int

    def _match(self, *types: TokenType) -> bool:
        """Check if current token matches any of the given types."""
        for token_type in types:
            if self._check(token_type):
                self._advance()
                return True
        return False

    def _check(self, token_type: TokenType) -> bool:
        """Check if current token is of given type."""
        if self._is_at_end():
            return False
        return self._peek().type == token_type

    def _check_any(self, *types: TokenType) -> bool:
        """Check if current token matches any of the given types."""
        return any(self._check(t) for t in types)

    def _advance(self) -> IToken:
        """Consume current token and return it."""
        if not self._is_at_end():
            self.current += 1
        return self._previous()

    def _is_at_end(self) -> bool:
        """Check if we're at end of tokens."""
        return self._peek().type == TokenType.EOF

    def _peek(self) -> IToken:
        """Return current token without advancing."""
        return self.tokens[self.current]

    def _previous(self) -> IToken:
        """Return previous token."""
        if self.current <= 0:
            return self.tokens[0]
        return self.tokens[self.current - 1]

    def _token_span(self, token: IToken) -> int:
        length = getattr(token, "length", 0) or 0
        return length if length > 0 else max(1, len(str(token.value)))

    def _location_from_token(self, token: IToken) -> Location:
        return Location(
            line=token.line,
            column=token.column,
            end_line=token.line,
            end_column=token.column + self._token_span(token),
        )

    def _location_from_tokens(self, start_token: IToken, end_token: IToken) -> Location:
        return Location(
            line=start_token.line,
            column=start_token.column,
            end_line=end_token.line,
            end_column=end_token.column + self._token_span(end_token),
        )

    def _location_from_nodes(self, start_node: ASTNode, end_node: ASTNode) -> Location | None:
        start = getattr(start_node, "location", None)
        end = getattr(end_node, "location", None)
        if start is None or end is None:
            return None
        return Location(
            line=start.line,
            column=start.column,
            file=start.file or end.file,
            end_line=end.end_line or end.line,
            end_column=end.end_column or (end.column + 1),
        )

    def _set_node_location_from_token(self, node: ASTNode, token: IToken) -> ASTNode:
        node.location = self._location_from_token(token)
        return node

    def _set_node_location_from_tokens(
        self, node: ASTNode, start_token: IToken, end_token: IToken
    ) -> ASTNode:
        node.location = self._location_from_tokens(start_token, end_token)
        return node

    def _set_node_location_from_nodes(
        self, node: ASTNode, start_node: ASTNode, end_node: ASTNode
    ) -> ASTNode:
        location = self._location_from_nodes(start_node, end_node)
        if location is not None:
            node.location = location
        return node

    def _synthetic_token_from_location(self, location: Location):
        class _SyntheticToken:
            def __init__(self, loc: Location) -> None:
                self.line = loc.line
                self.column = loc.column
                if loc.end_line == loc.line and loc.end_column is not None:
                    self.length = max(1, loc.end_column - loc.column)
                else:
                    self.length = 1
                self.value = ""

        return _SyntheticToken(location)
