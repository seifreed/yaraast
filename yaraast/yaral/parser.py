"""YARA-L parser implementation."""

from __future__ import annotations

from yaraast.lexer.tokens import TokenType as BaseTokenType

from ._parsing import YaraLParsingMixin
from ._shared import EXPECTED_FIELD_NAME_ERROR, YaraLParserError
from ._token_stream import TokenStreamMixin
from .ast_nodes import YaraLFile
from .lexer import YaraLLexer, YaraLToken


class YaraLParser(TokenStreamMixin, YaraLParsingMixin):
    """Parser for YARA-L 2.0 rules."""

    def __init__(self, text: str) -> None:
        self.lexer = YaraLLexer(text)
        self.tokens = self.lexer.tokenize()
        self.current = 0

    def parse(self) -> YaraLFile:
        """Parse YARA-L file."""
        rules = []

        while not self._is_at_end():
            if self._check_keyword("rule"):
                rules.append(self._parse_rule())
            else:
                # Skip unknown tokens
                self._advance()

        return YaraLFile(rules=rules)


__all__ = [
    "EXPECTED_FIELD_NAME_ERROR",
    "BaseTokenType",
    "YaraLParser",
    "YaraLParserError",
    "YaraLToken",
]
