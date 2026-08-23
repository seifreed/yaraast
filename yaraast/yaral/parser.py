"""YARA-L parser implementation."""

from __future__ import annotations

from yaraast.lexer.tokens import TokenType as BaseTokenType
from yaraast.limits import DEFAULT_RESOURCE_LIMITS, CancellationToken, ParseBudget, ResourceLimits

from ._parsing import YaraLParsingMixin
from ._shared import EXPECTED_FIELD_NAME_ERROR, YaraLParserError
from .ast_nodes import YaraLFile
from .lexer import YaraLLexer, YaraLToken


class YaraLParser(YaraLParsingMixin):
    """Parser for YARA-L 2.0 rules."""

    def __init__(
        self,
        text: str,
        *,
        resource_limits: ResourceLimits = DEFAULT_RESOURCE_LIMITS,
        cancellation_token: CancellationToken | None = None,
    ) -> None:
        self._budget = ParseBudget(resource_limits, cancellation_token)
        self._budget.validate_source(text)
        self.lexer = YaraLLexer(text, budget=self._budget)
        self.tokens = self.lexer.tokenize()
        self.current = 0

    def parse(self) -> YaraLFile:
        """Parse YARA-L file."""
        self.current = 0
        rules = []

        while not self._is_at_end():
            if self._check_keyword("rule"):
                rules.append(self._parse_rule())
            else:
                # Skip unknown tokens
                self._advance()

        document = YaraLFile(rules=rules)
        self._budget.validate_document(document)
        return document


__all__ = [
    "EXPECTED_FIELD_NAME_ERROR",
    "BaseTokenType",
    "YaraLParser",
    "YaraLParserError",
    "YaraLToken",
]
