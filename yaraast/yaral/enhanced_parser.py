"""Enhanced YARA-L parser with full support."""

from __future__ import annotations

from yaraast.lexer.tokens import TokenType as BaseTokenType
from yaraast.yaral.ast_nodes import YaraLFile
from yaraast.yaral.enhanced_parser_conditions import EnhancedYaraLParserConditionsMixin
from yaraast.yaral.enhanced_parser_events import EnhancedYaraLParserEventsMixin
from yaraast.yaral.enhanced_parser_helpers import EnhancedYaraLParserHelpersMixin
from yaraast.yaral.enhanced_parser_match import EnhancedYaraLParserMatchMixin
from yaraast.yaral.enhanced_parser_outcome import EnhancedYaraLParserOutcomeMixin
from yaraast.yaral.enhanced_parser_rules import EnhancedYaraLParserRulesMixin
from yaraast.yaral.lexer import YaraLLexer, YaraLToken
from yaraast.yaral.tokens import YaraLTokenType


class EnhancedYaraLParser(
    EnhancedYaraLParserRulesMixin,
    EnhancedYaraLParserEventsMixin,
    EnhancedYaraLParserMatchMixin,
    EnhancedYaraLParserConditionsMixin,
    EnhancedYaraLParserOutcomeMixin,
    EnhancedYaraLParserHelpersMixin,
):
    """Enhanced parser for YARA-L 2.0 with full feature support."""

    def __init__(self, text: str) -> None:
        """Initialize enhanced parser.

        Args:
            text: YARA-L source code to parse
        """
        self.lexer = YaraLLexer(text)
        self.tokens = self.lexer.tokenize()
        self.current = 0
        self.errors = []

    def parse(self) -> YaraLFile:
        """Parse YARA-L file with error recovery.

        Returns:
            Parsed YARA-L AST
        """
        rules = []
        max_iterations = 10000

        iteration = 0
        while not self._is_at_end() and iteration < max_iterations:
            try:
                if self._check_keyword("rule"):
                    rules.append(self._parse_rule())
                else:
                    self._advance()
            except Exception as e:
                self.errors.append(str(e))
                self._recover_to_next_rule()
            iteration += 1

        if iteration >= max_iterations:
            self.errors.append(f"Parser exceeded maximum iterations ({max_iterations})")

        return YaraLFile(rules=rules)

    def _check_keyword(self, keyword: str) -> bool:
        """Check if current token is a keyword."""
        if self._is_at_end():
            return False
        token = self._peek()
        if token.type == BaseTokenType.META and keyword == "meta":
            return True
        if token.type == BaseTokenType.CONDITION and keyword == "condition":
            return True
        if token.type == BaseTokenType.AND and keyword == "and":
            return True
        if token.type == BaseTokenType.OR and keyword == "or":
            return True
        if token.type == BaseTokenType.NOT and keyword == "not":
            return True
        if token.type == BaseTokenType.IN and keyword == "in":
            return True
        # Check by value for YARA-L keywords mapped to dedicated token types
        if hasattr(token, "value") and token.value and token.value.lower() == keyword.lower():
            return True
        return token.type == BaseTokenType.IDENTIFIER and token.value == keyword

    def _consume_keyword(self, keyword: str) -> YaraLToken:
        """Consume a keyword token."""
        if not self._check_keyword(keyword):
            raise self._error(f"Expected keyword '{keyword}'")
        return self._advance()

    def _check_yaral_type(self, token_type: YaraLTokenType) -> bool:
        """Check if current token is a YARA-L specific type."""
        if self._is_at_end():
            return False
        token = self._peek()
        return hasattr(token, "yaral_type") and token.yaral_type == token_type

    def _check_section_keyword(self) -> bool:
        """Check if current token is a section keyword."""
        section_keywords = [
            "meta",
            "events",
            "match",
            "condition",
            "outcome",
            "options",
        ]
        return any(self._check_keyword(kw) for kw in section_keywords)

    def _peek(self) -> YaraLToken:
        """Get current token without advancing."""
        if self._is_at_end():
            return self.tokens[-1]
        return self.tokens[self.current]

    def _peek_ahead(self, n: int) -> YaraLToken | None:
        """Peek ahead n tokens."""
        index = self.current + n
        if index < len(self.tokens):
            return self.tokens[index]
        return None

    def _advance(self) -> YaraLToken:
        """Consume and return current token."""
        if not self._is_at_end():
            self.current += 1
        return self.tokens[self.current - 1]

    def _check(self, token_type: BaseTokenType) -> bool:
        """Check if current token is of given type."""
        if self._is_at_end():
            return False
        return self._peek().type == token_type

    def _consume(self, token_type: BaseTokenType, message: str) -> YaraLToken:
        """Consume token of given type or raise error."""
        if self._check(token_type):
            return self._advance()
        raise self._error(message)

    def _is_at_end(self) -> bool:
        """Check if at end of tokens."""
        if self.current >= len(self.tokens):
            return True
        return self.tokens[self.current].type == BaseTokenType.EOF

    def _error(self, message: str) -> Exception:
        """Create parser error."""
        token = self._peek() if not self._is_at_end() else None
        if token:
            return ValueError(f"Parser error at {token.line}:{token.column}: {message}")
        return ValueError(f"Parser error: {message}")

    def _recover_to_next_rule(self) -> None:
        """Recover parser to next rule for error recovery."""
        while not self._is_at_end():
            if self._check_keyword("rule"):
                break
            self._advance()
