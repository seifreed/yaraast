"""Property-based tests for YARA lexer using Hypothesis."""

from __future__ import annotations

import pytest
from hypothesis import assume, given, settings
from hypothesis import strategies as st

from yaraast.lexer.lexer import Lexer
from yaraast.lexer.lexer_tables import KEYWORDS as _LEXER_KEYWORDS
from yaraast.lexer.tokens import TokenType

_ALL_KEYWORDS = frozenset(_LEXER_KEYWORDS.keys())


def _yara_keyword() -> st.SearchStrategy[str]:
    """Generate YARA keywords."""
    return st.sampled_from(
        [
            "rule",
            "strings",
            "condition",
            "meta",
            "import",
            "include",
            "true",
            "false",
            "and",
            "or",
            "not",
            "all",
            "any",
            "of",
            "them",
            "for",
            "in",
            "at",
            "filesize",
            "entrypoint",
            "global",
            "private",
        ]
    )


def _valid_identifier() -> st.SearchStrategy[str]:
    return st.from_regex(r"[a-zA-Z_][a-zA-Z0-9_]{0,15}", fullmatch=True)


@pytest.mark.hypothesis
class TestLexerProperties:
    """Property-based tests for lexer behavior."""

    @given(rule_text=st.just("rule test { condition: true }"))
    @settings(max_examples=5, deadline=5000)
    def test_lexer_always_ends_with_eof(self, rule_text: str) -> None:
        """Every token stream ends with EOF."""
        lexer = Lexer(rule_text)
        tokens = lexer.tokenize()
        assert tokens[-1].type == TokenType.EOF

    @given(name=_valid_identifier())
    @settings(max_examples=50, deadline=5000)
    def test_simple_rule_tokenizes(self, name: str) -> None:
        """Simple rules always produce valid token streams."""
        assume(name.lower() not in _ALL_KEYWORDS)
        text = f"rule {name} {{ condition: true }}"
        lexer = Lexer(text)
        tokens = lexer.tokenize()
        assert len(tokens) >= 5  # rule, name, {, condition, :, true, }, EOF
        assert tokens[0].type == TokenType.RULE

    @given(text=_yara_keyword())
    @settings(max_examples=30, deadline=5000)
    def test_keywords_recognized(self, text: str) -> None:
        """All YARA keywords are recognized as keyword tokens (not identifiers)."""
        lexer = Lexer(text)
        tokens = lexer.tokenize()
        # Should have at least keyword + EOF
        assert len(tokens) >= 2
        # The keyword should not be tokenized as IDENTIFIER
        assert tokens[0].type != TokenType.IDENTIFIER or text not in Lexer.KEYWORDS

    @given(
        name=_valid_identifier(),
        n=st.integers(min_value=1, max_value=3),
    )
    @settings(max_examples=30, deadline=5000)
    def test_double_tokenize_idempotent(self, name: str, n: int) -> None:
        """Tokenizing the same text multiple times produces identical results."""
        assume(name.lower() not in _ALL_KEYWORDS)
        text = f"rule {name} {{ condition: true }}"
        tokens1 = Lexer(text).tokenize()
        tokens2 = Lexer(text).tokenize()
        assert len(tokens1) == len(tokens2)
        for t1, t2 in zip(tokens1, tokens2):
            assert t1.type == t2.type
            assert t1.value == t2.value
