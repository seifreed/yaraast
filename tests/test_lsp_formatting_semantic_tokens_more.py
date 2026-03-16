"""More real tests for LSP formatting and semantic tokens."""

from __future__ import annotations

from yaraast.lsp.formatting import FormattingProvider
from yaraast.lsp.semantic_tokens import SemanticTokensProvider


def test_formatting_returns_no_edits_on_invalid_source() -> None:
    provider = FormattingProvider()
    assert provider.format_document("rule bad { condition: ") == []


def test_semantic_tokens_returns_empty_on_lexer_error() -> None:
    provider = SemanticTokensProvider()
    tokens = provider.get_semantic_tokens(
        'rule a { strings: $a = "unterminated\n condition: true }'
    )
    assert tokens.data == []


def test_semantic_tokens_legend_has_expected_shape() -> None:
    legend = SemanticTokensProvider.get_legend()
    assert "keyword" in legend.token_types
    assert "defaultLibrary" in legend.token_modifiers
