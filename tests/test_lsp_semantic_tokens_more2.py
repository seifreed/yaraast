"""More tests for LSP semantic tokens providers."""

from __future__ import annotations

from lsprotocol.types import Position, Range

from yaraast.lsp.semantic_tokens import SemanticTokensProvider


def test_semantic_tokens_range_returns_tokens_within_requested_window() -> None:
    provider = SemanticTokensProvider()
    text = """
rule sample {
  strings:
    $a = "x"
  condition:
    $a
}
""".lstrip()

    tokens = provider.get_semantic_tokens_range(
        text,
        Range(
            start=Position(line=2, character=0),
            end=Position(line=3, character=20),
        ),
    )
    assert tokens.data
    assert len(tokens.data) % 5 == 0


def test_semantic_tokens_range_returns_empty_on_lexer_failure() -> None:
    provider = SemanticTokensProvider()
    text = 'rule bad { strings: $a = "unterminated\n condition: $a }'

    tokens = provider.get_semantic_tokens_range(
        text,
        Range(start=Position(line=0, character=0), end=Position(line=1, character=20)),
    )
    assert tokens.data == []
