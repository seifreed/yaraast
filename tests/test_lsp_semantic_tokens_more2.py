"""More tests for LSP semantic tokens providers."""

from __future__ import annotations

from lsprotocol.types import Position, Range

from yaraast.lsp.semantic_tokens import TOKEN_TYPES, SemanticTokensProvider


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


def test_semantic_tokens_use_source_width_for_size_suffix_literals() -> None:
    provider = SemanticTokensProvider()
    text = "rule r { condition: filesize < 1KB }\n"

    tokens = provider.get_semantic_tokens(text)
    number_index = TOKEN_TYPES.index("number")
    number_lengths = [
        tokens.data[index + 2]
        for index in range(0, len(tokens.data), 5)
        if tokens.data[index + 3] == number_index
    ]

    assert number_lengths == [len("1KB")]
