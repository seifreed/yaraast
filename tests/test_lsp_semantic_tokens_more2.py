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


def test_semantic_tokens_range_excludes_tokens_outside_nonempty_range() -> None:
    provider = SemanticTokensProvider()
    text = "rule sample { condition: true }\n"

    tokens = provider.get_semantic_tokens_range(
        text,
        Range(start=Position(line=0, character=5), end=Position(line=0, character=7)),
    )
    variable_index = TOKEN_TYPES.index("variable")

    assert tokens.data == [0, 6, len("sample"), variable_index, 0]


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


def test_semantic_tokens_use_source_width_for_literal_tokens() -> None:
    provider = SemanticTokensProvider()
    text = """
rule literals {
  strings:
    $plain = "abc"
    $regex = /abc/i
    $hex = { 01 ?? }
  condition:
    any of them
}
""".lstrip()

    tokens = provider.get_semantic_tokens(text)
    string_index = TOKEN_TYPES.index("string")
    regex_index = TOKEN_TYPES.index("regexp")
    string_lengths = [
        tokens.data[index + 2]
        for index in range(0, len(tokens.data), 5)
        if tokens.data[index + 3] == string_index
    ]
    regex_lengths = [
        tokens.data[index + 2]
        for index in range(0, len(tokens.data), 5)
        if tokens.data[index + 3] == regex_index
    ]

    assert string_lengths == [len('"abc"'), len("{ 01 ?? }")]
    assert regex_lengths == [len("/abc/i")]
