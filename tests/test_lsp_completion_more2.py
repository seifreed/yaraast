"""More tests for LSP completion provider (no mocks)."""

from __future__ import annotations

from lsprotocol.types import Position

from yaraast.lsp.completion import CompletionProvider


def _pos(line: int, char: int) -> Position:
    return Position(line=line, character=char)


def test_completion_keywords_and_builtins() -> None:
    provider = CompletionProvider()
    text = "rule a { condition: true }"
    completions = provider.get_completions(text, _pos(0, 1))

    labels = {item.label for item in completions.items}
    assert "rule" in labels
    assert "uint32" in labels


def test_completion_condition_string_ids() -> None:
    provider = CompletionProvider()
    text = """
rule a {
  strings:
    $a = "x"
  condition:
    $a
}
""".lstrip()
    completions = provider.get_completions(text, _pos(4, 5))
    labels = {item.label for item in completions.items}
    assert "$a" in labels
    assert "#a" in labels


def test_completion_import_modules() -> None:
    provider = CompletionProvider()
    text = 'import "'
    completions = provider.get_completions(text, _pos(0, len(text)))
    labels = {item.label for item in completions.items}
    assert "pe" in labels
