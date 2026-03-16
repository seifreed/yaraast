"""Real tests for LSP completion provider (no mocks)."""

from __future__ import annotations

from lsprotocol.types import Position

from yaraast.lsp.completion import CompletionProvider


def _pos(line: int, char: int) -> Position:
    return Position(line=line, character=char)


def test_completion_keywords_general() -> None:
    provider = CompletionProvider()
    text = "rule x { condition: true }"

    completions = provider.get_completions(text, _pos(0, 0))
    labels = [item.label for item in completions.items]
    assert "rule" in labels
    assert "import" in labels


def test_completion_import_context() -> None:
    provider = CompletionProvider()
    text = 'import "'  # cursor after quote

    completions = provider.get_completions(text, _pos(0, 8))
    labels = [item.label for item in completions.items]
    assert "pe" in labels


def test_completion_module_member_context() -> None:
    provider = CompletionProvider()
    text = "rule r { condition: pe. }"

    completions = provider.get_completions(text, _pos(0, len(text)))
    labels = [item.label for item in completions.items]
    assert "imphash" in labels or "is_pe" in labels
