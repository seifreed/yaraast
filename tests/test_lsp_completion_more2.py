"""More tests for LSP completion provider (no mocks)."""

from __future__ import annotations

from typing import Any, cast

from lsprotocol.types import Position
import pytest

from yaraast.lexer.lexer_tables import KEYWORDS as LEXER_KEYWORDS
from yaraast.lsp.completion import CompletionProvider
from yaraast.lsp.completion_helpers import KEYWORDS, STRING_MODIFIERS


def _pos(line: int, char: int) -> Position:
    return Position(line=line, character=char)


def test_completion_keywords_and_builtins() -> None:
    provider = CompletionProvider()
    text = "rule a { condition: true }"
    completions = provider.get_completions(text, _pos(0, 1))

    labels = {item.label for item in completions.items}
    assert "rule" in labels
    assert "uint32" in labels


@pytest.mark.parametrize("text", [None, 1, b"rule r { condition: true }", object()])
def test_completion_rejects_non_string_text(text: Any) -> None:
    provider = CompletionProvider()

    with pytest.raises(TypeError, match="Completion text must be a string"):
        provider.get_completions(cast(str, text), _pos(0, 0))


def test_completion_rejects_non_position_inputs() -> None:
    provider = CompletionProvider()

    with pytest.raises(TypeError, match="position must be an LSP Position"):
        provider.get_completions("rule r { condition: true }", cast(Any, object()))


def test_completion_keywords_cover_non_modifier_lexer_keywords() -> None:
    missing = set(LEXER_KEYWORDS) - set(KEYWORDS) - set(STRING_MODIFIERS)

    assert missing == set()


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
