"""More tests for document highlight provider (no mocks)."""

from __future__ import annotations

from lsprotocol.types import DocumentHighlightKind, Position

from yaraast.lsp.document_highlight import DocumentHighlightProvider


def _pos(line: int, char: int) -> Position:
    return Position(line=line, character=char)


def test_document_highlight_string_identifier_fallback() -> None:
    text = 'rule { strings: $a = "x" condition: $a and $a }'
    provider = DocumentHighlightProvider()
    highlights = provider.get_highlights(text, _pos(0, text.find("$a")))
    assert len(highlights) == 3


def test_document_highlight_identifier_word_boundaries() -> None:
    text = "rule alpha { condition: true }\nrule alphabet { condition: alpha }"
    provider = DocumentHighlightProvider()
    highlights = provider.get_highlights(text, _pos(0, 5))
    assert len(highlights) == 2


def test_document_highlight_string_identifier_write_kind() -> None:
    text = """
rule r {
  strings:
    $a = "x"
  condition:
    $a and $a
}
""".lstrip()
    provider = DocumentHighlightProvider()
    highlights = provider.get_highlights(text, _pos(4, 6))
    assert any(h.kind == DocumentHighlightKind.Write for h in highlights)
