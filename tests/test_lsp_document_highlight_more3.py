"""More tests for document highlight provider (no mocks)."""

from __future__ import annotations

from lsprotocol.types import Position

from yaraast.lsp.document_highlight import DocumentHighlightProvider


def _pos(line: int, char: int) -> Position:
    return Position(line=line, character=char)


def test_document_highlight_out_of_range_position() -> None:
    text = "rule a { condition: true }"
    provider = DocumentHighlightProvider()
    highlights = provider.get_highlights(text, _pos(0, 200))
    assert highlights == []


def test_document_highlight_fallback_on_parse_error() -> None:
    text = "$a $a"
    provider = DocumentHighlightProvider()
    highlights = provider.get_highlights(text, _pos(0, 1))
    assert len(highlights) >= 2


def test_document_highlight_skips_embedded_string_identifiers() -> None:
    text = """
rule r {
    strings:
        $a = "abc"
        $msg = "x$a $ab $a1 $a"
    condition:
        $a
}
    """.lstrip()
    provider = DocumentHighlightProvider()
    highlights = provider._highlight_string_identifier(text, "$a")
    positions = {(h.range.start.line, h.range.start.character) for h in highlights}
    assert (3, 28) not in positions
    assert (3, 16) not in positions
    assert (3, 19) not in positions


def test_document_highlight_identifier_boundary_skips() -> None:
    provider = DocumentHighlightProvider()
    highlights = provider._highlight_identifier("alpha xalpha alpha1 alpha\n", "alpha")
    assert len(highlights) == 2
