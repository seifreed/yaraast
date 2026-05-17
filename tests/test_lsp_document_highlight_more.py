"""Real tests for LSP document highlight (no mocks)."""

from __future__ import annotations

from lsprotocol.types import Position

from yaraast.lsp.document_highlight import DocumentHighlightProvider


def _pos(line: int, char: int) -> Position:
    return Position(line=line, character=char)


def test_document_highlight_string_identifier() -> None:
    text = """
rule r {
    strings:
        $a = "abc"
    condition:
        $a and #a > 0 and @a == 10 and !a
}
""".lstrip()

    provider = DocumentHighlightProvider()
    highlights = provider.get_highlights(text, _pos(4, 8))
    assert len(highlights) >= 4


def test_document_highlight_prefixed_string_operators_resolve_string_symbol() -> None:
    text = """
rule r {
    strings:
        $a = "abc"
    condition:
        $a and #a > 0 and @a[1] == 10 and !a[1] > 0
}
""".lstrip()

    provider = DocumentHighlightProvider()
    for character in (16, 27, 43):
        highlights = provider.get_highlights(text, _pos(4, character))
        ranges = {
            (
                highlight.range.start.line,
                highlight.range.start.character,
                highlight.range.end.character,
            )
            for highlight in highlights
        }

        assert len(highlights) >= 5
        assert (4, 8, 10) in ranges
        assert (4, 15, 17) in ranges
        assert (4, 26, 28) in ranges
        assert (4, 42, 44) in ranges


def test_document_highlight_identifier() -> None:
    text = """
rule alpha { condition: true }
rule beta { condition: alpha }
""".lstrip()

    provider = DocumentHighlightProvider()
    highlights = provider.get_highlights(text, _pos(1, 25))
    assert len(highlights) >= 2
