"""More tests for document highlight provider (no mocks)."""

from __future__ import annotations

from lsprotocol.types import Position

from yaraast.lsp.document_highlight import DocumentHighlightProvider
from yaraast.lsp.utf16 import utf8_col_to_utf16


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


def test_document_highlight_fallback_returns_utf16_ranges() -> None:
    text = "😀 alpha alpha"
    line = text.splitlines()[0]
    first_start = line.index("alpha")
    second_start = line.index("alpha", first_start + len("alpha"))
    provider = DocumentHighlightProvider()

    highlights = provider.get_highlights(text, _pos(0, utf8_col_to_utf16(line, first_start)))

    positions = {
        (highlight.range.start.character, highlight.range.end.character) for highlight in highlights
    }
    assert positions == {
        (
            utf8_col_to_utf16(line, first_start),
            utf8_col_to_utf16(line, first_start + len("alpha")),
        ),
        (
            utf8_col_to_utf16(line, second_start),
            utf8_col_to_utf16(line, second_start + len("alpha")),
        ),
    }


def test_document_highlight_ast_records_return_utf16_ranges() -> None:
    text = """
rule r {
    strings:
        $a = "abc"
    condition:
        /* 😀 */ $a and $a
}
""".lstrip()
    line = text.splitlines()[4]
    first_start = line.index("$a")
    second_start = line.index("$a", first_start + len("$a"))
    provider = DocumentHighlightProvider()

    highlights = provider.get_highlights(text, _pos(4, utf8_col_to_utf16(line, first_start)))

    positions = {
        (highlight.range.start.character, highlight.range.end.character)
        for highlight in highlights
        if highlight.range.start.line == 4
    }
    assert positions == {
        (
            utf8_col_to_utf16(line, first_start),
            utf8_col_to_utf16(line, first_start + len("$a")),
        ),
        (
            utf8_col_to_utf16(line, second_start),
            utf8_col_to_utf16(line, second_start + len("$a")),
        ),
    }


def test_document_highlight_ignores_yarax_local_string_shadowing() -> None:
    text = """
rule shadowed {
    strings:
        $a = "abc"
    condition:
        with $a = 1:
            $a > 0
}
""".lstrip()
    provider = DocumentHighlightProvider()

    highlights = provider.get_highlights(text, _pos(5, 13))

    assert [(highlight.range.start.line, highlight.range.end.line) for highlight in highlights] == [
        (5, 5)
    ]


def test_document_highlight_yarax_local_declaration_uses_utf16_range() -> None:
    text = """
rule shadowed {
    strings:
        $a = "abc"
    condition:
        /* 😀 */ with $a = 1:
            $a > 0
}
""".lstrip()
    line = text.splitlines()[4]
    start = line.index("$a")
    provider = DocumentHighlightProvider()

    highlights = provider.get_highlights(text, _pos(4, utf8_col_to_utf16(line, start)))

    assert [
        (highlight.range.start.character, highlight.range.end.character) for highlight in highlights
    ] == [
        (
            utf8_col_to_utf16(line, start),
            utf8_col_to_utf16(line, start + len("$a")),
        )
    ]


def test_document_highlight_fallback_ignores_string_identifier_in_non_code() -> None:
    text = """
rule r {
    condition:
        $a
        // $a
        "$a"
        /$a/
    """.lstrip()
    provider = DocumentHighlightProvider()
    highlights = provider.get_highlights(text, _pos(2, 9))
    positions = {
        (highlight.range.start.line, highlight.range.start.character) for highlight in highlights
    }
    assert positions == {(2, 8)}


def test_document_highlight_fallback_ignores_rule_identifier_in_non_code() -> None:
    text = """
rule alpha {
    condition:
        alpha
        // alpha
        "alpha"
        /alpha/
    """.lstrip()
    provider = DocumentHighlightProvider()
    highlights = provider.get_highlights(text, _pos(2, 9))
    positions = {
        (highlight.range.start.line, highlight.range.start.character) for highlight in highlights
    }
    assert positions == {(0, 5), (2, 8)}


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
