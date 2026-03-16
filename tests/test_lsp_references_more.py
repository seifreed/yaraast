"""Real tests for LSP references provider (no mocks)."""

from __future__ import annotations

from lsprotocol.types import Position

from yaraast.lsp.references import ReferencesProvider


def _pos(line: int, char: int) -> Position:
    return Position(line=line, character=char)


def test_references_string_variants() -> None:
    text = """
rule r {
    strings:
        $a = "abc"
    condition:
        $a and #a > 0 and @a == 10 and !a
}
""".lstrip()

    provider = ReferencesProvider()
    refs = provider.get_references(text, _pos(4, 8), "file://test.yar")

    assert len(refs) >= 4


def test_references_word() -> None:
    text = """
rule alpha { condition: true }
rule beta { condition: alpha }
""".lstrip()

    provider = ReferencesProvider()
    refs = provider.get_references(text, _pos(1, 23), "file://test.yar")

    assert len(refs) >= 2
