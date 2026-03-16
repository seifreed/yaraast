"""Real tests for LSP definition provider (no mocks)."""

from __future__ import annotations

from lsprotocol.types import Position

from yaraast.lsp.definition import DefinitionProvider


def _pos(line: int, char: int) -> Position:
    return Position(line=line, character=char)


def test_definition_string_and_rule() -> None:
    text = """
rule alpha {
    strings:
        $a = "abc"
    condition:
        $a
}

rule beta {
    condition:
        alpha
}
""".lstrip()

    provider = DefinitionProvider()
    uri = "file://test.yar"

    string_def = provider.get_definition(text, _pos(4, 8), uri)
    assert string_def is not None
    assert string_def.range.start.line == 2

    rule_def = provider.get_definition(text, _pos(9, 9), uri)
    assert rule_def is not None
    assert rule_def.range.start.line == 0
