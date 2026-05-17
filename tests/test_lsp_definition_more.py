"""Real tests for LSP definition provider (no mocks)."""

from __future__ import annotations

from lsprotocol.types import Location, Position

from yaraast.lsp.definition import DefinitionProvider


def _pos(line: int, char: int) -> Position:
    return Position(line=line, character=char)


def _single_location(location: Location | list[Location]) -> Location:
    assert not isinstance(location, list)
    return location


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
    string_def = _single_location(string_def)
    assert string_def.range.start.line == 2

    rule_def = provider.get_definition(text, _pos(9, 9), uri)
    assert rule_def is not None
    rule_def = _single_location(rule_def)
    assert rule_def.range.start.line == 0


def test_definition_rule_reference_at_end_of_line() -> None:
    text = """
rule alpha { condition: true }
rule beta {
    condition:
        alpha
}
""".lstrip()

    rule_line = text.splitlines()[3]
    rule_def = DefinitionProvider().get_definition(
        text,
        _pos(3, len(rule_line)),
        "file://test.yar",
    )

    assert rule_def is not None
    assert _single_location(rule_def).range.start.line == 0
