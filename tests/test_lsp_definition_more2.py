"""More tests for LSP definition provider (no mocks)."""

from __future__ import annotations

from pathlib import Path

from lsprotocol.types import Position

from yaraast.lsp.definition import DefinitionProvider


def _pos(line: int, char: int) -> Position:
    return Position(line=line, character=char)


def test_definition_string_identifier() -> None:
    text = """
rule a {
  strings:
    $a = "x"
  condition:
    $a
}
""".lstrip()

    provider = DefinitionProvider()
    location = provider.get_definition(text, _pos(4, 5), "file://test.yar")
    assert location is not None
    assert location.range.start.line == 2


def test_definition_rule_reference() -> None:
    text = """
rule a { condition: true }
rule b { condition: a }
""".lstrip()

    provider = DefinitionProvider()
    location = provider.get_definition(text, _pos(1, 20), "file://test.yar")
    assert location is not None
    assert location.range.start.line == 0


def test_definition_prefixed_string_reference_without_runtime() -> None:
    text = """
rule a {
  strings:
    $a = "x"
  condition:
    #a > 0 and @a[1] > 0 and !a[1] > 0
}
""".lstrip()

    provider = DefinitionProvider()
    assert provider.get_definition(text, _pos(4, 5), "file://test.yar") is not None
    assert provider.get_definition(text, _pos(4, 16), "file://test.yar") is not None
    assert provider.get_definition(text, _pos(4, 29), "file://test.yar") is not None


def test_definition_include_target(tmp_path: Path) -> None:
    include_file = tmp_path / "common.yar"
    include_file.write_text("rule common { condition: true }\n", encoding="utf-8")
    sample = tmp_path / "sample.yar"
    sample.write_text('include "common.yar"\nrule test { condition: true }\n', encoding="utf-8")

    provider = DefinitionProvider()
    location = provider.get_definition(
        sample.read_text(encoding="utf-8"),
        _pos(0, 10),
        sample.resolve().as_uri(),
    )
    assert location is not None
    assert location.uri == include_file.resolve().as_uri()
    assert location.range.start.line == 0
    assert location.range.start.character == 0
