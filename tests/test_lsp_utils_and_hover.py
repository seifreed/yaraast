"""Tests for LSP utilities and hover provider."""

from __future__ import annotations

from lsprotocol.types import Position, Range

from yaraast.ast.base import Location, YaraFile
from yaraast.ast.expressions import BooleanLiteral
from yaraast.ast.rules import Rule
from yaraast.lexer.tokens import Token, TokenType
from yaraast.lsp.hover import HoverProvider
from yaraast.lsp.runtime import LspRuntime
from yaraast.lsp.utils import (
    find_node_at_position,
    get_word_at_position,
    location_to_range,
    offset_to_position,
    position_to_offset,
    token_to_range,
)


def test_token_and_location_to_range() -> None:
    token = Token(type=TokenType.IDENTIFIER, value="abc", line=2, column=3)
    token_range = token_to_range(token)
    assert token_range.start.line == 1
    assert token_range.start.character == 3
    assert token_range.end.line == 1
    assert token_range.end.character == 6

    location = Location(line=4, column=2)
    location_range = location_to_range(location)
    assert location_range.start.line == 3
    assert location_range.start.character == 2
    assert location_range.end.line == 3
    assert location_range.end.character == 3

    inline_location = Location(line=1, column=5)
    inline_range = location_to_range(inline_location, source_text="rule beta { condition: true }")
    assert inline_range.end.character > inline_range.start.character + 1


def test_position_offset_roundtrip() -> None:
    text = "abc\ndef\nghi"
    position = Position(line=1, character=2)
    offset = position_to_offset(text, position)
    assert offset == 6

    back = offset_to_position(text, offset)
    assert back.line == position.line
    assert back.character == position.character

    end = offset_to_position(text, 999)
    assert end.line == 2
    assert end.character == 3


def test_get_word_at_position_and_find_node() -> None:
    text = "rule test { condition: $a and pe.is_pe }"
    word, word_range = get_word_at_position(text, Position(line=0, character=23))
    assert word == "$a"
    assert hasattr(word_range, "start")
    assert hasattr(word_range, "end")

    rule = Rule(name="test")
    rule.location = Location(line=1, column=1)
    ast = YaraFile(rules=[rule])
    found = find_node_at_position(ast, Position(line=0, character=1))
    assert found is rule

    child = BooleanLiteral(True)
    child.location = Location(line=2, column=5)
    rule.condition = child
    found_child = find_node_at_position(ast, Position(line=1, character=5))
    assert found_child is child


def test_hover_provider_keywords_and_builtins() -> None:
    provider = HoverProvider()
    text = "rule test { condition: uint16(0) and true }"

    hover_keyword = provider.get_hover(text, Position(line=0, character=1))
    assert hover_keyword is not None
    assert "keyword" in hover_keyword.contents.value

    hover_builtin = provider.get_hover(text, Position(line=0, character=25))
    assert hover_builtin is not None
    assert "built-in function" in hover_builtin.contents.value


def test_hover_provider_module_and_string_identifier() -> None:
    provider = HoverProvider()
    text = 'rule test { strings: $a = "x" condition: $a and pe.imphash() }'

    hover_string = provider.get_hover(text, Position(line=0, character=41))
    assert hover_string is not None
    assert "string" in hover_string.contents.value

    hover_module = provider.get_hover(text, Position(line=0, character=48))
    assert hover_module is not None
    assert "imphash" in hover_module.contents.value


def test_hover_provider_runtime_supports_prefixed_string_variant(tmp_path) -> None:
    sample = tmp_path / "sample.yar"
    sample.write_text(
        """
rule test {
  strings:
    $a = "x"
  condition:
    #a > 0
}
""".lstrip(),
        encoding="utf-8",
    )
    text = sample.read_text(encoding="utf-8")
    runtime = LspRuntime()
    uri = sample.resolve().as_uri()
    runtime.open_document(uri, text)
    provider = HoverProvider(runtime)

    hover_string = provider.get_hover(text, Position(line=4, character=5), uri)
    assert hover_string is not None
    assert "$a" in hover_string.contents.value


def test_hover_provider_uses_structured_module_resolution_from_runtime(tmp_path) -> None:
    sample = tmp_path / "sample.yar"
    sample.write_text('import "pe"\nrule test { condition: pe.is_pe }\n', encoding="utf-8")
    text = sample.read_text(encoding="utf-8")
    runtime = LspRuntime()
    uri = sample.resolve().as_uri()
    runtime.open_document(uri, text)
    provider = HoverProvider(runtime)

    hover_module = provider.get_hover(text, Position(line=0, character=9), uri)
    assert hover_module is not None
    assert "(module)" in hover_module.contents.value
    assert hover_module.range.start.line == 0
    assert hover_module.range.start.character == 8
    assert hover_module.range.end.character == 10


def test_hover_provider_uses_structured_include_resolution_from_runtime(tmp_path) -> None:
    include_file = tmp_path / "common.yar"
    include_file.write_text("rule common { condition: true }\n", encoding="utf-8")
    sample = tmp_path / "sample.yar"
    sample.write_text('include "common.yar"\nrule test { condition: true }\n', encoding="utf-8")
    text = sample.read_text(encoding="utf-8")
    runtime = LspRuntime()
    uri = sample.resolve().as_uri()
    runtime.open_document(uri, text)
    provider = HoverProvider(runtime)

    hover_include = provider.get_hover(text, Position(line=0, character=10), uri)
    assert hover_include is not None
    assert "(include)" in hover_include.contents.value
    assert "common.yar" in hover_include.contents.value
    assert str(include_file.resolve()) in hover_include.contents.value
    assert hover_include.range.start.line == 0
    assert hover_include.range.start.character == 9
    assert hover_include.range.end.character == 19


def test_hover_provider_uses_structured_module_member_resolution_from_runtime(tmp_path) -> None:
    sample = tmp_path / "sample.yar"
    sample.write_text('import "pe"\nrule test { condition: pe.imphash() }\n', encoding="utf-8")
    text = sample.read_text(encoding="utf-8")
    runtime = LspRuntime()
    uri = sample.resolve().as_uri()
    runtime.open_document(uri, text)
    provider = HoverProvider(runtime)

    hover_member = provider.get_hover(text, Position(line=1, character=29), uri)
    assert hover_member is not None
    assert "imphash" in hover_member.contents.value
    assert hover_member.range.start.line == 1
    assert hover_member.range.start.character == 23
    assert hover_member.range.end.character == 33


def test_hover_provider_module_member_and_rule() -> None:
    provider = HoverProvider()
    word_range = Range(start=Position(line=0, character=0), end=Position(line=0, character=7))

    member_hover = provider._get_module_member_hover("pe", "imphash", word_range)
    assert member_hover is not None
    assert "function" in member_hover.contents.value

    text = "rule test { condition: true }\nrule other { condition: test }"
    hover_rule = provider.get_hover(text, Position(line=1, character=24))
    assert hover_rule is not None
    assert "(rule)" in hover_rule.contents.value


def test_hover_provider_uses_local_structured_resolution_for_prefixed_string() -> None:
    provider = HoverProvider()
    text = """
rule test {
  strings:
    $a = "x"
  condition:
    #a > 0
}
""".lstrip()

    hover_string = provider.get_hover(text, Position(line=4, character=5), "file://local.yar")
    assert hover_string is not None
    assert "$a" in hover_string.contents.value


def test_hover_provider_uses_structured_meta_and_section_resolution(tmp_path) -> None:
    sample = tmp_path / "sample.yar"
    sample.write_text(
        """
rule sample {
  meta:
    author = "me"
  strings:
    $a = "x"
  condition:
    $a
}
""".lstrip(),
        encoding="utf-8",
    )
    text = sample.read_text(encoding="utf-8")
    runtime = LspRuntime()
    uri = sample.resolve().as_uri()
    runtime.open_document(uri, text)
    provider = HoverProvider(runtime)

    meta_hover = provider.get_hover(text, Position(line=2, character=5), uri)
    assert meta_hover is not None
    assert "(metadata)" in meta_hover.contents.value
    assert "me" in meta_hover.contents.value
    assert meta_hover.range.start.line == 2
    assert meta_hover.range.start.character == 4
    assert meta_hover.range.end.character == 10

    section_hover = provider.get_hover(text, Position(line=3, character=4), uri)
    assert section_hover is not None
    assert "(section)" in section_hover.contents.value
    assert "strings" in section_hover.contents.value
    assert section_hover.range.start.line == 3
    assert section_hover.range.start.character == 2
    assert section_hover.range.end.character == 9
