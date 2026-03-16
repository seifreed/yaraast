"""More tests for LSP hover provider (no mocks)."""

from __future__ import annotations

from lsprotocol.types import Position

from yaraast.lsp.hover import HoverProvider


def _pos(line: int, char: int) -> Position:
    return Position(line=line, character=char)


def test_hover_keyword_and_builtin() -> None:
    text = "rule a { condition: uint16(0) and true }"
    provider = HoverProvider()

    hover_rule = provider.get_hover(text, _pos(0, 1))
    assert hover_rule is not None
    assert "keyword" in hover_rule.contents.value

    hover_uint = provider.get_hover(text, _pos(0, 22))
    assert hover_uint is not None
    assert "built-in function" in hover_uint.contents.value


def test_hover_string_identifier() -> None:
    text = """
rule a {
  strings:
    $a = "x" ascii
  condition:
    $a
}
""".lstrip()

    provider = HoverProvider()
    hover = provider.get_hover(text, _pos(4, 5))
    assert hover is not None
    assert "$a" in hover.contents.value
