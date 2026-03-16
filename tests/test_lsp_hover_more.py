"""Real tests for LSP hover provider (no mocks)."""

from __future__ import annotations

from textwrap import dedent

from lsprotocol.types import Position

from yaraast.lsp.hover import HoverProvider


def _pos(line: int, char: int) -> Position:
    return Position(line=line, character=char)


def test_hover_keyword_and_builtin() -> None:
    provider = HoverProvider()
    text = "rule x { condition: true }\nuint16(0)"

    hover_rule = provider.get_hover(text, _pos(0, 1))
    assert hover_rule is not None
    assert "(keyword)" in hover_rule.contents.value

    hover_uint = provider.get_hover(text, _pos(1, 1))
    assert hover_uint is not None
    assert "built-in function" in hover_uint.contents.value


def test_hover_module_and_string_identifier() -> None:
    provider = HoverProvider()
    text = dedent(
        """
        import "pe"
        rule demo {
            strings:
                $a = "abc" ascii
            condition:
                $a and pe.is_pe
        }
        """,
    ).lstrip()

    hover_module = provider.get_hover(text, _pos(0, 8))
    assert hover_module is not None
    assert "(module)" in hover_module.contents.value

    hover_string = provider.get_hover(text, _pos(5, 8))
    assert hover_string is not None
    assert "string" in hover_string.contents.value


def test_hover_rule_name() -> None:
    provider = HoverProvider()
    text = dedent(
        """
        rule alpha {
            meta:
                author = "unit"
            condition:
                true
        }

        rule beta : tag1 {
            condition:
                alpha
        }
        """,
    ).lstrip()

    hover_rule = provider.get_hover(text, _pos(9, 8))
    assert hover_rule is not None
    assert "**alpha**" in hover_rule.contents.value
    assert "Metadata" in hover_rule.contents.value


def test_hover_module_member_direct() -> None:
    provider = HoverProvider()
    word_range = provider.get_hover("pe.imphash", _pos(0, 1)).range
    hover = provider._get_module_member_hover("pe", "imphash", word_range)
    assert hover is not None
    assert "function" in hover.contents.value
