"""Real tests for LSP hover provider (no mocks)."""

from __future__ import annotations

from textwrap import dedent

from lsprotocol.types import Hover, MarkupContent, Position, Range

from yaraast.lsp.hover import HoverProvider


def _pos(line: int, char: int) -> Position:
    return Position(line=line, character=char)


def _hover_text(hover: Hover) -> str:
    assert isinstance(hover.contents, MarkupContent)
    return hover.contents.value


def _hover_range(hover: Hover) -> Range:
    assert hover.range is not None
    return hover.range


def test_hover_keyword_and_builtin() -> None:
    provider = HoverProvider()
    text = "rule x { condition: true }\nuint16(0)"

    hover_rule = provider.get_hover(text, _pos(0, 1))
    assert hover_rule is not None
    assert "(keyword)" in _hover_text(hover_rule)

    hover_uint = provider.get_hover(text, _pos(1, 1))
    assert hover_uint is not None
    assert "built-in function" in _hover_text(hover_uint)


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
    assert "(module)" in _hover_text(hover_module)

    hover_string = provider.get_hover(text, _pos(5, 8))
    assert hover_string is not None
    assert "string" in _hover_text(hover_string)


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
    hover_rule_text = _hover_text(hover_rule)
    assert "**alpha**" in hover_rule_text
    assert "Metadata" in hover_rule_text


def test_hover_rule_name_survives_parse_failure() -> None:
    provider = HoverProvider()
    text = dedent("""
        rule alpha : tag1 {
            strings:
                $a = "abc"
            condition:
                true
        }

        rule broken {
            condition:
        """).lstrip()

    hover_rule = provider.get_hover(text, _pos(0, 5))
    assert hover_rule is not None
    hover_rule_text = _hover_text(hover_rule)
    assert "**alpha**" in hover_rule_text
    assert "Tags: tag1" in hover_rule_text
    assert "**Strings:** 1 defined" in hover_rule_text


def test_hover_module_member_direct() -> None:
    provider = HoverProvider()
    word_hover = provider.get_hover("pe.imphash", _pos(0, 1))
    assert word_hover is not None
    word_range = _hover_range(word_hover)
    hover = provider._get_module_member_hover("pe", "imphash", word_range)
    assert hover is not None
    assert "function" in _hover_text(hover)
