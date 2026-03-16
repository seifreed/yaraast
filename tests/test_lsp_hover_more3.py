"""Additional branch coverage for hover provider internals (no mocks)."""

from __future__ import annotations

from types import SimpleNamespace

from lsprotocol.types import Position, Range

from yaraast.lsp.hover import HoverProvider


def _pos(line: int, char: int) -> Position:
    return Position(line=line, character=char)


def _range() -> Range:
    return Range(start=_pos(0, 0), end=_pos(0, 4))


def test_get_hover_none_and_dotted_non_member_paths() -> None:
    provider = HoverProvider()
    assert provider.get_hover("   ", _pos(0, 0)) is None
    assert provider.get_hover("a.b.c", _pos(0, 1)) is None
    hover = provider.get_hover("pe.imphash", _pos(0, 1))
    assert hover is not None
    assert "(function)" in hover.contents.value


def test_module_member_function_and_field_with_descriptions() -> None:
    provider = HoverProvider()
    provider.module_loader = SimpleNamespace(
        get_module=lambda name: (
            SimpleNamespace(
                functions={
                    "f": SimpleNamespace(
                        parameters=[("x", "int")],
                        return_type="bool",
                        description="does f",
                    ),
                },
                fields={
                    "k": SimpleNamespace(type="integer", description="field k"),
                },
            )
            if name == "m"
            else None
        ),
    )

    hover_f = provider._get_module_member_hover("m", "f", _range())
    assert hover_f is not None
    assert "function" in hover_f.contents.value
    assert "does f" in hover_f.contents.value

    hover_k = provider._get_module_member_hover("m", "k", _range())
    assert hover_k is not None
    assert "field" in hover_k.contents.value
    assert "field k" in hover_k.contents.value

    assert provider._get_module_member_hover("m", "missing", _range()) is None
    assert provider._get_module_member_hover("missing", "f", _range()) is None


def test_string_identifier_hover_regex_hex_and_fallback() -> None:
    provider = HoverProvider()

    text_regex = """
rule r {
  strings:
    $r = /ab+c/i
  condition:
    $r
}
""".lstrip()
    hover_regex = provider.get_hover(text_regex, _pos(4, 5))
    assert hover_regex is not None
    assert "(regex)" in hover_regex.contents.value

    text_hex = """
rule r {
  strings:
    $h = { 6A 40 ?? }
  condition:
    $h
}
""".lstrip()
    hover_hex = provider.get_hover(text_hex, _pos(4, 5))
    assert hover_hex is not None
    assert "(hex string)" in hover_hex.contents.value

    # Parse failure path falls back to generic identifier documentation.
    fallback = provider._get_string_identifier_hover("rule {", "$x", _range())
    assert fallback is not None
    assert "string identifier" in fallback.contents.value


def test_rule_hover_with_modifiers_tags_meta_and_strings() -> None:
    provider = HoverProvider()
    text = """
private rule alpha : t1 t2 {
  meta:
    author = "me"
  strings:
    $a = "abc"
  condition:
    true
}

rule beta {
  condition:
    alpha
}
""".lstrip()
    hover = provider.get_hover(text, _pos(11, 5))
    assert hover is not None
    value = hover.contents.value
    assert "(rule)" in value
    assert "private" in value
    assert "Tags: t1, t2" in value
    assert "Metadata" in value
    assert "**Strings:** 1 defined" in value

    # Parse failure path in _get_rule_hover should return None.
    assert provider._get_rule_hover("rule {", "x", _range()) is None


def test_get_hover_module_member_and_unknown_string_type_paths() -> None:
    provider = HoverProvider()

    provider.module_loader = SimpleNamespace(
        get_module=lambda _m: SimpleNamespace(
            functions={"f": SimpleNamespace(parameters=[], return_type="bool")},
            fields={},
        ),
    )
    hover = provider._get_module_member_hover("m", "f", _range())
    assert hover is not None
    assert "function" in hover.contents.value

    fallback = provider._get_string_identifier_hover("rule {", "$u", _range())
    assert fallback is not None
    assert "string identifier" in fallback.contents.value
