"""Additional direct tests for LSP completion helpers."""

from __future__ import annotations

from dataclasses import dataclass

from lsprotocol.types import Position

from yaraast.lsp.completion_helpers import (
    analyze_context,
    build_condition_completions,
    build_module_member_completions,
    get_current_module,
)
from yaraast.lsp.language_services import parse_source


def _pos(line: int, char: int) -> Position:
    return Position(line=line, character=char)


@dataclass
class _FakeFunction:
    parameters: list[tuple[str, str]]
    description: str | None = None


@dataclass
class _FakeField:
    type: str | None = None
    description: str | None = None


@dataclass
class _FakeModule:
    functions: dict[str, _FakeFunction]
    fields: dict[str, _FakeField] | None = None
    attributes: dict[str, object] | None = None


def test_analyze_context_and_current_module_edges() -> None:
    assert analyze_context("", _pos(5, 0)) == "general"

    regex_string = """
rule a {
  strings:
    $a = /abc/ n
}
""".lstrip()
    assert analyze_context(regex_string, _pos(2, 16)) == "string_modifier"

    ascii_string = """
rule a {
  strings:
    $a = "x" ascii
}
""".lstrip()
    assert analyze_context(ascii_string, _pos(2, 18)) == "string_modifier"

    in_strings = """
rule a {
  strings:
    $a = "x"
}
""".lstrip()
    assert analyze_context(in_strings, _pos(2, 3)) == "strings"

    dotted_string = """
rule a {
  strings:
    $a = "a.b"
}
""".lstrip()
    assert analyze_context(dotted_string, _pos(2, 14)) == "string_modifier"

    condition_after_module = "rule r {\n  condition:\n    pe.is_pe and "
    condition_after_decimal = "rule r {\n  condition:\n    filesize > 1.0 and "
    assert analyze_context(condition_after_module, _pos(2, 17)) == "condition"
    assert analyze_context(condition_after_decimal, _pos(2, 23)) == "condition"

    assert get_current_module("rule a { condition: pe. }", _pos(0, 24)) == "pe"
    assert get_current_module(condition_after_module, _pos(2, 17)) is None
    assert get_current_module("rule a { condition: no_dot }", _pos(0, 28)) is None
    assert get_current_module("x", _pos(4, 0)) is None


def test_analyze_context_stops_at_modified_rule_declarations() -> None:
    text = """
private rule a {
  condition:
    true
}
private rule b {

}
""".lstrip()

    assert analyze_context(text, _pos(5, 2)) == "general"


def test_build_module_member_completions_uses_fields_and_attributes_fallback() -> None:
    module_with_fields = _FakeModule(
        functions={"f": _FakeFunction(parameters=[("x", "int")], description="fn")},
        fields={"flag": _FakeField(type=None, description="field")},
    )
    items = build_module_member_completions("mod", module_with_fields)
    labels = {item.label for item in items}
    assert "f" in labels
    assert "flag" in labels
    flag = next(item for item in items if item.label == "flag")
    assert flag.detail is not None
    assert "mod.flag:" in flag.detail

    module_with_attributes = _FakeModule(
        functions={},
        fields=None,
        attributes={"attr": 123},
    )
    items = build_module_member_completions("mod", module_with_attributes)
    attr = next(item for item in items if item.label == "attr")
    assert attr.detail == "mod.attr: 123"

    assert (
        build_module_member_completions(
            "mod", _FakeModule(functions={}, fields=None, attributes=None)
        )
        == []
    )


def test_build_condition_completions_falls_back_to_keywords_on_invalid_text() -> None:
    items = build_condition_completions(
        'rule a { strings: $a = "unterminated }', ["rule", "condition"]
    )
    labels = {item.label for item in items}
    assert labels == {"rule", "condition"}


def test_lsp_condition_completions_parse_yarax_sources() -> None:
    text = 'rule x { strings: $a = "x" condition: with xs = [1]: match xs { _ => $a } }'

    ast = parse_source(text)
    items = build_condition_completions(text, ["with", "match"])

    labels = {item.label for item in items}
    assert ast.rules[0].condition.__class__.__name__ == "WithStatement"
    assert "$a" in labels


def test_condition_completions_hide_anonymous_internal_string_ids() -> None:
    text = """
rule x {
  strings:
    $a = "x"
    $ = "anonymous"
  condition:
    true
}
""".lstrip()

    items = build_condition_completions(text, [])
    labels = {item.label for item in items}

    assert "$a" in labels
    assert "#a" in labels
    assert "$anon_1" not in labels
    assert "#anon_1" not in labels
    assert "@anon_1" not in labels
    assert "!anon_1" not in labels
