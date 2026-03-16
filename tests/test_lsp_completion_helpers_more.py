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

    assert get_current_module("rule a { condition: pe. }", _pos(0, 24)) == "pe"
    assert get_current_module("rule a { condition: no_dot }", _pos(0, 28)) is None
    assert get_current_module("x", _pos(4, 0)) is None


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
