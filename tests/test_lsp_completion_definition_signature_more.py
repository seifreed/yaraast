"""Additional real LSP provider tests."""

from __future__ import annotations

from lsprotocol.types import Position

from yaraast.lsp.completion import CompletionProvider
from yaraast.lsp.definition import DefinitionProvider
from yaraast.lsp.signature_help import SignatureHelpProvider


def _pos(line: int, char: int) -> Position:
    return Position(line=line, character=char)


def test_completion_meta_and_string_modifier_contexts() -> None:
    provider = CompletionProvider()

    meta_text = """
rule a {
  meta:
    au
  condition:
    true
}
""".lstrip()
    meta_items = provider.get_completions(meta_text, _pos(2, 4)).items
    meta_labels = {item.label for item in meta_items}
    assert "author" in meta_labels
    assert "description" in meta_labels

    modifier_text = """
rule a {
  strings:
    $a = "x" no
  condition:
    $a
}
""".lstrip()
    modifier_items = provider.get_completions(modifier_text, _pos(2, 15)).items
    modifier_labels = {item.label for item in modifier_items}
    assert "nocase" in modifier_labels
    assert "wide" in modifier_labels


def test_completion_unknown_module_member_returns_empty() -> None:
    provider = CompletionProvider()
    text = "rule r { condition: unknown_mod. }"

    completions = provider.get_completions(text, _pos(0, len(text)))

    assert completions.items == []


def test_definition_provider_handles_missing_symbol_and_parse_failure() -> None:
    provider = DefinitionProvider()
    uri = "file://test.yar"

    assert provider.get_definition("rule a { condition: true }", _pos(0, 999), uri) is None

    text = """
rule a {
  strings:
    $a = "x"
  condition:
    #a > 0 and @a[1] > 0 and !a[1] > 0
}
""".lstrip()
    assert provider.get_definition(text, _pos(4, 5), uri) is not None
    assert provider.get_definition(text, _pos(4, 16), uri) is not None
    assert provider.get_definition(text, _pos(4, 29), uri) is not None

    broken = """
rule a {
  strings:
    $a = "unterminated
  condition:
    $a
}
""".lstrip()
    assert provider.get_definition(broken, _pos(4, 5), uri) is None
    assert provider._find_rule_definition(broken, "a", uri) is None


def test_signature_help_edge_cases_and_parameter_counting() -> None:
    provider = SignatureHelpProvider()

    assert provider.get_signature_help("rule a { condition: true }", _pos(0, 0)) is None
    assert provider.get_signature_help("rule a { condition: foo(1) }", _pos(0, 26)) is None

    boundary_text = "rule a { condition: { uint32(0) } }"
    assert provider._find_function_at_position(boundary_text, _pos(0, 22)) is None

    assert provider._find_function_at_position("uint32(", _pos(1, 0)) is None
    assert provider._find_function_at_position("(", _pos(0, 1)) is None

    text = "math.deviation(1, 2, 3)"
    sig = provider.get_signature_help(text, _pos(0, len(text) - 1))
    assert sig is not None
    assert sig.active_parameter == 2
    assert "deviation" in sig.signatures[0].label

    assert provider._calculate_active_parameter("uint32(1,", _pos(1, 0)) == 0
    assert provider._calculate_active_parameter("uint32(1", _pos(0, 99)) == 0
    assert provider._calculate_active_parameter("uint32(1)", _pos(0, len("uint32(1)"))) == 0
