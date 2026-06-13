"""Additional real LSP provider tests."""

from __future__ import annotations

from typing import Any, cast

from lsprotocol.types import Position
import pytest

from yaraast.lsp.completion import CompletionProvider
from yaraast.lsp.definition import DefinitionProvider
from yaraast.lsp.signature_help import SignatureHelpProvider
from yaraast.lsp.utf16 import utf8_col_to_utf16


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


@pytest.mark.parametrize("text", [None, 1, b"rule a", object()])
def test_definition_rejects_non_string_text(text: Any) -> None:
    provider = DefinitionProvider()

    with pytest.raises(TypeError, match="Definition text must be a string"):
        provider.get_definition(cast(str, text), _pos(0, 0), "file://test.yar")


def test_definition_rejects_non_position_inputs() -> None:
    provider = DefinitionProvider()

    with pytest.raises(TypeError, match="position must be an LSP Position"):
        provider.get_definition(
            "rule a { condition: true }", cast(Any, object()), "file://test.yar"
        )


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

    nested_text = "math.deviation(uint32(0), 10, "
    nested_sig = provider.get_signature_help(nested_text, _pos(0, len(nested_text)))
    assert nested_sig is not None
    assert nested_sig.active_parameter == 2
    assert "deviation" in nested_sig.signatures[0].label

    string_comma_text = 'pe.imports("kernel,32", '
    string_comma_sig = provider.get_signature_help(
        string_comma_text, _pos(0, len(string_comma_text))
    )
    assert string_comma_sig is not None
    assert string_comma_sig.active_parameter == 1
    assert "imports" in string_comma_sig.signatures[0].label

    regex_after_matches_text = 'pe.imports("abc" matches /a,b/'
    regex_after_matches_sig = provider.get_signature_help(
        regex_after_matches_text, _pos(0, len(regex_after_matches_text))
    )
    assert regex_after_matches_sig is not None
    assert regex_after_matches_sig.active_parameter == 0
    assert "imports" in regex_after_matches_sig.signatures[0].label

    rich_signature_text = "pe.rich_signature.version(1, "
    rich_signature_sig = provider.get_signature_help(
        rich_signature_text, _pos(0, len(rich_signature_text))
    )
    assert rich_signature_sig is not None
    assert rich_signature_sig.active_parameter == 1
    assert "version" in rich_signature_sig.signatures[0].label


@pytest.mark.parametrize("text", [None, 1, b"uint32(", object()])
def test_signature_help_rejects_non_string_text(text: Any) -> None:
    provider = SignatureHelpProvider()

    with pytest.raises(TypeError, match="Signature help text must be a string"):
        provider.get_signature_help(cast(str, text), _pos(0, 0))


def test_signature_help_rejects_non_position_inputs() -> None:
    provider = SignatureHelpProvider()

    with pytest.raises(TypeError, match="position must be an LSP Position"):
        provider.get_signature_help("uint32(", cast(Any, object()))


def test_signature_help_uses_utf16_cursor_for_active_parameter() -> None:
    provider = SignatureHelpProvider()
    text = "rule a { condition: /* 😀 */ hash.md5(value, length) }"
    cursor = text.index(",")

    signature = provider.get_signature_help(text, _pos(0, utf8_col_to_utf16(text, cursor)))

    assert signature is not None
    assert signature.active_parameter == 0

    assert provider._calculate_active_parameter("uint32(1,", _pos(1, 0)) == 0
    assert provider._calculate_active_parameter("uint32(1", _pos(0, 99)) == 0
    assert provider._calculate_active_parameter("uint32(1)", _pos(0, len("uint32(1)"))) == 0


def test_signature_help_tracks_multiline_function_calls() -> None:
    provider = SignatureHelpProvider()
    text = "\n".join(
        [
            "rule a {",
            "  condition:",
            "    pe.imports(",
            '      "kernel32.dll",',
            "      ",
        ]
    )

    signature = provider.get_signature_help(text, _pos(4, 6))

    assert signature is not None
    assert signature.active_parameter == 1
    assert "imports" in signature.signatures[0].label
