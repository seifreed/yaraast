"""Coverage for LSP document query lookups (meta, strings, modules, includes).

Includes a regression for module field info, which previously read a
non-existent ``fields`` attribute instead of ``attributes`` and so never
returned field metadata.
"""

from __future__ import annotations

from lsprotocol.types import Position

from yaraast.lsp import document_query_lookup as lookup
from yaraast.lsp.document_context import DocumentContext

PARSEABLE = """import "pe"
include "./other.yar"
rule alpha {
    meta:
        author = "alice"
        score = 5
        active = true
    strings:
        $a = "plain"
    condition:
        $a and pe.number_of_sections > 0 and pe.imports("k")
}
"""

UNPARSEABLE = (
    'rule broken {\n  meta:\n    author = "bob"\n    count = 3\n    flag = true\n  condition:\n'
)


def _doc(text: str) -> DocumentContext:
    return DocumentContext(uri="file://x.yar", text=text)


def test_get_meta_value_from_ast() -> None:
    doc = _doc(PARSEABLE)
    assert doc.ast() is not None
    assert lookup.get_meta_value(doc, "author") == "alice"
    assert lookup.get_meta_value(doc, "score") == 5
    assert lookup.get_meta_value(doc, "missing") is None


def test_get_meta_value_text_fallback() -> None:
    doc = _doc(UNPARSEABLE)
    assert doc.ast() is None
    assert lookup.get_meta_value(doc, "author") == "bob"
    assert lookup.get_meta_value(doc, "count") == 3
    assert lookup.get_meta_value(doc, "flag") is True


def test_get_meta_value_text_fallback_keeps_complex_literals_as_text() -> None:
    doc = _doc("rule broken {\n  meta:\n    payload = [1, 2, 3]\n  condition:\n")
    assert doc.ast() is None
    value = lookup.get_meta_value(doc, "payload")
    assert value == "[1, 2, 3]"
    assert isinstance(value, str)


def test_get_meta_value_text_fallback_rejects_non_finite_numbers() -> None:
    doc = _doc("rule broken {\n  meta:\n    payload = NaN\n  condition:\n")
    assert doc.ast() is None
    assert lookup.get_meta_value(doc, "payload") == "NaN"


def test_string_definition_lookups() -> None:
    doc = _doc(PARSEABLE)
    assert lookup.get_string_definition_node(doc, "$a") is not None
    assert lookup.get_string_definition_info(doc, "$a")
    assert lookup.get_string_definition_node(doc, "$missing") is None


def test_module_member_info_function_and_field() -> None:
    doc = _doc(PARSEABLE)

    function_info = lookup.get_module_member_info(doc, "pe.imports")
    assert function_info is not None
    assert function_info["kind"] == "function"

    # Regression: field info reads module attributes, not a missing 'fields' attr.
    field_info = lookup.get_module_member_info(doc, "pe.number_of_sections")
    assert field_info is not None
    assert field_info["kind"] == "field"

    assert lookup.get_module_member_info(doc, "pe.nonexistent_xyz") is None
    assert lookup.get_module_member_info(doc, "nomodule.x") is None


def test_include_info_and_dotted_symbol_at_position() -> None:
    doc = _doc(PARSEABLE)
    assert lookup.get_include_info(doc, "./other.yar")

    dotted = lookup.get_dotted_symbol_at_position(doc, Position(line=11, character=30))
    assert dotted is None or isinstance(dotted[0], str)
