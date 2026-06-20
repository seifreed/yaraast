"""Coverage for LSP per-rule document queries (info, meta, strings, sections)."""

from __future__ import annotations

from yaraast.lsp import document_rule_queries as queries
from yaraast.lsp.document_context import DocumentContext

PARSEABLE = (
    "rule alpha {\n"
    "    meta:\n"
    '        author = "alice"\n'
    "        score = 5\n"
    "        active = true\n"
    "    strings:\n"
    '        $a = "plain"\n'
    '        $b = "other"\n'
    "    condition:\n"
    "        $a or $b\n"
    "}\n"
)

UNPARSEABLE = 'rule broken {\n  meta:\n    author = "bob"\n    count = 3\n  strings:\n    $a = "x"\n  condition:\n'


def _doc(text: str) -> DocumentContext:
    return DocumentContext(uri="file://x.yar", text=text)


def test_rule_info_and_members_from_ast() -> None:
    doc = _doc(PARSEABLE)
    assert doc.ast() is not None
    info = queries.get_rule_info(doc, "alpha")
    assert info is not None
    assert queries.get_rule_info(doc, "missing") is None
    assert ("author", "alice") in queries.get_rule_meta_items(doc, "alpha")
    assert "$a" in queries.get_rule_string_identifiers(doc, "alpha")
    sections = queries.get_rule_sections(doc, "alpha")
    assert "meta" in sections and "strings" in sections and "condition" in sections


def test_rule_meta_text_fallback() -> None:
    doc = _doc(UNPARSEABLE)
    assert doc.ast() is None
    items = queries.get_rule_meta_items(doc, "broken")
    keys = {key for key, _value in items}
    assert "author" in keys


def test_parse_meta_assignment_variants() -> None:
    assert queries._parse_meta_assignment('author = "alice"') == ("author", "alice")
    assert queries._parse_meta_assignment("score = 5") == ("score", 5)
    assert queries._parse_meta_assignment("active = true") == ("active", True)
    assert queries._parse_meta_assignment("no assignment here") == (None, None)
