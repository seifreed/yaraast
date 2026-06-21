"""Regression tests raising symbol_tree_builder.py coverage toward 100%.

Copyright (c) 2026 Marc Rivero López
Licensed under GPLv3. See LICENSE file for details.
This test suite validates real code behavior without mocks or stubs.

Coverage targets (module yaraast.lsp.symbol_tree_builder):
- Lines 81-90   : include records path in _append_include_symbols
- Lines 265-273 : _kind_for_record branches (include, rule, meta, default)
- Lines 509-517 : _append_extra_sections reaching inner body for YARAL rules
- Line 580      : make_range function body called directly

Unreachable lines (defensive guards — reported, not faked):
- 28, 30->25    : rule is None / rule_symbol is None from _build_rule_symbol
                  (get_rule_names() and get_rule() share the same index; the guard
                  can only fire if the index is in an impossible inconsistent state)
- 52-66         : import fallback (import_records empty but get_import_modules non-empty)
                  (both use _symbol_index.get_symbols(); they are structurally in sync)
- 93-107        : include fallback — same structural argument as the import fallback
- 128           : rule_line < 0 in _build_rule_symbol
                  (rule name comes from get_rule_names() which requires a symbol record,
                  so find_symbol_record always succeeds for that name)
- 201           : seen_rules duplicate guard in _build_text_document_symbols
                  (build_text_symbols deduplicates rule names before indexing)
- 205->199      : _build_text_rule_symbol always returns a DocumentSymbol, never None
- 303, 305->exit: meta_line < 0 guard in _append_meta_section
                  (meta section records are always created when the AST succeeds)
- 332           : hasattr(rule.meta, "entries") re-check in _build_meta_children
                  (neither YARA nor YARA-X AST uses an entries attribute on meta)
- 340->342, 343 : meta record fallback in _build_meta_children
                  (meta_records_by_name and meta_items are derived from the same index)
- 356->337      : key_line < 0 guard in _build_meta_children
- 387           : strings_line < 0 guard in _append_strings_section
- 405-419       : string identifier fallback (no string_records but get_rule_string_identifiers
                  non-empty — same structural impossibility as import/include fallbacks)
- 427->exit     : string_children empty guard
- 458           : condition_line < 0 guard in _append_condition_section
- 467           : condition make_range fallback (section record always present for parsed doc)
"""

from __future__ import annotations

from lsprotocol.types import SymbolKind

from yaraast.lsp.document_context import DocumentContext
from yaraast.lsp.document_types import LanguageMode
from yaraast.lsp.symbol_tree_builder import (
    _build_text_document_symbols,
    _kind_for_record,
    build_document_symbols,
    make_range,
)

# ---------------------------------------------------------------------------
# Lines 81-90: _append_include_symbols include-records path
# ---------------------------------------------------------------------------


def test_include_records_path_emits_file_symbol() -> None:
    """build_document_symbols covers lines 81-90 when a parseable doc has an include."""
    text = 'include "common.yar"\nrule sample { condition: true }\n'
    doc = DocumentContext(uri="file://x.yar", text=text)
    lines = text.split("\n")

    symbols = build_document_symbols(doc, lines)

    names = [s.name for s in symbols]
    assert 'include "common.yar"' in names
    include_sym = next(s for s in symbols if s.name == 'include "common.yar"')
    assert include_sym.kind == SymbolKind.File


def test_include_and_import_records_both_present() -> None:
    """Parseable doc with both import and include produces both top-level symbols."""
    text = 'import "pe"\ninclude "helpers.yar"\nrule r { condition: pe.is_pe }\n'
    doc = DocumentContext(uri="file://x.yar", text=text)
    lines = text.split("\n")

    symbols = build_document_symbols(doc, lines)
    names = [s.name for s in symbols]

    assert 'import "pe"' in names
    assert 'include "helpers.yar"' in names


# ---------------------------------------------------------------------------
# Lines 265, 267, 269, 273: _kind_for_record branches
# ---------------------------------------------------------------------------


def test_kind_for_record_include_returns_file() -> None:
    """Line 265: _kind_for_record('include') returns SymbolKind.File."""
    assert _kind_for_record("include") == SymbolKind.File


def test_kind_for_record_rule_returns_class() -> None:
    """Line 267: _kind_for_record('rule') returns SymbolKind.Class."""
    assert _kind_for_record("rule") == SymbolKind.Class


def test_kind_for_record_meta_returns_property() -> None:
    """Line 269: _kind_for_record('meta') returns SymbolKind.Property."""
    assert _kind_for_record("meta") == SymbolKind.Property


def test_kind_for_record_import_returns_namespace() -> None:
    """Line 264: _kind_for_record('import') returns SymbolKind.Namespace."""
    assert _kind_for_record("import") == SymbolKind.Namespace


def test_kind_for_record_condition_returns_function() -> None:
    """Line 271: _kind_for_record('condition') returns SymbolKind.Function."""
    assert _kind_for_record("condition") == SymbolKind.Function


def test_kind_for_record_default_returns_variable() -> None:
    """Line 273: unknown kinds fall through to SymbolKind.Variable."""
    assert _kind_for_record("section") == SymbolKind.Variable
    assert _kind_for_record("string") == SymbolKind.Variable
    assert _kind_for_record("unknown_kind") == SymbolKind.Variable


# ---------------------------------------------------------------------------
# Lines 269, 273 via _build_text_document_symbols -> _document_symbol_from_record
# ---------------------------------------------------------------------------


def test_text_fallback_meta_grandchildren_use_property_kind() -> None:
    """Lines 269, 273: text fallback calls _kind_for_record for meta and string records.

    The truncated source fails to parse, so build_document_symbols takes the text
    fallback path. _document_symbol_from_record is called for each section child,
    exercising _kind_for_record with 'meta' (-> Property) and 'string' (-> Variable).
    """
    # No closing brace: the parser fails, triggering text fallback.
    text = (
        "rule alpha {\n"
        "    meta:\n"
        '        author = "alice"\n'
        "    strings:\n"
        '        $a = "plain"\n'
        "    condition:\n"
        "        $a\n"
    )
    doc = DocumentContext(uri="file://x.yar", text=text)
    assert doc.ast() is None, "Expected parse failure for truncated source"
    lines = text.split("\n")

    symbols = _build_text_document_symbols(doc, lines)

    rule_sym = next(s for s in symbols if s.name == "alpha")
    children = rule_sym.children or []
    child_map = {c.name: c for c in children}

    # 'meta' section itself uses _kind_for_record('section') -> Variable
    assert "meta" in child_map
    assert child_map["meta"].kind == SymbolKind.Variable

    # grandchildren: 'meta' kind records -> _kind_for_record('meta') -> Property
    meta_grandchildren = child_map["meta"].children or []
    assert any(gc.kind == SymbolKind.Property for gc in meta_grandchildren)

    # 'strings' section children: 'string' kind -> _kind_for_record('string') -> Variable
    assert "strings" in child_map
    string_grandchildren = child_map["strings"].children or []
    assert any(gc.kind == SymbolKind.Variable for gc in string_grandchildren)


# ---------------------------------------------------------------------------
# Lines 509-517: _append_extra_sections body for YARAL rules
# ---------------------------------------------------------------------------


def test_yaral_rule_with_events_section_produces_events_child() -> None:
    """Lines 509-517: extra section body runs for a YARAL rule with an events section."""
    text = (
        "rule login_event {\n"
        "  events:\n"
        '    $e.metadata.event_type = "USER_LOGIN"\n'
        "  condition:\n"
        "    $e\n"
        "}\n"
    )
    doc = DocumentContext(uri="file://login.yar", text=text, language_mode=LanguageMode.YARA_L)
    assert doc.ast() is not None
    lines = text.split("\n")

    symbols = build_document_symbols(doc, lines)

    rule_sym = next(s for s in symbols if s.name == "login_event")
    child_names = [c.name for c in (rule_sym.children or [])]
    assert "events" in child_names
    assert "condition" in child_names


def test_yaral_rule_with_all_extra_sections() -> None:
    """Lines 509-517: each extra section (events, match, outcome) runs the inner body."""
    text = (
        "rule full_event {\n"
        "  events:\n"
        '    $e.metadata.event_type = "USER_LOGIN"\n'
        "  match:\n"
        "    $e over 5m\n"
        "  outcome:\n"
        "    $risk = 80\n"
        "  condition:\n"
        "    $e\n"
        "}\n"
    )
    doc = DocumentContext(uri="file://full.yar", text=text, language_mode=LanguageMode.YARA_L)
    assert doc.ast() is not None
    lines = text.split("\n")

    symbols = build_document_symbols(doc, lines)

    rule_sym = next(s for s in symbols if s.name == "full_event")
    child_names = [c.name for c in (rule_sym.children or [])]

    assert "events" in child_names, f"events missing from {child_names}"
    assert "match" in child_names, f"match missing from {child_names}"
    assert "outcome" in child_names, f"outcome missing from {child_names}"
    assert "condition" in child_names


def test_yaral_extra_section_range_starts_at_correct_line() -> None:
    """Extra section symbol range.start.line matches the source position."""
    text = (
        "rule check {\n"
        "  events:\n"
        '    $e.metadata.event_type = "PROCESS_LAUNCH"\n'
        "  condition:\n"
        "    $e\n"
        "}\n"
    )
    doc = DocumentContext(uri="file://check.yar", text=text, language_mode=LanguageMode.YARA_L)
    lines = text.split("\n")

    symbols = build_document_symbols(doc, lines)
    rule_sym = next(s for s in symbols if s.name == "check")
    events_sym = next(c for c in (rule_sym.children or []) if c.name == "events")

    # "  events:" is line 1 (0-indexed)
    assert events_sym.range.start.line == 1


# ---------------------------------------------------------------------------
# Line 580: make_range function body
# ---------------------------------------------------------------------------


def test_make_range_constructs_correct_lsp_range() -> None:
    """Line 580: make_range returns a Range with the exact positions given."""
    result = make_range(2, 4, 5, 11)

    assert result.start.line == 2
    assert result.start.character == 4
    assert result.end.line == 5
    assert result.end.character == 11


def test_make_range_single_line_range() -> None:
    """make_range works when start and end are on the same line."""
    result = make_range(7, 0, 7, 15)

    assert result.start.line == result.end.line == 7
    assert result.start.character == 0
    assert result.end.character == 15


def test_make_range_zero_based_positions() -> None:
    """make_range accepts zero-based line and character positions."""
    result = make_range(0, 0, 0, 0)

    assert result.start.line == 0
    assert result.start.character == 0
    assert result.end.line == 0
    assert result.end.character == 0
