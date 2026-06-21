"""Coverage tests for symbol_tree_builder.py — third pass.

Copyright (c) 2026 Marc Rivero López
Licensed under GPLv3. See LICENSE file for details.
This test suite validates real code behavior without mocks or stubs.

Strategy: the "fallback" branches (lines 52-66, 93-107, 405-419) and the
various negative-line guards (28, 128, 201, 303, 305, 332, 340, 343, 356,
387, 427, 458, 467, 516) are reached by constructing real DocumentContext
objects whose _symbol_index is directly manipulated to introduce the
divergent state that normal parsing never produces.  All objects are real
instances; no mocks are used.

Manipulation pattern used throughout:
    doc._symbol_index._symbols = <list>
    doc._symbol_index._symbols_by_kind = <dict or None>
    doc._symbol_index._symbol_lookup = <dict or None>

Setting _symbols_by_kind / _symbol_lookup to None causes _ensure_indexes
to rebuild them from _symbols, giving fine-grained control over which
records are visible to doc.symbols() vs. doc.get_import_modules() etc.
"""

from __future__ import annotations

from typing import Any, cast

from lsprotocol.types import SymbolKind

from yaraast.ast.rules import Rule
from yaraast.lsp.document_context import DocumentContext
from yaraast.lsp.document_types import SymbolRecord
from yaraast.lsp.symbol_tree_builder import (
    _append_condition_section,
    _append_extra_sections,
    _append_import_symbols,
    _append_include_symbols,
    _append_meta_section,
    _append_strings_section,
    _build_meta_children,
    _build_text_document_symbols,
    build_document_symbols,
    make_range,
)

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _clear_symbol_index(doc: DocumentContext) -> None:
    """Replace the symbol index with an empty, fully-indexed state."""
    doc._symbol_index._symbols = []
    doc._symbol_index._symbols_by_kind = {}
    doc._symbol_index._symbol_lookup = {}


def _set_symbol_index(
    doc: DocumentContext,
    symbols: list[SymbolRecord],
    by_kind: dict[str, list[SymbolRecord]] | None,
    lookup: dict[tuple[str, str, str | None], SymbolRecord] | None,
) -> None:
    """Set the symbol index to an explicit state."""
    doc._symbol_index._symbols = list(symbols)
    doc._symbol_index._symbols_by_kind = by_kind
    doc._symbol_index._symbol_lookup = lookup


# ---------------------------------------------------------------------------
# Lines 52-62: import fallback — find_symbol_record succeeds
# _append_import_symbols: import_records is empty but get_import_modules is non-empty.
# The divergence is created by setting _symbols=[] while keeping _symbols_by_kind
# with an 'import' entry so _unique_symbol_names still returns the module name.
# ---------------------------------------------------------------------------


def test_import_fallback_with_existing_symbol_record() -> None:
    """Lines 52-62: fallback uses find_symbol_record when import_records is empty."""
    text = 'import "pe"\nrule r { condition: true }'
    doc = DocumentContext(uri="file://t.yar", text=text)
    assert doc.ast() is not None
    all_symbols = doc.symbols()
    import_record = next(s for s in all_symbols if s.kind == "import")

    # _symbols is empty so doc.symbols() yields no 'import' records,
    # but _symbols_by_kind keeps 'import' data so get_import_modules returns ['pe'],
    # and _symbol_lookup keeps find_symbol_record working.
    _set_symbol_index(
        doc,
        symbols=[],
        by_kind={"import": [import_record]},
        lookup={("import", "pe", None): import_record},
    )

    symbols: list[Any] = []
    lines = text.split("\n")
    _append_import_symbols(symbols, doc, lines)

    assert len(symbols) == 1
    assert symbols[0].name == 'import "pe"'
    assert symbols[0].kind == SymbolKind.Namespace
    assert symbols[0].range == import_record.range


# ---------------------------------------------------------------------------
# Lines 63-66: import fallback — find_symbol_record returns None, text search used
# Same divergent setup but _symbol_lookup has no entry for pe, so find_symbol_record
# returns None and find_line_containing locates the import in the source text.
# ---------------------------------------------------------------------------


def test_import_fallback_text_search_when_no_symbol_record() -> None:
    """Lines 63-66: fallback falls through to text scan when find_symbol_record is None."""
    text = 'import "pe"\nrule r { condition: true }'
    doc = DocumentContext(uri="file://t.yar", text=text)
    assert doc.ast() is not None
    all_symbols = doc.symbols()
    import_record = next(s for s in all_symbols if s.kind == "import")

    # Empty _symbol_lookup -> find_symbol_record('import','pe') returns None.
    # _symbols_by_kind still has 'import' so get_import_modules returns ['pe'].
    _set_symbol_index(
        doc,
        symbols=[],
        by_kind={"import": [import_record]},
        lookup={},
    )

    symbols: list[Any] = []
    lines = text.split("\n")
    _append_import_symbols(symbols, doc, lines)

    assert len(symbols) == 1
    assert symbols[0].name == 'import "pe"'
    # The range is built from find_line_containing → covers the full line
    assert symbols[0].range.start.line == 0
    assert symbols[0].range.start.character == 0


# ---------------------------------------------------------------------------
# Lines 64->51: import fallback — module not found in text (line_num < 0)
# The module name is in get_import_modules() but find_symbol_record returns None
# AND the module's import directive is absent from the lines being searched.
# ---------------------------------------------------------------------------


def test_import_fallback_skips_module_absent_from_text() -> None:
    """Line 64->51: module not appended when find_line_containing returns -1."""
    text = 'import "pe"\nrule r { condition: true }'
    doc = DocumentContext(uri="file://t.yar", text=text)
    assert doc.ast() is not None
    all_symbols = doc.symbols()
    import_record = next(s for s in all_symbols if s.kind == "import")

    _set_symbol_index(
        doc,
        symbols=[],
        by_kind={"import": [import_record]},
        lookup={},  # find_symbol_record returns None for 'pe'
    )

    symbols: list[Any] = []
    # Lines that do not contain 'import "pe"' → line_num < 0 → 64->51 arc
    lines = ["rule r { condition: true }"]
    _append_import_symbols(symbols, doc, lines)

    assert symbols == []


# ---------------------------------------------------------------------------
# Lines 93-102: include fallback — find_symbol_record succeeds
# Mirrors the import fallback but for 'include' records.
# ---------------------------------------------------------------------------


def test_include_fallback_with_existing_symbol_record() -> None:
    """Lines 93-102: fallback uses find_symbol_record when include_records is empty."""
    text = 'include "utils.yar"\nrule r { condition: true }'
    doc = DocumentContext(uri="file://t.yar", text=text)
    assert doc.ast() is not None
    all_symbols = doc.symbols()
    include_record = next(s for s in all_symbols if s.kind == "include")

    _set_symbol_index(
        doc,
        symbols=[],
        by_kind={"include": [include_record]},
        lookup={("include", "utils.yar", None): include_record},
    )

    symbols: list[Any] = []
    lines = text.split("\n")
    _append_include_symbols(symbols, doc, lines)

    assert len(symbols) == 1
    assert symbols[0].name == 'include "utils.yar"'
    assert symbols[0].kind == SymbolKind.File
    assert symbols[0].range == include_record.range


# ---------------------------------------------------------------------------
# Lines 104-107: include fallback — text search path
# ---------------------------------------------------------------------------


def test_include_fallback_text_search_when_no_symbol_record() -> None:
    """Lines 104-107: include fallback falls through to text scan."""
    text = 'include "utils.yar"\nrule r { condition: true }'
    doc = DocumentContext(uri="file://t.yar", text=text)
    assert doc.ast() is not None
    all_symbols = doc.symbols()
    include_record = next(s for s in all_symbols if s.kind == "include")

    _set_symbol_index(
        doc,
        symbols=[],
        by_kind={"include": [include_record]},
        lookup={},
    )

    symbols: list[Any] = []
    lines = text.split("\n")
    _append_include_symbols(symbols, doc, lines)

    assert len(symbols) == 1
    assert symbols[0].name == 'include "utils.yar"'
    assert symbols[0].range.start.line == 0
    assert symbols[0].range.start.character == 0


# ---------------------------------------------------------------------------
# Lines 105->92: include fallback — path not found in text (line_num < 0)
# ---------------------------------------------------------------------------


def test_include_fallback_skips_path_absent_from_text() -> None:
    """Line 105->92: include not appended when find_line_containing returns -1."""
    text = 'include "utils.yar"\nrule r { condition: true }'
    doc = DocumentContext(uri="file://t.yar", text=text)
    assert doc.ast() is not None
    all_symbols = doc.symbols()
    include_record = next(s for s in all_symbols if s.kind == "include")

    _set_symbol_index(
        doc,
        symbols=[],
        by_kind={"include": [include_record]},
        lookup={},
    )

    symbols: list[Any] = []
    lines = ["rule r { condition: true }"]  # no include directive present
    _append_include_symbols(symbols, doc, lines)

    assert symbols == []


# ---------------------------------------------------------------------------
# Line 28: rule is None guard in build_document_symbols
# A 'rule' SymbolRecord exists in the index for a name that the AST does not
# contain, so get_rule() returns None and the rule is skipped.
# ---------------------------------------------------------------------------


def test_build_document_symbols_skips_rule_when_get_rule_returns_none() -> None:
    """Line 28: rule is None → continue; ghost rule is absent from output."""
    text = "rule real_rule { condition: true }"
    doc = DocumentContext(uri="file://t.yar", text=text)
    assert doc.ast() is not None
    real_symbols = doc.symbols()
    rule_rec = next(s for s in real_symbols if s.kind == "rule")
    block_rec = next(s for s in real_symbols if s.kind == "rule_block")

    ghost_range = make_range(0, 5, 0, 15)
    ghost_rec = SymbolRecord(name="ghost_rule", kind="rule", uri="file://t.yar", range=ghost_range)

    # _symbols has the ghost record; _symbols_by_kind keeps both for get_rule_names()
    # but _symbol_lookup does NOT have ghost_rule, so find_symbol_record returns None
    # for rule_block — and the AST only knows about real_rule.
    _set_symbol_index(
        doc,
        symbols=real_symbols,
        by_kind={"rule": [rule_rec, ghost_rec], "rule_block": [block_rec]},
        lookup={
            ("rule", "real_rule", None): rule_rec,
            ("rule_block", "real_rule", None): block_rec,
        },
    )
    # Override so get_rule_names() returns both names:
    if doc._symbol_index._symbols_by_kind is not None:
        doc._symbol_index._symbols_by_kind["rule"] = [rule_rec, ghost_rec]

    lines = text.split("\n")
    symbols = build_document_symbols(doc, lines)

    rule_names = [s.name for s in symbols]
    assert "ghost_rule" not in rule_names
    assert "real_rule" in rule_names


# ---------------------------------------------------------------------------
# Line 128: rule_line < 0 in _build_rule_symbol
# No SymbolRecord for the rule name AND 'rule absent' not found in lines.
# ---------------------------------------------------------------------------


def test_build_rule_symbol_returns_none_when_rule_line_not_found() -> None:
    """Line 128: _build_rule_symbol returns None when the rule line is absent from text."""
    from yaraast.lsp.symbol_tree_builder import _build_rule_symbol

    text = "rule real_rule { condition: true }"
    doc = DocumentContext(uri="file://t.yar", text=text)
    assert doc.ast() is not None
    real_symbols = doc.symbols()
    rule_rec = next(s for s in real_symbols if s.kind == "rule")
    block_rec = next(s for s in real_symbols if s.kind == "rule_block")

    # Lookup contains only the real rule; 'absent' has no entry.
    _set_symbol_index(
        doc,
        symbols=[rule_rec, block_rec],
        by_kind={"rule": [rule_rec], "rule_block": [block_rec]},
        lookup={
            ("rule", "real_rule", None): rule_rec,
            ("rule_block", "real_rule", None): block_rec,
        },
    )

    absent_rule = Rule(name="absent")
    lines = ["rule real_rule { condition: true }"]  # 'rule absent' not present

    result = _build_rule_symbol(doc, lines, absent_rule, "absent")

    assert result is None


# ---------------------------------------------------------------------------
# Line 189: include text fallback in _build_text_document_symbols
# The document fails to parse, so build uses text-derived symbols.
# An 'include' record in those symbols produces a SymbolKind.File entry.
# ---------------------------------------------------------------------------


def test_text_document_symbols_include_record_produces_file_symbol() -> None:
    """Line 189: truncated doc yields include symbol via text fallback path."""
    text = 'include "utils.yar"\nrule broken { strings: $s = '
    doc = DocumentContext(uri="file://t.yar", text=text)
    assert doc.ast() is None  # parse must fail

    lines = text.split("\n")
    symbols = _build_text_document_symbols(doc, lines)

    include_sym = next((s for s in symbols if "include" in s.name), None)
    assert include_sym is not None
    assert include_sym.kind == SymbolKind.File
    assert include_sym.name == 'include "utils.yar"'


# ---------------------------------------------------------------------------
# Line 201: seen_rules duplicate guard in _build_text_document_symbols
# Two 'rule' records with the same name produce only one symbol.
# ---------------------------------------------------------------------------


def test_text_document_symbols_deduplicates_rule_records() -> None:
    """Line 201: seen_rules set prevents duplicate rule symbols."""
    text = "rule alpha { condition: true }"
    doc = DocumentContext(uri="file://t.yar", text=text)
    assert doc.ast() is not None
    real_symbols = doc.symbols()
    rule_rec = next(s for s in real_symbols if s.kind == "rule")

    # Inject a duplicate 'rule' record for 'alpha'.
    _set_symbol_index(
        doc,
        symbols=[*real_symbols, rule_rec],
        by_kind=None,
        lookup=None,
    )

    lines = text.split("\n")
    symbols = _build_text_document_symbols(doc, lines)

    alpha_count = sum(1 for s in symbols if s.name == "alpha")
    assert alpha_count == 1


# ---------------------------------------------------------------------------
# Lines 303, 305->exit: meta_line < 0 causes early return in _append_meta_section
# ---------------------------------------------------------------------------


def test_append_meta_section_returns_early_when_meta_line_not_found() -> None:
    """Line 303: early return when meta_line < 0 (no 'meta:' in lines)."""
    text = "rule myrule { condition: true }"
    doc = DocumentContext(uri="file://t.yar", text=text)
    assert doc.ast() is not None
    _clear_symbol_index(doc)

    rule = Rule(name="myrule", meta={"author": "test"})
    lines = ["rule myrule {", "  condition:", "    true", "}"]  # no 'meta:'
    children: list[Any] = []

    _append_meta_section(children, doc, lines, rule, "myrule", 0, set())

    assert children == []


def test_append_meta_section_no_append_when_meta_children_empty() -> None:
    """Line 305->exit: meta_line >= 0 but _build_meta_children returns empty list."""
    text = "rule myrule { condition: true }"
    doc = DocumentContext(uri="file://t.yar", text=text)
    assert doc.ast() is not None
    _clear_symbol_index(doc)

    rule = Rule(name="myrule")  # rule has no meta entries
    # Lines contain 'meta:' so meta_line >= 0, but no meta items exist.
    lines = ["rule myrule {", "  meta:", "  condition:", "    true", "}"]
    children: list[Any] = []

    _append_meta_section(children, doc, lines, rule, "myrule", 0, {"meta"})

    assert children == []


# ---------------------------------------------------------------------------
# Line 332: hasattr(rule.meta, 'entries') fallback in _build_meta_children
# get_rule_meta_items returns [] and rule.meta has an 'entries' attribute.
# ---------------------------------------------------------------------------


def test_build_meta_children_uses_entries_attribute_fallback() -> None:
    """Line 332: entries-attribute path used when meta_items is empty.

    To reach line 332, get_rule_meta_items must return [] AND rule.meta must have
    an 'entries' attribute.  get_rule_meta_items returns [] when get_rule() returns
    None (rule name not in AST) and text parsing also finds no meta.  Using a rule
    name absent from the document AST satisfies both conditions.
    """

    class _Entry:
        def __init__(self, key: str, value: str) -> None:
            self.key = key
            self.value = value

    class _FakeMeta:
        entries = [_Entry("author", "bob")]

    class _FakeRule:
        name = "phantom"  # not in the document's AST
        meta: Any = _FakeMeta()
        strings: Any = None
        condition: Any = None

    # The document only knows rule 'myrule'; 'phantom' is absent from the AST.
    text = "rule myrule { condition: true }"
    doc = DocumentContext(uri="file://t.yar", text=text)
    assert doc.ast() is not None
    _clear_symbol_index(doc)

    # Lines that include 'author =' so key_line will be found (lines 344-347 path).
    lines = ["rule phantom {", "  meta:", '    author = "bob"', "  condition:", "    true", "}"]
    children = _build_meta_children(doc, lines, _FakeRule(), "phantom", 1)

    assert len(children) == 1
    assert "author" in children[0].name
    assert "bob" in children[0].name


# ---------------------------------------------------------------------------
# Lines 340->342, 343: meta_records_by_name lookup miss in _build_meta_children
# meta_items has an entry but there are no matching SymbolRecords,
# so selected_meta_record falls back to find_symbol_record (also None here).
# The text 'author =' is found in lines so a range is built.
# ---------------------------------------------------------------------------


def test_build_meta_children_uses_text_search_when_no_meta_records() -> None:
    """Lines 340-343: meta children built via text search when symbol records are absent."""
    text = 'rule myrule {\n  meta:\n    author = "test"\n  condition:\n    true\n}'
    doc = DocumentContext(uri="file://t.yar", text=text)
    assert doc.ast() is not None
    # Clear index: no 'meta' symbol records visible; get_rule_meta_items uses the AST rule.
    _clear_symbol_index(doc)

    rule = Rule(name="myrule", meta={"author": "test"})
    lines = text.split("\n")

    children = _build_meta_children(doc, lines, rule, "myrule", 1)

    assert len(children) == 1
    assert "author" in children[0].name
    assert children[0].range.start.line == 2


# ---------------------------------------------------------------------------
# Line 356->337: key_line < 0 in _build_meta_children — key missing from text
# ---------------------------------------------------------------------------


def test_build_meta_children_skips_key_not_found_in_lines() -> None:
    """Line 356->337: key_line < 0 causes the entry to be skipped entirely.

    To reach the 356->337 arc, meta_items must be non-empty so the loop body
    executes, but the key must be absent from the source lines.  The easiest
    path is via line 332 (entries-attribute fallback), which populates
    meta_items from an object whose matching key is not present in lines.
    """

    class _Entry:
        key = "phantom_key"
        value = "phantom_value"

    class _FakeMeta:
        entries = [_Entry()]  # triggers line-332 path; key absent from lines

    class _FakeRule:
        name = "phantom"  # not in AST → get_rule_meta_items returns []
        meta: Any = _FakeMeta()
        strings: Any = None
        condition: Any = None

    text = "rule myrule { condition: true }"
    doc = DocumentContext(uri="file://t.yar", text=text)
    assert doc.ast() is not None
    _clear_symbol_index(doc)

    # 'phantom_key =' is absent → find_line_containing returns -1 → 356->337.
    lines = ["rule phantom {", "  meta:", "  condition:", "    true", "}"]

    children = _build_meta_children(doc, lines, _FakeRule(), "phantom", 1)

    assert children == []


# ---------------------------------------------------------------------------
# Line 387: strings_line < 0 in _append_strings_section
# 'strings' is in section_names but 'strings:' does not appear in lines.
# ---------------------------------------------------------------------------


def test_append_strings_section_returns_early_when_strings_line_not_found() -> None:
    """Line 387: early return when strings_line < 0."""
    text = "rule myrule { condition: true }"
    doc = DocumentContext(uri="file://t.yar", text=text)
    assert doc.ast() is not None
    _clear_symbol_index(doc)

    rule = Rule(name="myrule")
    lines = ["rule myrule {", "  condition:", "    true", "}"]  # no 'strings:'
    children: list[Any] = []

    _append_strings_section(children, doc, lines, rule, "myrule", 0, {"strings"})

    assert children == []


# ---------------------------------------------------------------------------
# Lines 405-419: string identifier fallback
# 'string' SymbolRecords are absent but get_rule_string_identifiers returns
# identifiers (via the intact AST), so the fallback branch iterates them.
# ---------------------------------------------------------------------------


def test_append_strings_section_fallback_uses_identifier_list() -> None:
    """Lines 405-419: string children built from identifier list when no string records."""
    text = 'rule myrule {\n  strings:\n    $s = "hello"\n  condition:\n    $s\n}'
    doc = DocumentContext(uri="file://t.yar", text=text)
    assert doc.ast() is not None
    real_symbols = doc.symbols()
    # Keep only section records for strings so strings_section_record is found,
    # but remove the 'string' kind record to force the fallback path.
    section_records = [
        s for s in real_symbols if s.kind in ("section", "section_header") and s.name == "strings"
    ]
    _set_symbol_index(doc, symbols=section_records, by_kind=None, lookup=None)

    rule = doc.get_rule("myrule")
    assert rule is not None

    lines = text.split("\n")
    children: list[Any] = []
    _append_strings_section(children, doc, lines, rule, "myrule", 0, {"strings"})

    assert len(children) == 1
    assert children[0].name == "strings"
    string_children = children[0].children or []
    assert any("$s" in c.name for c in string_children)


def test_append_strings_section_fallback_skips_string_not_in_lines() -> None:
    """Lines 412-417: string_line < 0 inside fallback; entry is omitted."""
    text = 'rule myrule {\n  strings:\n    $s = "hello"\n  condition:\n    $s\n}'
    doc = DocumentContext(uri="file://t.yar", text=text)
    assert doc.ast() is not None
    real_symbols = doc.symbols()
    section_records = [
        s for s in real_symbols if s.kind in ("section", "section_header") and s.name == "strings"
    ]
    _set_symbol_index(doc, symbols=section_records, by_kind=None, lookup=None)

    rule = doc.get_rule("myrule")
    assert rule is not None

    # Lines do not contain '$s' so string_line < 0 for that identifier.
    lines = ["rule myrule {", "  strings:", "  condition:", "    true", "}"]
    children: list[Any] = []
    _append_strings_section(children, doc, lines, rule, "myrule", 0, {"strings"})

    # strings section not appended because no string_children were added.
    assert children == []


# ---------------------------------------------------------------------------
# Line 427->exit: string_children empty; strings section not appended
# ---------------------------------------------------------------------------


def test_append_strings_section_no_append_when_string_children_empty() -> None:
    """Line 427->exit: strings section skipped when string_children is empty."""
    text = "rule myrule { condition: true }"
    doc = DocumentContext(uri="file://t.yar", text=text)
    assert doc.ast() is not None
    _clear_symbol_index(doc)

    rule = Rule(name="myrule")  # no strings
    lines = ["rule myrule {", "  strings:", "  condition:", "    true", "}"]
    children: list[Any] = []
    _append_strings_section(children, doc, lines, rule, "myrule", 0, {"strings"})

    assert children == []


# ---------------------------------------------------------------------------
# Line 458: condition early return in _append_condition_section
# ---------------------------------------------------------------------------


def test_append_condition_section_returns_early_when_no_condition_indicator() -> None:
    """Line 458: early return when 'condition' absent from section_names and rule.condition is None.

    Line 457 evaluates: 'condition' not in section_names AND not rule.condition.
    Both must be True to hit the return at line 458.
    """
    text = "rule myrule { condition: true }"
    doc = DocumentContext(uri="file://t.yar", text=text)
    assert doc.ast() is not None
    _clear_symbol_index(doc)

    rule = Rule(name="myrule")  # condition field is None by default
    lines = ["rule myrule { condition: true }"]
    children: list[Any] = []

    # section_names is empty AND rule.condition is None → line 458 early return.
    _append_condition_section(children, doc, lines, rule, "myrule", 0, 0, set())

    assert children == []


def test_append_condition_section_returns_early_when_condition_line_not_found() -> None:
    """Line 466-467: early return when condition_line < 0 (keyword missing from lines)."""
    text = "rule myrule { condition: true }"
    doc = DocumentContext(uri="file://t.yar", text=text)
    assert doc.ast() is not None
    _clear_symbol_index(doc)

    rule = Rule(name="myrule")
    lines = ["rule myrule {", "    true", "}"]  # no 'condition:'
    children: list[Any] = []

    _append_condition_section(children, doc, lines, rule, "myrule", 0, 2, {"condition"})

    assert children == []


# ---------------------------------------------------------------------------
# Line 467: condition make_range fallback (no section_record, no header_record)
# ---------------------------------------------------------------------------


def test_append_condition_section_uses_make_range_fallback() -> None:
    """Line 467: range and selection_range built via make_range when no section records."""
    text = "rule myrule { condition: true }"
    doc = DocumentContext(uri="file://t.yar", text=text)
    assert doc.ast() is not None
    _clear_symbol_index(doc)

    rule = Rule(name="myrule")
    lines = ["rule myrule {", "  condition: true", "}"]
    children: list[Any] = []

    _append_condition_section(children, doc, lines, rule, "myrule", 0, 2, {"condition"})

    assert len(children) == 1
    cond = children[0]
    assert cond.name == "condition"
    # range spans from condition_line (1) to rule_end (2)
    assert cond.range.start.line == 1
    assert cond.range.end.line == 2
    # selection_range is on the condition_line only
    assert cond.selection_range.start.line == 1
    assert cond.selection_range.end.line == 1


# ---------------------------------------------------------------------------
# Line 516->498: section_line < 0 in _append_extra_sections
# The rule attribute is truthy but the section keyword is absent from the lines.
# ---------------------------------------------------------------------------


def test_append_extra_sections_skips_section_absent_from_lines() -> None:
    """Line 516->498: section not appended when section_line < 0."""
    text = "rule myrule { condition: true }"
    doc = DocumentContext(uri="file://t.yar", text=text)
    assert doc.ast() is not None
    _clear_symbol_index(doc)

    class _FakeRuleWithEvents:
        name = "myrule"
        events: Any = "something"  # truthy: events section is expected
        match: Any = None
        outcome: Any = None
        options: Any = None
        meta: list[Any] = []
        strings: list[Any] = []
        condition: Any = True

    lines = ["rule myrule {", "  condition: true", "}"]  # no 'events:' present
    children: list[Any] = []

    _append_extra_sections(
        children, doc, lines, cast(Rule, _FakeRuleWithEvents()), "myrule", 0, set()
    )

    assert children == []


# ---------------------------------------------------------------------------
# Line 30->25: rule_symbol is None (from _build_rule_symbol) — for-loop continues
# rule is present in the AST (get_rule returns it) but rule_line cannot be found
# in lines AND no SymbolRecord exists, so _build_rule_symbol returns None.
# ---------------------------------------------------------------------------


def test_build_document_symbols_skips_rule_when_build_rule_symbol_returns_none() -> None:
    """Line 30->25: rule_symbol is None → continue; the rule is absent from output."""
    text = "rule myrule { condition: true }"
    doc = DocumentContext(uri="file://t.yar", text=text)
    assert doc.ast() is not None
    slist = doc.symbols()
    rule_rec = next(s for s in slist if s.kind == "rule")

    # get_rule_names returns ['myrule'] (via _symbols_by_kind),
    # get_rule('myrule') returns the real AST rule (not None, so line 28 is not taken),
    # but _symbol_lookup is empty so find_symbol_record('rule','myrule') returns None,
    # and 'rule myrule' is not in the lines so find_line_containing returns -1
    # → _build_rule_symbol returns None → line 30->25 arc is exercised.
    _set_symbol_index(
        doc,
        symbols=[],
        by_kind={"rule": [rule_rec]},
        lookup={},
    )

    # Lines without 'rule myrule' so find_line_containing fails.
    lines = ["  condition: true }"]
    symbols = build_document_symbols(doc, lines)

    assert symbols == []


# ---------------------------------------------------------------------------
# Lines 409-410: string identifier fallback — found_string_record is not None
# When the 'string' kind is absent from doc.symbols() but find_symbol_record
# succeeds via _symbol_lookup, lines 409-410 are taken.
# ---------------------------------------------------------------------------


def test_append_strings_section_fallback_uses_found_string_record() -> None:
    """Lines 409-410: found_string_record is not None inside the identifier fallback."""
    text = 'rule myrule {\n  strings:\n    $s = "hello"\n  condition:\n    $s\n}'
    doc = DocumentContext(uri="file://t.yar", text=text)
    assert doc.ast() is not None
    slist = doc.symbols()

    strings_sec = next(s for s in slist if s.kind == "section" and s.name == "strings")
    strings_hdr = next(s for s in slist if s.kind == "section_header" and s.name == "strings")
    str_rec = next(s for s in slist if s.kind == "string")

    # _symbols contains only section records → doc.symbols() has no 'string' kind,
    # so string_records (line 389-393) is empty → fallback branch at 405 is taken.
    # _symbol_lookup has the 'string' record → find_symbol_record returns it →
    # lines 409-410 (found_string_record is not None branch) are executed.
    _set_symbol_index(
        doc,
        symbols=[strings_sec, strings_hdr],
        by_kind={"section": [strings_sec], "section_header": [strings_hdr]},
        lookup={
            ("section", "strings", "myrule"): strings_sec,
            ("section_header", "strings", "myrule"): strings_hdr,
            ("string", "$s", "myrule"): str_rec,
        },
    )

    rule = doc.get_rule("myrule")
    assert rule is not None

    lines = text.split("\n")
    children: list[Any] = []
    _append_strings_section(children, doc, lines, rule, "myrule", 0, {"strings"})

    assert len(children) == 1
    string_children = children[0].children or []
    assert any(c.name == "$s" for c in string_children)
    # Range comes from the actual SymbolRecord (found_string_record.range).
    s_child = next(c for c in string_children if c.name == "$s")
    assert s_child.range == str_rec.range


# ---------------------------------------------------------------------------
# Combined: lines 28+30->25 via build_document_symbols
# A ghost rule name is in get_rule_names() but get_rule() returns None for it;
# real_rule still produces its symbol.
# ---------------------------------------------------------------------------


def test_build_document_symbols_rule_none_then_rule_symbol_none_skipped() -> None:
    """Lines 28 and 30->25: ghost rule skipped; only real rule is emitted."""
    text = "rule real_rule { condition: true }"
    doc = DocumentContext(uri="file://t.yar", text=text)
    assert doc.ast() is not None
    real_symbols = doc.symbols()
    rule_rec = next(s for s in real_symbols if s.kind == "rule")
    block_rec = next(s for s in real_symbols if s.kind == "rule_block")
    cond_recs = [s for s in real_symbols if s.kind in ("section", "section_header", "condition")]

    ghost_range = make_range(0, 5, 0, 15)
    ghost_rec = SymbolRecord(name="ghost_rule", kind="rule", uri="file://t.yar", range=ghost_range)

    # The ghost has a 'rule' record (so get_rule_names includes it) but no AST rule node.
    lookup: dict[tuple[str, str, str | None], SymbolRecord] = {
        ("rule", "real_rule", None): rule_rec,
        ("rule_block", "real_rule", None): block_rec,
    }
    for rec in cond_recs:
        lookup[(rec.kind, rec.name, rec.container_name)] = rec

    _set_symbol_index(
        doc,
        symbols=[rule_rec, block_rec, *cond_recs],
        by_kind={"rule": [rule_rec, ghost_rec], "rule_block": [block_rec]},
        lookup=lookup,
    )

    lines = text.split("\n")
    symbols = build_document_symbols(doc, lines)

    names = [s.name for s in symbols]
    assert "real_rule" in names
    assert "ghost_rule" not in names
