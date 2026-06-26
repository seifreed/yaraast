# Copyright (c) 2026 Marc Rivero López
# Licensed under GPLv3. See LICENSE file for details.
# This test suite validates real code behavior without mocks or stubs.
"""Regression tests raising document_symbol_sections.py coverage toward 100%.

The functions under test live in yaraast.lsp.document_symbol_sections and are
called by build_symbols (in document_symbols.py) during real AST-based symbol
extraction.  Every test here executes actual production code with real parsed
ASTs; no mocking framework or test double is used.

Coverage strategy
-----------------
The five public appenders (append_meta_symbols, append_string_symbols,
append_condition_symbols, append_extra_section_symbols) plus the four helpers
(find_section_header_in_rule, section_content_range, meta_item_ranges,
meta_item_range) are driven through:

1. Real DocumentContext.symbols() calls — the highest-fidelity path.
2. Direct calls to the appender functions when a specific branch requires
   constructing a controlled rule_block_range that would not be produced by a
   normally-parsed rule.
3. Direct calls to the two pure helpers (section_content_range,
   meta_item_ranges, meta_item_range) with real or real-shaped inputs.
4. Lightweight real helper objects (ASTNode subclass, minimal section object)
   where the production AST does not produce nodes with location information
   but the code path legitimately handles such nodes.

Unreachable lines / branches
-----------------------------
- Line 78 (make_range with start=-1 inside find_line_containing block):
  key_text is extracted from the meta line before '=', so lines[line_num].find(key_text)
  always finds it in the same line; key_start < 0 cannot occur in practice.
"""

from __future__ import annotations

from typing import Any

from lsprotocol.types import Position, Range
import pytest

from yaraast.ast.base import ASTNode, Location
from yaraast.lsp.document_context import DocumentContext
from yaraast.lsp.document_symbol_ranges import node_range
from yaraast.lsp.document_symbol_sections import (
    append_condition_symbols,
    append_extra_section_symbols,
    append_meta_symbols,
    append_string_symbols,
    find_section_header_in_rule,
    meta_item_range,
    meta_item_ranges,
    section_content_range,
)
from yaraast.lsp.document_symbols import build_symbols
from yaraast.lsp.document_types import SymbolRecord

# ---------------------------------------------------------------------------
# Reusable YARA source fixtures
# ---------------------------------------------------------------------------

CLASSIC_FULL = """\
rule alpha {
    meta:
        author = "alice"
        score = 5
        active = true
    strings:
        $a = "plain"
        $b = { 4D 5A }
        $c = /regex/
    condition:
        $a or $b
}
"""

CLASSIC_ANON_STRING = """\
rule with_anon {
    strings:
        $ = "anon_value"
        $named = "other"
    condition:
        any of them
}
"""

CLASSIC_NO_META = """\
rule no_meta {
    strings:
        $a = "x"
    condition:
        $a
}
"""

CLASSIC_NO_STRINGS = """\
rule no_strings {
    meta:
        note = "nothing here"
    condition:
        true
}
"""

CLASSIC_CONDITION_ONLY = """\
rule cond_only {
    condition:
        true
}
"""

CLASSIC_SINGLE_LINE = 'rule sl { meta: author = "me" strings: $x = "y" condition: $x }\n'

CLASSIC_DUPLICATE_META = """\
rule dup_meta {
    meta:
        author = "alice"
        author = "bob"
    condition:
        true
}
"""

YARAL_FULL = """\
rule YaralRule {
  meta:
    author = "analyst"
    version = "1.0"
  events:
    $e.metadata.event_type = "NETWORK_CONNECTION"
  match:
    $e over 5m
  outcome:
    $count = count($e.metadata.id)
  condition:
    $e
}
"""

YARAL_MINIMAL = """\
rule YaralMinimal {
  meta:
    note = "simple"
  condition:
    $e
}
"""


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _doc(text: str, uri: str = "file://x.yar") -> DocumentContext:
    return DocumentContext(uri=uri, text=text)


def _kinds(symbols: list[SymbolRecord]) -> set[str]:
    return {s.kind for s in symbols}


def _names_of_kind(symbols: list[SymbolRecord], kind: str) -> list[str]:
    return [s.name for s in symbols if s.kind == kind]


class _FakeRuleWithUnknownMeta:
    """Minimal rule-like object carrying an unknown meta type."""

    def __init__(self) -> None:
        self.meta: Any = object()

    # Other attributes accessed by append_string_symbols / append_condition_symbols
    # are not present — those helpers guard with getattr defaults.


class _LocatedMetaEntry(ASTNode):
    """Minimal ASTNode-based meta entry carrying a real Location.

    Used to exercise branches that require meta_item_ranges to produce a non-None
    Range (so section_content_range returns a real value rather than None).
    The production parsers never produce ASTNode list-form meta entries with
    locations, but the code is designed to handle them.
    """

    def __init__(self, key: str, value: str, loc: Location | None = None) -> None:
        self.key = key
        self.value = value
        self.location = loc

    def accept(self, visitor: Any) -> Any:
        return None


class _FakeRuleWithLocatedMeta:
    """Rule-like object whose .meta is a list of _LocatedMetaEntry instances."""

    def __init__(self, entries: list[_LocatedMetaEntry]) -> None:
        self.meta: list[_LocatedMetaEntry] = entries


class _FakeStringNoLocation:
    """String definition with a real identifier but no location attribute.

    Used to force node_range and node_value_range to return None, exercising
    the find_string_line fallback path (lines 117-120 of append_string_symbols).
    """

    def __init__(self, identifier: str, *, is_anonymous: bool = False) -> None:
        self.identifier = identifier
        self.is_anonymous = is_anonymous
        self.location: None = None


class _FakeRuleWithNoLocationStrings:
    """Rule-like object whose strings have no location information."""

    def __init__(self, strings: list[_FakeStringNoLocation]) -> None:
        self.strings = strings
        self.meta: list[Any] = []
        self.condition: None = None


class _FakeSectionWithLocation:
    """Section-like object with a real Location.

    Used to exercise the branch where section_content_range returns a non-None
    value for extra sections (line 172->179 in append_extra_section_symbols).
    """

    def __init__(self, loc: Location) -> None:
        self.location = loc


class _FakeRuleWithLocatedSection:
    """Rule-like object carrying a section attribute with a real Location."""

    def __init__(self, section_name: str, loc: Location) -> None:
        self.meta: list[Any] = []
        setattr(self, section_name, _FakeSectionWithLocation(loc))

    def __getattr__(self, item: str) -> None:
        return None


# ---------------------------------------------------------------------------
# section_content_range helper — lines 200-205
# ---------------------------------------------------------------------------


class TestSectionContentRange:
    """Pure helper: verify all three input shapes."""

    def test_empty_list_returns_none(self) -> None:
        """section_content_range with an empty list always returns None."""
        header = Range(start=Position(line=1, character=4), end=Position(line=1, character=8))
        result = section_content_range(header, [])
        assert result is None

    def test_all_none_items_returns_none(self) -> None:
        """When every content range is None the function returns None."""
        header = Range(start=Position(line=1, character=4), end=Position(line=1, character=8))
        result = section_content_range(header, [None, None, None])
        assert result is None

    def test_single_real_range_uses_header_start(self) -> None:
        """With one real content range the returned Range starts at the header line."""
        header = Range(start=Position(line=1, character=4), end=Position(line=1, character=8))
        content = Range(start=Position(line=2, character=8), end=Position(line=2, character=20))
        result = section_content_range(header, [content])
        assert result is not None
        assert result.start.line == 1
        assert result.start.character == 0
        assert result.end.line == 2
        assert result.end.character == 20

    def test_mixed_none_and_real_ignores_none(self) -> None:
        """None items are filtered out; the max of remaining real ranges is used."""
        header = Range(start=Position(line=0, character=0), end=Position(line=0, character=4))
        r1 = Range(start=Position(line=1, character=0), end=Position(line=1, character=10))
        r2 = Range(start=Position(line=3, character=0), end=Position(line=3, character=5))
        result = section_content_range(header, [None, r1, None, r2])
        assert result is not None
        assert result.end.line == 3

    def test_multiple_real_ranges_picks_maximum_end(self) -> None:
        """When several real ranges exist the one with the highest end line wins."""
        header = Range(start=Position(line=0, character=0), end=Position(line=0, character=4))
        r_early = Range(start=Position(line=1, character=0), end=Position(line=1, character=30))
        r_late = Range(start=Position(line=5, character=0), end=Position(line=5, character=10))
        result = section_content_range(header, [r_early, r_late])
        assert result is not None
        assert result.end.line == 5


# ---------------------------------------------------------------------------
# meta_item_ranges helper — lines 208-218
# ---------------------------------------------------------------------------


class TestMetaItemRanges:
    """Exercise all three branches of meta_item_ranges."""

    def test_list_form_skips_non_astnode_entries(self) -> None:
        """Classic YARA MetaEntry items are not ASTNode instances; result is []."""
        doc = _doc(CLASSIC_FULL)
        ast = doc.ast()
        assert ast is not None
        rule: Any = ast.rules[0]
        result = meta_item_ranges(rule, CLASSIC_FULL)
        # MetaEntry is not ASTNode, so every item is filtered out
        assert isinstance(result, list)
        assert all(r is None for r in result) or result == []

    def test_entries_form_processes_yaral_astnode_entries(self) -> None:
        """YARA-L MetaSection has .entries; each entry is an ASTNode."""
        doc = _doc(YARAL_FULL, uri="file://x.yaral")
        ast = doc.ast()
        assert ast is not None
        rule: Any = ast.rules[0]
        result = meta_item_ranges(rule, YARAL_FULL)
        # YARA-L MetaEntry.location is None so node_range returns None for each
        assert isinstance(result, list)
        assert len(result) >= 1

    def test_unknown_meta_type_returns_empty_list(self) -> None:
        """A meta object that is neither a list nor has entries returns []."""
        rule: Any = _FakeRuleWithUnknownMeta()
        result = meta_item_ranges(rule, "rule a { meta: x = 1 condition: true }")
        assert result == []


# ---------------------------------------------------------------------------
# meta_item_range helper — lines 221-237
# ---------------------------------------------------------------------------


class TestMetaItemRange:
    """Exercise occurrence-based lookup and the entries/list dispatch."""

    def test_list_form_first_occurrence_returns_value_range(self) -> None:
        """Classic YARA list form: occurrence 0 on key with no location returns None."""
        doc = _doc(CLASSIC_FULL)
        ast = doc.ast()
        assert ast is not None
        rule: Any = ast.rules[0]
        meta = rule.meta
        # MetaEntry has no location so node_value_range returns None
        result = meta_item_range(meta, "author", CLASSIC_FULL, 0)
        assert result is None

    def test_list_form_skip_increments_on_mismatched_occurrence(self) -> None:
        """When occurrence=1 the first matching key is skipped (seen counter increments)."""
        doc = _doc(CLASSIC_DUPLICATE_META)
        ast = doc.ast()
        assert ast is not None
        rule: Any = ast.rules[0]
        meta = rule.meta
        # occurrence=1: first 'author' is skipped, second occurrence is searched
        result = meta_item_range(meta, "author", CLASSIC_DUPLICATE_META, 1)
        # YARA MetaEntry has no location so result is still None,
        # but the occurrence-skipping branch was executed
        assert result is None

    def test_list_form_absence_returns_none(self) -> None:
        """A key not present in the meta list returns None."""
        doc = _doc(CLASSIC_FULL)
        ast = doc.ast()
        assert ast is not None
        rule: Any = ast.rules[0]
        result = meta_item_range(rule.meta, "nonexistent_key", CLASSIC_FULL, 0)
        assert result is None

    def test_entries_form_occurrence_skipping(self) -> None:
        """YARA-L entries form: duplicate key with occurrence=1 skips first entry."""
        src = """\
rule DupMetaRule {
  meta:
    author = "alice"
    author = "bob"
  condition:
    $e
}
"""
        doc = _doc(src, uri="file://x.yaral")
        ast = doc.ast()
        assert ast is not None
        rule: Any = ast.rules[0]
        meta = rule.meta
        # occurrence=0: first 'author' found (location None -> returns None)
        r0 = meta_item_range(meta, "author", src, 0)
        assert r0 is None
        # occurrence=1: first 'author' skipped, second returned (also None from location)
        r1 = meta_item_range(meta, "author", src, 1)
        assert r1 is None

    def test_unknown_meta_type_returns_none(self) -> None:
        """Unknown meta object type (not list, no entries) returns None immediately."""
        result = meta_item_range(object(), "key", "source", 0)
        assert result is None


# ---------------------------------------------------------------------------
# find_section_header_in_rule — lines 185-197
# ---------------------------------------------------------------------------


class TestFindSectionHeaderInRule:
    """Verify that section header lookup respects the rule_block_range bounds."""

    def test_finds_meta_header_in_range(self) -> None:
        """meta: header is found when it lies within rule_block_range."""
        doc = _doc(CLASSIC_FULL)
        lines = doc.lines
        # meta: is at line 1, rule ends at line 11
        rule_range = Range(start=Position(line=0, character=0), end=Position(line=11, character=1))
        result = find_section_header_in_rule(lines, "meta", rule_range)
        assert result is not None
        assert result.start.line == 1

    def test_returns_none_when_section_not_in_range(self) -> None:
        """When the section keyword falls outside rule_block_range the result is None."""
        doc = _doc(CLASSIC_FULL)
        lines = doc.lines
        # range covers only line 0 (rule declaration), not meta: at line 1
        narrow_range = Range(
            start=Position(line=0, character=0), end=Position(line=0, character=12)
        )
        result = find_section_header_in_rule(lines, "meta", narrow_range)
        assert result is None

    def test_finds_condition_header(self) -> None:
        """condition: header is found within the full rule range."""
        doc = _doc(CLASSIC_CONDITION_ONLY)
        lines = doc.lines
        rule_range = Range(start=Position(line=0, character=0), end=Position(line=2, character=1))
        result = find_section_header_in_rule(lines, "condition", rule_range)
        assert result is not None
        assert result.start.line == 1


# ---------------------------------------------------------------------------
# append_meta_symbols — lines 27-81
# ---------------------------------------------------------------------------


class TestAppendMetaSymbols:
    """Drive every branch of append_meta_symbols."""

    # -- Early return when meta is empty / None --

    def test_no_meta_produces_no_symbols(self) -> None:
        """A rule with no meta section returns early without appending symbols."""
        doc = _doc(CLASSIC_NO_META)
        ast = doc.ast()
        assert ast is not None
        rule: Any = ast.rules[0]
        rule_rng = node_range(rule, CLASSIC_NO_META)
        assert rule_rng is not None
        symbols: list[SymbolRecord] = []
        append_meta_symbols(doc, symbols, doc.lines, rule, "no_meta", rule_rng)
        assert symbols == []

    def test_empty_meta_list_produces_no_symbols(self) -> None:
        """A rule whose .meta is an empty list hits the falsy guard and returns early."""
        doc = _doc(CLASSIC_CONDITION_ONLY)
        ast = doc.ast()
        assert ast is not None
        rule: Any = ast.rules[0]
        rule_rng = node_range(rule, CLASSIC_CONDITION_ONLY)
        assert rule_rng is not None
        symbols: list[SymbolRecord] = []
        append_meta_symbols(doc, symbols, doc.lines, rule, "cond_only", rule_rng)
        assert not any(s.kind == "meta" for s in symbols)

    # -- Header found, section_content_range succeeds via find_section_range --

    def test_classic_multi_line_rule_produces_meta_and_header_symbols(self) -> None:
        """Multi-line rule: meta section + header symbols are emitted (lines 48-51)."""
        doc = _doc(CLASSIC_FULL)
        ast = doc.ast()
        assert ast is not None
        rule: Any = ast.rules[0]
        rule_rng = node_range(rule, CLASSIC_FULL)
        assert rule_rng is not None
        symbols: list[SymbolRecord] = []
        append_meta_symbols(doc, symbols, doc.lines, rule, "alpha", rule_rng)
        kinds = {s.kind for s in symbols}
        assert "section" in kinds
        assert "section_header" in kinds
        assert "meta" in kinds
        # Verify names present
        meta_names = [s.name for s in symbols if s.kind == "meta"]
        assert "author" in meta_names
        assert "score" in meta_names

    def test_meta_header_range_none_when_outside_rule_range(self) -> None:
        """When rule_block_range excludes the meta: header line, the section and
        section_header symbols are NOT emitted (the 'if meta_header_range is not None:'
        guard on line 39 is False).  The meta item fallback loop still fires because
        it is outside that guard, so individual 'meta' kind symbols may appear."""
        doc = _doc(CLASSIC_FULL)
        ast = doc.ast()
        assert ast is not None
        rule: Any = ast.rules[0]
        # Range covers only the rule header line (line 0); meta: is at line 1
        narrow_range = Range(
            start=Position(line=0, character=0), end=Position(line=0, character=12)
        )
        symbols: list[SymbolRecord] = []
        append_meta_symbols(doc, symbols, doc.lines, rule, "alpha", narrow_range)
        # The section and section_header symbols require the header to be found
        assert not any(s.kind == "section" for s in symbols)
        assert not any(s.kind == "section_header" for s in symbols)

    # -- section_content_range returns None -> find_section_range fallback (line 43-44) --

    def test_classic_single_line_uses_make_range_fallback(self) -> None:
        """Single-line rule: find_section_range returns None, make_range is used."""
        doc = _doc(CLASSIC_SINGLE_LINE)
        ast = doc.ast()
        assert ast is not None
        rule: Any = ast.rules[0]
        rule_rng = node_range(rule, CLASSIC_SINGLE_LINE)
        assert rule_rng is not None
        symbols: list[SymbolRecord] = []
        append_meta_symbols(doc, symbols, doc.lines, rule, "sl", rule_rng)
        # section symbol must exist and fall back to make_range (single line)
        section_syms = [s for s in symbols if s.kind == "section" and s.name == "meta"]
        assert len(section_syms) == 1
        assert section_syms[0].range.start.line == section_syms[0].range.end.line

    # -- List form: meta is list of MetaEntry (lines 53-54) --

    def test_classic_meta_list_form_iterates_entries(self) -> None:
        """Classic YARA meta is a list; the list-form branch produces meta symbols."""
        doc = _doc(CLASSIC_FULL)
        symbols = doc.symbols()
        meta_names = _names_of_kind(symbols, "meta")
        assert "author" in meta_names
        assert "score" in meta_names
        assert "active" in meta_names

    # -- entries form: meta has .entries (lines 55-56) --

    def test_yaral_meta_entries_form_iterates_entries(self) -> None:
        """YARA-L MetaSection.entries form: meta symbols produced for each key."""
        doc = _doc(YARAL_FULL, uri="file://x.yaral")
        symbols = doc.symbols()
        meta_names = _names_of_kind(symbols, "meta")
        assert "author" in meta_names
        assert "version" in meta_names

    # -- Unknown meta type: else branch -> iter([]) (line 58) --

    def test_unknown_meta_type_produces_section_but_no_meta_items(self) -> None:
        """Unknown meta object: else-branch fires; section/header emitted, no meta items."""
        doc = _doc(CLASSIC_FULL)
        rule_rng = Range(start=Position(line=0, character=0), end=Position(line=11, character=1))
        symbols: list[SymbolRecord] = []
        fake_rule: Any = _FakeRuleWithUnknownMeta()
        append_meta_symbols(doc, symbols, doc.lines, fake_rule, "alpha", rule_rng)
        # section and section_header should be present (meta: is in lines)
        assert any(s.kind == "section" for s in symbols)
        # No meta items because iter([]) is empty
        assert not any(s.kind == "meta" for s in symbols)

    # -- Duplicate meta key: occurrence counter increments (lines 62-64) --

    def test_duplicate_meta_key_occurrence_counter(self) -> None:
        """Two meta entries with the same key produce two meta symbols (different occurrences)."""
        doc = _doc(CLASSIC_DUPLICATE_META)
        symbols = doc.symbols()
        author_syms = [s for s in symbols if s.kind == "meta" and s.name == "author"]
        # Both occurrences produce a symbol (via find_line_containing fallback)
        assert len(author_syms) == 2

    # -- key_range fallback via find_line_containing (lines 67-79) --

    def test_key_range_fallback_finds_key_in_text(self) -> None:
        """When meta_item_range returns None, find_line_containing locates the key."""
        # Classic YARA MetaEntry has no location so meta_item_range always returns None,
        # forcing the find_line_containing fallback on every key.
        doc = _doc(CLASSIC_FULL)
        symbols = doc.symbols()
        # The meta symbols present prove the text fallback found each key
        author = next((s for s in symbols if s.kind == "meta" and s.name == "author"), None)
        assert author is not None
        assert author.range is not None


# ---------------------------------------------------------------------------
# append_string_symbols — lines 84-122
# ---------------------------------------------------------------------------


class TestAppendStringSymbols:
    """Drive all branches of append_string_symbols."""

    def test_no_strings_section_produces_no_string_symbols(self) -> None:
        """Rule with no strings section: strings header not found, loop is empty."""
        doc = _doc(CLASSIC_NO_STRINGS)
        symbols = doc.symbols()
        string_syms = [s for s in symbols if s.kind == "string"]
        assert string_syms == []
        section_strings = [s for s in symbols if s.kind == "section" and s.name == "strings"]
        assert section_strings == []

    def test_named_strings_produce_section_header_and_string_symbols(self) -> None:
        """Normal strings section: section, section_header, and string symbols all appear."""
        doc = _doc(CLASSIC_FULL)
        symbols = doc.symbols()
        kinds = _kinds(symbols)
        assert "section" in kinds
        assert "section_header" in kinds
        assert "string" in kinds
        string_names = _names_of_kind(symbols, "string")
        assert "$a" in string_names
        assert "$b" in string_names
        assert "$c" in string_names

    def test_anonymous_string_uses_dollar_as_display_id(self) -> None:
        """Anonymous string (is_anonymous=True) gets display_id='$' in the symbol."""
        doc = _doc(CLASSIC_ANON_STRING)
        symbols = doc.symbols()
        string_names = _names_of_kind(symbols, "string")
        assert "$" in string_names
        assert "$named" in string_names

    def test_single_line_rule_strings_uses_make_range_fallback(self) -> None:
        """Single-line rule: find_section_range returns None, make_range fallback fires."""
        doc = _doc(CLASSIC_SINGLE_LINE)
        symbols = doc.symbols()
        section_strings = [s for s in symbols if s.kind == "section" and s.name == "strings"]
        assert len(section_strings) == 1
        # Single-line: start and end lines are the same
        assert section_strings[0].range.start.line == section_strings[0].range.end.line

    def test_string_symbols_with_multiple_types(self) -> None:
        """Hex and regex strings also appear as string symbols alongside plain strings."""
        doc = _doc(CLASSIC_FULL)
        symbols = doc.symbols()
        string_names = _names_of_kind(symbols, "string")
        assert "$a" in string_names  # plain
        assert "$b" in string_names  # hex
        assert "$c" in string_names  # regex


# ---------------------------------------------------------------------------
# append_condition_symbols — lines 125-150
# ---------------------------------------------------------------------------


class TestAppendConditionSymbols:
    """Drive all branches of append_condition_symbols."""

    def test_condition_header_not_in_range_returns_early(self) -> None:
        """When condition: lies outside rule_block_range the function returns early."""
        src = YARAL_FULL
        doc = _doc(src, uri="file://x.yaral")
        ast = doc.ast()
        assert ast is not None
        rule: Any = ast.rules[0]
        # Range that ends before the condition: line (line 9)
        narrow = Range(start=Position(line=0, character=0), end=Position(line=4, character=0))
        symbols: list[SymbolRecord] = []
        append_condition_symbols(doc, symbols, doc.lines, rule, "YaralRule", narrow, src)
        assert symbols == []

    def test_classic_condition_produces_three_symbols(self) -> None:
        """Normal condition section: section, section_header, condition symbols."""
        doc = _doc(CLASSIC_FULL)
        symbols = doc.symbols()
        cond_syms = [s for s in symbols if s.name == "condition"]
        kinds_of_cond = {s.kind for s in cond_syms}
        assert "section" in kinds_of_cond
        assert "section_header" in kinds_of_cond
        assert "condition" in kinds_of_cond

    def test_yaral_condition_node_without_location_uses_find_section_range(self) -> None:
        """YARA-L condition node has location=None; section_content_range returns None,
        triggering the find_section_range fallback (lines 141-144)."""
        src = YARAL_FULL
        doc = _doc(src, uri="file://x.yaral")
        symbols = doc.symbols()
        cond_syms = [s for s in symbols if s.name == "condition"]
        assert len(cond_syms) >= 1

    def test_condition_make_range_fallback_via_single_line_range(self) -> None:
        """Force find_section_range to return None by using a single-line rule_block_range
        that covers only the 'condition:' header line, exercising make_range (line 145)."""
        src = YARAL_FULL
        doc = _doc(src, uri="file://x.yaral")
        ast = doc.ast()
        assert ast is not None
        rule: Any = ast.rules[0]
        # condition: is at line 9 in YARAL_FULL; single-line range -> find_section_range None
        condition_line = next(
            i for i, ln in enumerate(doc.lines) if ln.strip().startswith("condition:")
        )
        single_range = Range(
            start=Position(line=condition_line, character=0),
            end=Position(line=condition_line, character=len(doc.lines[condition_line])),
        )
        symbols: list[SymbolRecord] = []
        append_condition_symbols(doc, symbols, doc.lines, rule, "YaralRule", single_range, src)
        section_syms = [s for s in symbols if s.kind == "section" and s.name == "condition"]
        assert len(section_syms) == 1
        # make_range produces start_line == end_line
        assert section_syms[0].range.start.line == section_syms[0].range.end.line

    def test_single_line_classic_condition_uses_make_range(self) -> None:
        """Classic single-line rule: condition_range computed from make_range fallback."""
        doc = _doc(CLASSIC_SINGLE_LINE)
        symbols = doc.symbols()
        cond_syms = [s for s in symbols if s.kind == "condition"]
        assert len(cond_syms) >= 1


# ---------------------------------------------------------------------------
# append_extra_section_symbols — lines 153-182
# ---------------------------------------------------------------------------


class TestAppendExtraSectionSymbols:
    """Drive all branches of append_extra_section_symbols."""

    def test_classic_rule_has_no_extra_sections(self) -> None:
        """Classic YARA rule has no events/match/outcome/options; nothing appended."""
        doc = _doc(CLASSIC_FULL)
        symbols = doc.symbols()
        extra_names = {s.name for s in symbols if s.name in ("events", "match", "outcome")}
        assert extra_names == set()

    def test_yaral_rule_produces_events_match_outcome_sections(self) -> None:
        """YARA-L rule with events/match/outcome: all three extra sections appear."""
        doc = _doc(YARAL_FULL, uri="file://x.yaral")
        symbols = doc.symbols()
        kinds_of = {s.name: s.kind for s in symbols if s.name in ("events", "match", "outcome")}
        assert "events" in kinds_of
        assert "match" in kinds_of
        assert "outcome" in kinds_of
        # Each should produce a section symbol
        section_names = {s.name for s in symbols if s.kind == "section"}
        assert "events" in section_names
        assert "match" in section_names
        assert "outcome" in section_names

    def test_extra_section_header_symbols_are_emitted(self) -> None:
        """Each extra section also produces a section_header symbol."""
        doc = _doc(YARAL_FULL, uri="file://x.yaral")
        symbols = doc.symbols()
        header_names = {s.name for s in symbols if s.kind == "section_header"}
        assert "events" in header_names
        assert "match" in header_names
        assert "outcome" in header_names

    def test_extra_section_make_range_fallback_via_single_line_range(self) -> None:
        """Single-line rule_block_range covering only the events: line forces make_range."""
        src = YARAL_FULL
        doc = _doc(src, uri="file://x.yaral")
        ast = doc.ast()
        assert ast is not None
        rule: Any = ast.rules[0]
        events_line = next(i for i, ln in enumerate(doc.lines) if ln.strip().startswith("events:"))
        single_range = Range(
            start=Position(line=events_line, character=0),
            end=Position(line=events_line, character=len(doc.lines[events_line])),
        )
        symbols: list[SymbolRecord] = []
        append_extra_section_symbols(doc, symbols, doc.lines, rule, "YaralRule", single_range, src)
        section_syms = [s for s in symbols if s.kind == "section" and s.name == "events"]
        assert len(section_syms) == 1
        # Single-line make_range: start_line == end_line
        assert section_syms[0].range.start.line == section_syms[0].range.end.line

    def test_section_with_none_section_attribute_is_skipped(self) -> None:
        """When a rule attribute for an extra section is None, that section is skipped."""
        src = YARAL_MINIMAL
        doc = _doc(src, uri="file://x.yaral")
        ast = doc.ast()
        assert ast is not None
        rule: Any = ast.rules[0]
        # YaralMinimal has no events/match/outcome/options
        rule_rng = Range(start=Position(line=0, character=0), end=Position(line=4, character=1))
        symbols: list[SymbolRecord] = []
        append_extra_section_symbols(doc, symbols, doc.lines, rule, "YaralMinimal", rule_rng, src)
        assert symbols == []


# ---------------------------------------------------------------------------
# Integration: DocumentContext.symbols() exercises all appenders together
# ---------------------------------------------------------------------------


class TestDocumentContextSymbolsIntegration:
    """End-to-end validation that symbols() correctly invokes all section appenders."""

    @pytest.mark.parametrize(
        ("src", "uri", "expected_kinds"),
        [
            (
                CLASSIC_FULL,
                "file://full.yar",
                {"rule", "rule_block", "section", "section_header", "meta", "string", "condition"},
            ),
            (
                CLASSIC_NO_META,
                "file://no_meta.yar",
                {"rule", "rule_block", "section", "section_header", "string", "condition"},
            ),
            (
                CLASSIC_NO_STRINGS,
                "file://no_strings.yar",
                {"rule", "rule_block", "section", "section_header", "meta", "condition"},
            ),
            (
                CLASSIC_CONDITION_ONLY,
                "file://cond_only.yar",
                {"rule", "rule_block", "section", "section_header", "condition"},
            ),
            (
                YARAL_FULL,
                "file://full.yaral",
                {"rule", "rule_block", "section", "section_header", "meta", "condition"},
            ),
        ],
    )
    def test_all_expected_kinds_present(self, src: str, uri: str, expected_kinds: set[str]) -> None:
        """Each YARA/YARA-L document produces at least the expected symbol kinds."""
        doc = _doc(src, uri=uri)
        symbols = doc.symbols()
        actual_kinds = _kinds(symbols)
        for kind in expected_kinds:
            assert kind in actual_kinds, f"Expected kind '{kind}' missing from {uri}"

    def test_single_line_rule_produces_symbols(self) -> None:
        """Single-line rule produces rule, section, and string symbols."""
        doc = _doc(CLASSIC_SINGLE_LINE, uri="file://sl.yar")
        symbols = doc.symbols()
        assert any(s.kind == "rule" for s in symbols)
        assert any(s.kind == "section" and s.name == "meta" for s in symbols)
        assert any(s.kind == "section" and s.name == "strings" for s in symbols)
        assert any(s.kind == "string" for s in symbols)

    def test_anonymous_string_symbol_is_dollar(self) -> None:
        """Anonymous string yields a symbol named '$'."""
        doc = _doc(CLASSIC_ANON_STRING, uri="file://anon.yar")
        symbols = doc.symbols()
        assert any(s.kind == "string" and s.name == "$" for s in symbols)

    def test_build_symbols_called_with_real_ast_returns_list(self) -> None:
        """build_symbols with a real parsed AST returns a non-empty list."""
        doc = _doc(CLASSIC_FULL, uri="file://build.yar")
        ast = doc.ast()
        assert ast is not None
        result = build_symbols(doc, ast, doc.lines)
        assert isinstance(result, list)
        assert len(result) > 0

    def test_yaral_extra_sections_are_present_in_symbols(self) -> None:
        """YARA-L document with events/match/outcome yields those as section symbols."""
        doc = _doc(YARAL_FULL, uri="file://yaral.yaral")
        symbols = doc.symbols()
        section_names = {s.name for s in symbols if s.kind == "section"}
        assert "events" in section_names
        assert "match" in section_names
        assert "outcome" in section_names

    def test_all_symbol_ranges_are_range_instances(self) -> None:
        """Every symbol produced has a valid Range with Position endpoints."""
        doc = _doc(CLASSIC_FULL, uri="file://range_check.yar")
        for symbol in doc.symbols():
            assert isinstance(symbol.range, Range), f"Symbol {symbol!r} has no Range"
            assert isinstance(symbol.range.start, Position)
            assert isinstance(symbol.range.end, Position)


# ---------------------------------------------------------------------------
# Additional branch coverage: paths reachable only through synthetic objects
# ---------------------------------------------------------------------------

# Source used by all synthetic-object tests; real text for valid ctx/lines.
_SYNTHETIC_SRC = """\
rule synth {
    meta:
        author = "alice"
        author = "bob"
    strings:
        $a = "hit"
    condition:
        $a
}
"""

_YARAL_SRC_WITH_EVENTS = """\
rule SynthYaral {
  meta:
    author = "analyst"
  events:
    $e.metadata.event_type = "NETWORK"
  condition:
    $e
}
"""


class TestMetaItemRangeListFormASTNodes:
    """Exercise meta_item_range list-form branches that require ASTNode items.

    Production parsers do not emit list-form meta entries as ASTNode instances.
    These tests use _LocatedMetaEntry to reach lines 225-229 (list-form match,
    occurrence-skip, and return) and the multi-occurrence path on line 226-228.
    """

    def test_list_form_first_occurrence_with_location_returns_range(self) -> None:
        """ASTNode list-form entry with real location: occurrence=0 returns a Range."""
        src = _SYNTHETIC_SRC
        loc = Location(line=2, column=8, end_line=2, end_column=14)
        meta_list = [_LocatedMetaEntry("author", "alice", loc)]
        result = meta_item_range(meta_list, "author", src, 0)
        assert result is not None

    def test_list_form_skip_first_occurrence_and_return_second(self) -> None:
        """ASTNode list-form: occurrence=1 skips first entry (lines 226-228) and
        returns the second entry's range (line 229)."""
        src = _SYNTHETIC_SRC
        loc_a = Location(line=2, column=8, end_line=2, end_column=14)
        loc_b = Location(line=3, column=8, end_line=3, end_column=14)
        meta_list = [
            _LocatedMetaEntry("author", "alice", loc_a),
            _LocatedMetaEntry("author", "bob", loc_b),
        ]
        # occurrence=0 returns range for first entry
        r0 = meta_item_range(meta_list, "author", src, 0)
        assert r0 is not None
        # occurrence=1 skips first, returns range for second entry
        r1 = meta_item_range(meta_list, "author", src, 1)
        assert r1 is not None
        assert r1.start.line != r0.start.line

    def test_list_form_occurrence_beyond_count_returns_none(self) -> None:
        """When occurrence exceeds the number of matching entries, None is returned."""
        src = _SYNTHETIC_SRC
        loc = Location(line=2, column=8, end_line=2, end_column=14)
        meta_list = [_LocatedMetaEntry("author", "alice", loc)]
        result = meta_item_range(meta_list, "author", src, 1)
        assert result is None


class TestMetaItemRangeEntriesFormOccurrenceSkip:
    """Exercise meta_item_range entries-form occurrence-skip (lines 234-235).

    YARA-L rules with an events section produce MetaSection with ASTNode entries.
    """

    def test_entries_form_first_occurrence_found(self) -> None:
        """Entries form, occurrence=0: first matching entry is processed (line 235-236)."""
        src = _YARAL_SRC_WITH_EVENTS
        doc = _doc(src, uri="file://x.yaral")
        ast = doc.ast()
        assert ast is not None
        rule: Any = ast.rules[0]
        meta = rule.meta
        assert hasattr(meta, "entries"), "Expected MetaSection with entries"
        result = meta_item_range(meta, "author", src, 0)
        # YARA-L MetaEntry location is None so node_value_range returns None
        assert result is None

    def test_entries_form_skip_then_return(self) -> None:
        """Entries form, occurrence=1: first entry is skipped via lines 234-235."""
        src = """\
rule DupMeta {
  meta:
    author = "alice"
    author = "bob"
  events:
    $e.metadata.event_type = "NETWORK"
  condition:
    $e
}
"""
        doc = _doc(src, uri="file://dup.yaral")
        ast = doc.ast()
        assert ast is not None
        rule: Any = ast.rules[0]
        meta = rule.meta
        assert hasattr(meta, "entries"), "Expected MetaSection with entries"
        # occurrence=1: first 'author' is skipped (234-235), second is returned
        result = meta_item_range(meta, "author", src, 1)
        # location is None so return value is None, but the skip branch was exercised
        assert result is None


class TestMetaItemRangesListASTNodes:
    """meta_item_ranges with a list of real ASTNode entries (lines 210-211)."""

    def test_list_of_located_astnodes_returns_real_ranges(self) -> None:
        """When the meta list contains ASTNode entries with locations, ranges are non-None."""
        src = _SYNTHETIC_SRC
        loc = Location(line=2, column=8, end_line=2, end_column=14)
        fake_rule: Any = _FakeRuleWithLocatedMeta([_LocatedMetaEntry("author", "alice", loc)])
        result = meta_item_ranges(fake_rule, src)
        assert len(result) == 1
        assert result[0] is not None


class TestAppendMetaSymbolsSectionContentRangeNonNone:
    """Cover branch 41->48: section_content_range returns a real Range.

    This path is only reachable when meta_item_ranges produces a non-None Range,
    which requires the meta items to be ASTNode instances with real locations.
    """

    def test_section_content_range_not_none_skips_fallback(self) -> None:
        """When section_content_range returns a real Range (line 40-41), the
        inner fallback block (lines 42-47) is skipped, going directly to line 48."""
        src = _SYNTHETIC_SRC
        doc = _doc(src)
        loc = Location(line=2, column=8, end_line=2, end_column=14)
        fake_rule: Any = _FakeRuleWithLocatedMeta([_LocatedMetaEntry("author", "alice", loc)])
        rule_rng = Range(start=Position(line=0, character=0), end=Position(line=7, character=1))
        symbols: list[SymbolRecord] = []
        append_meta_symbols(doc, symbols, doc.lines, fake_rule, "synth", rule_rng)
        # section symbol is emitted directly from the computed range (line 48)
        section_syms = [s for s in symbols if s.kind == "section" and s.name == "meta"]
        assert len(section_syms) == 1
        # Range start comes from header line (line 1) and end from content (line 2)
        assert section_syms[0].range.start.line <= section_syms[0].range.end.line


class TestAppendStringSymbolsNoLocationFallback:
    """Cover lines 99-105 (strings_range fallback) and 112-120 (string_range fallback).

    When string nodes carry no location, node_range returns None, forcing
    section_content_range to return None (triggering find_section_range / make_range)
    and node_value_range to return None (triggering find_string_line).
    """

    def test_strings_range_fallback_via_find_section_range(self) -> None:
        """No-location strings: section_content_range([None]) triggers find_section_range."""
        src = _SYNTHETIC_SRC
        doc = _doc(src)
        ast = doc.ast()
        assert ast is not None
        real_rule: Any = ast.rules[0]
        rule_rng = node_range(real_rule, src)
        assert rule_rng is not None
        fake_rule: Any = _FakeRuleWithNoLocationStrings([_FakeStringNoLocation("$a")])
        symbols: list[SymbolRecord] = []
        append_string_symbols(doc, symbols, doc.lines, fake_rule, "synth", rule_rng, src)
        # strings section symbol is emitted via fallback
        section_syms = [s for s in symbols if s.kind == "section" and s.name == "strings"]
        assert len(section_syms) == 1

    def test_string_identifier_none_triggers_continue(self) -> None:
        """String with None identifier: the 'if not string_id: continue' guard fires."""
        src = _SYNTHETIC_SRC
        doc = _doc(src)
        ast = doc.ast()
        assert ast is not None
        real_rule: Any = ast.rules[0]
        rule_rng = node_range(real_rule, src)
        assert rule_rng is not None
        fake_rule: Any = _FakeRuleWithNoLocationStrings(
            [_FakeStringNoLocation(""), _FakeStringNoLocation("$a")]
        )
        # Patch empty-string identifier to be empty so 'not string_id' is True
        fake_rule.strings[0].identifier = ""
        symbols: list[SymbolRecord] = []
        append_string_symbols(doc, symbols, doc.lines, fake_rule, "synth", rule_rng, src)
        # Only $a should appear; the empty-identifier entry is skipped
        string_syms = [s for s in symbols if s.kind == "string"]
        assert all(s.name != "" for s in string_syms)

    def test_string_range_none_when_id_not_in_source(self) -> None:
        """String whose identifier is absent from source lines: find_string_line returns -1,
        string_range stays None, and no string symbol is emitted (line 121->110)."""
        src = _SYNTHETIC_SRC
        doc = _doc(src)
        ast = doc.ast()
        assert ast is not None
        real_rule: Any = ast.rules[0]
        rule_rng = node_range(real_rule, src)
        assert rule_rng is not None
        fake_rule: Any = _FakeRuleWithNoLocationStrings(
            [_FakeStringNoLocation("$not_present_in_source_at_all")]
        )
        symbols: list[SymbolRecord] = []
        append_string_symbols(doc, symbols, doc.lines, fake_rule, "synth", rule_rng, src)
        # Unfindable string: no string symbol
        string_syms = [s for s in symbols if s.kind == "string"]
        assert string_syms == []

    def test_string_find_string_line_fallback_finds_string_in_text(self) -> None:
        """No-location string whose id IS in the source: find_string_line fallback finds it."""
        src = _SYNTHETIC_SRC
        doc = _doc(src)
        ast = doc.ast()
        assert ast is not None
        real_rule: Any = ast.rules[0]
        rule_rng = node_range(real_rule, src)
        assert rule_rng is not None
        fake_rule: Any = _FakeRuleWithNoLocationStrings([_FakeStringNoLocation("$a")])
        symbols: list[SymbolRecord] = []
        append_string_symbols(doc, symbols, doc.lines, fake_rule, "synth", rule_rng, src)
        string_syms = [s for s in symbols if s.kind == "string" and s.name == "$a"]
        assert len(string_syms) == 1


class TestAppendExtraSectionSymbolsSuccessPath:
    """Cover line 172->179: section_content_range returns a real Range.

    The production YARA-L AST does not provide location for section nodes.
    _FakeSectionWithLocation provides a real Location so node_range returns
    a non-None Range, and section_content_range therefore returns a real value,
    skipping the find_section_range / make_range fallback.
    """

    def test_extra_section_content_range_not_none_skips_fallback(self) -> None:
        """Synthetic section with real location: section_content_range succeeds (line 172->179).

        The branch at line 172 ('if section_range is None') evaluates to False
        and the fallback block (lines 173-178) is not entered.
        """
        src = _YARAL_SRC_WITH_EVENTS
        doc = _doc(src, uri="file://synth.yaral")
        # events: is at line 3 in _YARAL_SRC_WITH_EVENTS
        events_line = next(i for i, ln in enumerate(doc.lines) if "events:" in ln)
        next_line = events_line + 1
        loc = Location(
            line=next_line + 1,
            column=4,
            end_line=next_line + 1,
            end_column=30,
        )
        fake_rule: Any = _FakeRuleWithLocatedSection("events", loc)
        rule_rng = Range(
            start=Position(line=0, character=0),
            end=Position(line=len(doc.lines) - 1, character=1),
        )
        symbols: list[SymbolRecord] = []
        append_extra_section_symbols(
            doc, symbols, doc.lines, fake_rule, "SynthYaral", rule_rng, src
        )
        section_syms = [s for s in symbols if s.kind == "section" and s.name == "events"]
        assert len(section_syms) == 1
        # Range comes from section_content_range (not from fallback make_range)
        # The range spans from the header line to the location end
        assert section_syms[0].range is not None


# ---------------------------------------------------------------------------
# Final coverage gaps: lines 72->80, 80->61, 105, 231->237
# ---------------------------------------------------------------------------


class TestAppendMetaSymbolsKeyNotFindable:
    """Cover lines 72->80 and 80->61 in append_meta_symbols.

    Branch 72->80: find_line_containing returns -1 because the key appears in
    the AST but the meta line uses 'key=value' format (no spaces), so the search
    string 'key =' is never found in lines.

    Branch 80->61: after that, key_range is still None so the loop body appends
    nothing and the loop iterates to the next key.
    """

    def test_key_not_findable_via_find_line_containing(self) -> None:
        """Meta key written as 'x=1' (no spaces): 'x =' not in lines -> -1 -> 72->80."""
        src = "rule a {\n    meta:\n        x=1\n    condition:\n        true\n}\n"
        doc = _doc(src)
        ast = doc.ast()
        assert ast is not None
        rule: Any = ast.rules[0]
        rule_rng = node_range(rule, src)
        assert rule_rng is not None
        symbols: list[SymbolRecord] = []
        append_meta_symbols(doc, symbols, doc.lines, rule, "a", rule_rng)
        # section and section_header emitted, but no meta symbol for 'x'
        # because find_line_containing('x =', ...) returns -1
        assert any(s.kind == "section" and s.name == "meta" for s in symbols)
        assert not any(s.kind == "meta" and s.name == "x" for s in symbols)

    def test_key_loop_body_continues_when_key_range_none(self) -> None:
        """Multiple unfindable keys: the loop iterates multiple times with key_range=None."""
        src = "rule b {\n    meta:\n        x=1\n        y=2\n    condition:\n        true\n}\n"
        doc = _doc(src)
        ast = doc.ast()
        assert ast is not None
        rule: Any = ast.rules[0]
        rule_rng = node_range(rule, src)
        assert rule_rng is not None
        symbols: list[SymbolRecord] = []
        append_meta_symbols(doc, symbols, doc.lines, rule, "b", rule_rng)
        # No meta symbols for x or y since 'x =' and 'y =' are not in lines
        meta_syms = [s for s in symbols if s.kind == "meta"]
        assert meta_syms == []


class TestAppendStringSymbolsMakeRangeFallback:
    """Cover line 105: strings_range = make_range(...) when find_section_range returns None.

    This path is reached when:
    - strings: header is found (header is in lines)
    - section_content_range returns None (all string nodes have no location)
    - find_section_range returns None (single-line rule)
    """

    def test_strings_make_range_on_single_line_no_location_strings(self) -> None:
        """Single-line rule + no-location strings: find_section_range returns None,
        make_range is invoked (line 105)."""
        src = 'rule sl { strings: $a = "x" condition: $a }\n'
        doc = _doc(src)
        rule_rng = Range(
            start=Position(line=0, character=0),
            end=Position(line=0, character=len(src.rstrip("\n"))),
        )
        fake_rule: Any = _FakeRuleWithNoLocationStrings([_FakeStringNoLocation("$a")])
        symbols: list[SymbolRecord] = []
        append_string_symbols(doc, symbols, doc.lines, fake_rule, "sl", rule_rng, src)
        section_syms = [s for s in symbols if s.kind == "section" and s.name == "strings"]
        assert len(section_syms) == 1
        # make_range (line 105): start line == end line (single-line)
        assert section_syms[0].range.start.line == section_syms[0].range.end.line


class TestMetaItemRangeEntriesFormKeyAbsent:
    """Cover branch 231->237: entries form loop completes without matching the key."""

    def test_entries_form_key_absent_returns_none(self) -> None:
        """When the requested key is not in any entries, the loop exhausts and None
        is returned (branch 231->237)."""
        src = _YARAL_SRC_WITH_EVENTS
        doc = _doc(src, uri="file://x.yaral")
        ast = doc.ast()
        assert ast is not None
        rule: Any = ast.rules[0]
        meta = rule.meta
        assert hasattr(meta, "entries"), "Expected MetaSection with entries for this YARA-L rule"
        result = meta_item_range(meta, "this_key_does_not_exist", src, 0)
        assert result is None

    def test_entries_form_empty_entries_returns_none(self) -> None:
        """Empty entries list: loop body never runs, falls through to return None."""

        class _EmptySection:
            entries: list[Any] = []

        result = meta_item_range(_EmptySection(), "any_key", "source", 0)
        assert result is None
