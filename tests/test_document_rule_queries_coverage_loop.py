# Copyright (c) 2026 Marc Rivero López
# Licensed under GPLv3. See LICENSE file for details.
# This test suite validates real code behavior without mocks or stubs.

"""Regression tests targeting uncovered lines in yaraast/lsp/document_rule_queries.py.

Missing-line targets (from --cov-report=term-missing at 66.67%):
  24->22, 33, 39-66, 72-75, 95, 104-107, 116, 119-125, 139,
  143->142, 147-152, 167, 171, 184, 187, 198, 201, 208

All tests parse real YARA / YARA-L documents through DocumentContext and call
the public query functions directly. No mocking is used.
"""

from __future__ import annotations

from yaraast.lsp import document_rule_queries as queries
from yaraast.lsp.document_context import DocumentContext

# ---------------------------------------------------------------------------
# Reusable YARA / YARA-L document text
# ---------------------------------------------------------------------------

# Parseable YARA rule with meta, strings, and condition.
_CLASSIC_ONE = (
    "rule alpha {\n"
    "    meta:\n"
    '        author = "alice"\n'
    "    strings:\n"
    '        $a = "plain"\n'
    "    condition:\n"
    "        $a\n"
    "}\n"
)

# Parseable YARA rule that uses an anonymous string, plus a regular one.
_CLASSIC_ANON = (
    "rule anon_rule {\n"
    "    strings:\n"
    '        $ = "anon"\n'
    '        $b = "named"\n'
    "    condition:\n"
    "        any of them\n"
    "}\n"
)

# Two parseable YARA rules in one document; used to exercise section-symbol
# filtering across rule boundaries.
_CLASSIC_TWO = (
    "rule first {\n"
    "    strings:\n"
    '        $a = "x"\n'
    "    condition:\n"
    "        $a\n"
    "}\n"
    "\n"
    "rule second {\n"
    "    meta:\n"
    '        author = "bob"\n'
    "    strings:\n"
    '        $b = "y"\n'
    "    condition:\n"
    "        $b\n"
    "}\n"
)

# Parseable YARA-L rule that produces a MetaSection with .entries.
_YARAL_WITH_META = (
    "rule detect_login {\n"
    "  meta:\n"
    '    author = "alice"\n'
    "    version = 1\n"
    "  events:\n"
    '    $e.metadata.event_type = "USER_LOGIN"\n'
    "  condition:\n"
    "    $e\n"
    "}\n"
)

# Parseable YARA-L rule that has no meta section at all.
_YARAL_NO_META = (
    "rule no_meta {\n"
    "  events:\n"
    '    $e.metadata.event_type = "USER_LOGIN"\n'
    "  condition:\n"
    "    $e\n"
    "}\n"
)

# Unparseable YARA: rule header present, meta section present, rule body truncated.
_UNPARSEABLE_WITH_META = (
    "rule broken {\n"
    "  meta:\n"
    '    author = "bob"\n'
    "    count = 3\n"
    "  strings:\n"
    '    $a = "x"\n'
    "  condition:\n"
)

# Unparseable YARA: rule has tags in its header (exercises tag-split branch).
_UNPARSEABLE_WITH_TAGS = (
    "rule tagged_broken : tag1 tag2 {\n"
    "  meta:\n"
    '    author = "carol"\n'
    "  strings:\n"
    '    $a = "x"\n'
    "  condition:\n"
)

# Unparseable YARA: private modifier present (exercises modifier-split branch).
_UNPARSEABLE_PRIVATE = 'private rule priv_broken {\n  strings:\n    $a = "x"\n  condition:\n'

# Unparseable YARA: rule exists but has no meta section.
_UNPARSEABLE_NO_META = 'rule no_meta_broken {\n  strings:\n    $a = "x"\n  condition:\n'

# Unparseable YARA: meta lines include blank, comment, and a bad entry (= value,
# no key), so the skipping/filtering branches inside _fallback_rule_meta_items run.
_UNPARSEABLE_META_MIXED = (
    "rule mixed_meta {\n"
    "  meta:\n"
    '    author = "bob"\n'
    "\n"
    "    // a comment line\n"
    "    = bad_no_key\n"
    "    count = 3\n"
    "  condition:\n"
)

# Unparseable YARA-L document: the parser raises YaraLParserError (not a
# ParserError or LexerError), so DocumentContext._SymbolIndex.get_symbols
# returns [] instead of running build_text_symbols.  As a result,
# get_rule_sections finds no section symbols and falls through to the
# text-scan fallback at lines 147-152.
_YARAL_BROKEN_EVENTS = (
    "rule detect_event {\n"
    "  events:\n"
    '    $e.metadata.event_type = "USER_LOGIN"\n'
    "  condition:\n"
    "    $e\n"
    # intentionally truncated so YARA-L parser raises an error
)


def _doc(text: str, uri: str = "file://test.yar") -> DocumentContext:
    return DocumentContext(uri=uri, text=text)


# ---------------------------------------------------------------------------
# Cache-hit paths
# ---------------------------------------------------------------------------


def test_get_rule_info_cache_hit_returns_same_data() -> None:
    """Line 33: second call to get_rule_info returns a copy from the cache."""
    doc = _doc(_CLASSIC_ONE)
    assert doc.ast() is not None

    first = queries.get_rule_info(doc, "alpha")
    assert first is not None
    second = queries.get_rule_info(doc, "alpha")  # cache hit at line 33
    assert second is not None
    assert first == second
    # Verify independence: mutating the returned copy must not corrupt the cache.
    assert isinstance(first["modifiers"], list)
    first["modifiers"].append("INJECTED")
    third = queries.get_rule_info(doc, "alpha")
    assert third is not None
    assert "INJECTED" not in third["modifiers"]


def test_get_rule_meta_items_cache_hit() -> None:
    """Line 95: second call to get_rule_meta_items returns the cached result."""
    doc = _doc(_CLASSIC_ONE)
    assert doc.ast() is not None

    first = queries.get_rule_meta_items(doc, "alpha")
    second = queries.get_rule_meta_items(doc, "alpha")  # cache hit at line 95
    assert first == second
    assert ("author", "alice") in second


def test_get_rule_string_identifiers_cache_hit() -> None:
    """Line 116: second call to get_rule_string_identifiers uses the cache."""
    doc = _doc(_CLASSIC_ONE)
    assert doc.ast() is not None

    first = queries.get_rule_string_identifiers(doc, "alpha")
    second = queries.get_rule_string_identifiers(doc, "alpha")  # cache hit at line 116
    assert first == second
    assert "$a" in second


def test_get_rule_sections_cache_hit() -> None:
    """Line 139: second call to get_rule_sections returns the cached list."""
    doc = _doc(_CLASSIC_ONE)
    assert doc.ast() is not None

    first = queries.get_rule_sections(doc, "alpha")
    second = queries.get_rule_sections(doc, "alpha")  # cache hit at line 139
    assert first == second
    assert "condition" in second


# ---------------------------------------------------------------------------
# Unparseable-document fallback paths: get_rule_info (lines 39-66)
# ---------------------------------------------------------------------------


def test_get_rule_info_fallback_with_meta_and_strings() -> None:
    """Lines 39-66: text-fallback path for get_rule_info on an unparseable doc."""
    doc = _doc(_UNPARSEABLE_WITH_META)
    assert doc.ast() is None  # confirm parse failure

    info = queries.get_rule_info(doc, "broken")
    assert info is not None
    assert info["name"] == "broken"
    assert info["modifiers"] == []
    assert info["tags"] == []
    assert ("author", "bob") in info["meta"]
    assert info["strings_count"] == 1


def test_get_rule_info_fallback_with_tags() -> None:
    """Lines 44-45: tag-split branch inside text-fallback for get_rule_info."""
    doc = _doc(_UNPARSEABLE_WITH_TAGS)
    assert doc.ast() is None

    info = queries.get_rule_info(doc, "tagged_broken")
    assert info is not None
    assert info["tags"] == ["tag1", "tag2"]


def test_get_rule_info_fallback_with_modifier() -> None:
    """Lines 43: modifier-split branch inside text-fallback for get_rule_info."""
    doc = _doc(_UNPARSEABLE_PRIVATE)
    assert doc.ast() is None

    info = queries.get_rule_info(doc, "priv_broken")
    assert info is not None
    assert "private" in info["modifiers"]


def test_get_rule_info_fallback_for_missing_rule_returns_none() -> None:
    """Lines 36-38: text fallback returns None when rule name is not found."""
    doc = _doc(_UNPARSEABLE_WITH_META)
    assert doc.ast() is None

    result = queries.get_rule_info(doc, "nonexistent_rule")
    assert result is None


# ---------------------------------------------------------------------------
# AST paths with YARA-L meta (entries): lines 72-75, 104-107
# ---------------------------------------------------------------------------


def test_get_rule_info_yaral_meta_entries_path() -> None:
    """Lines 72-73: get_rule_info reads meta from MetaSection.entries (YARA-L)."""
    doc = _doc(_YARAL_WITH_META, uri="file://test.yaral")
    assert doc.ast() is not None

    info = queries.get_rule_info(doc, "detect_login")
    assert info is not None
    assert ("author", "alice") in info["meta"]
    assert ("version", 1) in info["meta"]
    assert info["has_events"] is True
    assert info["has_match"] is False


def test_get_rule_info_yaral_no_meta_else_branch() -> None:
    """Lines 74-75: else branch in get_rule_info when meta is None (YARA-L rule without meta)."""
    doc = _doc(_YARAL_NO_META, uri="file://test.yaral")
    assert doc.ast() is not None

    info = queries.get_rule_info(doc, "no_meta")
    assert info is not None
    assert info["meta"] == []
    assert info["has_events"] is True


def test_get_rule_meta_items_yaral_entries_path() -> None:
    """Lines 104-105: get_rule_meta_items reads from MetaSection.entries (YARA-L)."""
    doc = _doc(_YARAL_WITH_META, uri="file://test.yaral")
    assert doc.ast() is not None

    items = queries.get_rule_meta_items(doc, "detect_login")
    assert ("author", "alice") in items
    assert ("version", 1) in items


def test_get_rule_meta_items_yaral_no_meta_else_branch() -> None:
    """Lines 106-107: else branch in get_rule_meta_items when meta is None (YARA-L)."""
    doc = _doc(_YARAL_NO_META, uri="file://test.yaral")
    assert doc.ast() is not None

    items = queries.get_rule_meta_items(doc, "no_meta")
    assert items == []


# ---------------------------------------------------------------------------
# Unparseable-document fallback paths: get_rule_string_identifiers (lines 119-125)
# ---------------------------------------------------------------------------


def test_get_rule_string_identifiers_fallback_for_unparseable_doc() -> None:
    """Lines 119-125: text-symbol fallback for get_rule_string_identifiers."""
    doc = _doc(_UNPARSEABLE_WITH_META)
    assert doc.ast() is None

    ids = queries.get_rule_string_identifiers(doc, "broken")
    assert "$a" in ids


def test_get_rule_string_identifiers_fallback_nonexistent_rule_returns_empty() -> None:
    """Lines 119-125: fallback returns empty list when rule is not found."""
    doc = _doc(_UNPARSEABLE_WITH_META)
    assert doc.ast() is None

    ids = queries.get_rule_string_identifiers(doc, "nonexistent")
    assert ids == []


# ---------------------------------------------------------------------------
# Anonymous strings: line 127
# ---------------------------------------------------------------------------


def test_get_rule_string_identifiers_anonymous_string_becomes_dollar() -> None:
    """Line 127: anonymous string (is_anonymous=True) is represented as '$'."""
    doc = _doc(_CLASSIC_ANON)
    assert doc.ast() is not None

    ids = queries.get_rule_string_identifiers(doc, "anon_rule")
    assert "$" in ids
    assert "$b" in ids


# ---------------------------------------------------------------------------
# Multi-rule document: branch 143->142 (section symbol filtered by container)
# ---------------------------------------------------------------------------


def test_get_rule_sections_multi_rule_filters_by_container() -> None:
    """Branch 143->142: when iterating section symbols, symbols from a different
    rule are skipped.  A two-rule doc guarantees the filter runs on both rules."""
    doc = _doc(_CLASSIC_TWO)
    assert doc.ast() is not None

    first_secs = queries.get_rule_sections(doc, "first")
    second_secs = queries.get_rule_sections(doc, "second")

    # 'first' has no meta section; 'second' does.
    assert "meta" not in first_secs
    assert "meta" in second_secs
    assert "condition" in first_secs
    assert "condition" in second_secs


# ---------------------------------------------------------------------------
# Unparseable-document fallback for get_rule_sections (lines 147-152)
# ---------------------------------------------------------------------------


def test_get_rule_sections_text_fallback_for_unparseable_classic_doc() -> None:
    """Lines 147-152 (first path): confirms structure is found via sections symbols
    from build_text_symbols for a ParserError doc (sections not empty, so fallback
    is skipped - validating the guard condition)."""
    doc = _doc(_UNPARSEABLE_WITH_META)
    assert doc.ast() is None

    secs = queries.get_rule_sections(doc, "broken")
    assert "meta" in secs
    assert "strings" in secs
    assert "condition" in secs


def test_get_rule_sections_text_fallback_yaral_parser_error() -> None:
    """Lines 147-152 (actual path): YaraLParserError is not ParserError/LexerError,
    so get_symbols returns [] and the text-scan fallback at lines 147-152 runs."""
    # YaraLParserError is not a subclass of ParserError or LexerError.
    # DocumentContext._SymbolIndex.get_symbols returns [] when the error is not
    # one of those two types.  With no section symbols, the fallback fires.
    doc = _doc(_YARAL_BROKEN_EVENTS, uri="file://test.yaral")
    assert doc.ast() is None

    # Confirm the error type is not ParserError or LexerError.
    from yaraast.lexer.lexer_errors import LexerError
    from yaraast.parser._shared import ParserError

    err = doc.parse_error()
    assert not isinstance(err, (ParserError, LexerError))

    # Section symbols must be empty (proving the fallback is needed).
    assert doc._symbols_of_kind("section") == []

    secs = queries.get_rule_sections(doc, "detect_event")
    assert "events" in secs
    assert "condition" in secs


def test_get_rule_sections_fallback_rule_not_in_text_returns_empty() -> None:
    """Branch 148->153: rule_line < 0 branch - rule name not found in text at all.

    With a YaraLParserError doc, section symbols are empty and get_rule returns None.
    When the queried rule name does not appear in the document text either,
    find_rule_line returns -1 and the inner text-scan block is skipped, yielding []."""
    doc = _doc(_YARAL_BROKEN_EVENTS, uri="file://test.yaral")
    assert doc.ast() is None

    from yaraast.lexer.lexer_errors import LexerError
    from yaraast.parser._shared import ParserError

    err = doc.parse_error()
    assert not isinstance(err, (ParserError, LexerError))
    assert doc._symbols_of_kind("section") == []

    secs = queries.get_rule_sections(doc, "completely_absent_rule")
    assert secs == []


# ---------------------------------------------------------------------------
# _fallback_rule_meta_items edge cases (lines 167, 171, 184, 187)
# ---------------------------------------------------------------------------


def test_fallback_rule_meta_items_unknown_rule_name_returns_empty() -> None:
    """Line 167: _fallback returns [] when the rule name is not found in the text."""
    doc = _doc(_UNPARSEABLE_WITH_META)
    assert doc.ast() is None

    result = queries.get_rule_meta_items(doc, "absolutely_not_here")
    assert result == []


def test_fallback_rule_meta_items_rule_without_meta_section_returns_empty() -> None:
    """Line 171: _fallback returns [] when find_section_header_position('meta') is None."""
    doc = _doc(_UNPARSEABLE_NO_META)
    assert doc.ast() is None

    result = queries.get_rule_meta_items(doc, "no_meta_broken")
    assert result == []


def test_fallback_rule_meta_items_skips_blank_and_comment_lines() -> None:
    """Line 184: blank lines and comment lines inside the meta block are skipped."""
    doc = _doc(_UNPARSEABLE_META_MIXED)
    assert doc.ast() is None

    items = queries.get_rule_meta_items(doc, "mixed_meta")
    keys = {k for k, _ in items}
    assert "author" in keys
    assert "count" in keys
    # The empty-key entry '= bad_no_key' must be excluded.
    assert "" not in keys


def test_fallback_rule_meta_items_skips_entry_with_no_key() -> None:
    """Line 187: _parse_meta_assignment returning (None, None) causes the entry to be skipped."""
    doc = _doc(_UNPARSEABLE_META_MIXED)
    assert doc.ast() is None

    items = queries.get_rule_meta_items(doc, "mixed_meta")
    # None-key entries must not appear.
    assert all(k is not None for k, _ in items)
    assert all(k != "" for k, _ in items)


# ---------------------------------------------------------------------------
# _parse_meta_assignment edge cases (lines 198, 201, 208)
# ---------------------------------------------------------------------------


def test_parse_meta_assignment_empty_key_returns_none_pair() -> None:
    """Line 198: when the key part is empty (e.g., ' = value'), return (None, None)."""
    key, value = queries._parse_meta_assignment(" = some_value")
    assert key is None
    assert value is None


def test_parse_meta_assignment_empty_value_returns_key_with_empty_string() -> None:
    """Line 201: when the value part is empty (e.g., 'key = '), return (key, '')."""
    key, value = queries._parse_meta_assignment("key = ")
    assert key == "key"
    assert value == ""


def test_parse_meta_assignment_non_literal_raw_string_fallback() -> None:
    """Line 208: when ast.literal_eval fails and the token is not a bare bool,
    the raw value is returned after stripping surrounding double-quotes."""
    key, value = queries._parse_meta_assignment("note = some unquoted text")
    assert key == "note"
    assert value == "some unquoted text"


def test_parse_meta_assignment_no_equals_sign_returns_none_pair() -> None:
    """Line 194: when the line contains no '=' character, return (None, None)."""
    key, value = queries._parse_meta_assignment("no equals sign here")
    assert key is None
    assert value is None


def test_parse_meta_assignment_bare_true_boolean() -> None:
    """Lines 206-207: bare 'true'/'false' tokens are converted to Python bool."""
    k1, v1 = queries._parse_meta_assignment("flag = true")
    assert k1 == "flag"
    assert v1 is True

    k2, v2 = queries._parse_meta_assignment("flag = false")
    assert k2 == "flag"
    assert v2 is False
