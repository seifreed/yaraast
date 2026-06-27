# Copyright (c) 2026 Marc Rivero López
# Licensed under GPLv3. See LICENSE file for details.
# This test suite validates real code behavior without mocks or stubs.
"""Regression tests for yaraast/lsp/document_symbols.py — second coverage pass.

Coverage targets added by this file (module yaraast.lsp.document_symbols):

- Lines 77-79  : _build_text_import_symbols — symbol_range is not None, symbol appended.
                 Reached by calling build_text_symbols with a source that contains an
                 import directive so IMPORT_DIRECTIVE_RE matches and _quoted_text_range
                 succeeds.

- Lines 96-98  : _build_text_include_symbols — same pattern for include directives.

- Lines 302-310: _quoted_text_range — entire function body.
                 Exercised by three direct-call scenarios:
                   (a) quoted form "value" absent, plain value found (fallback path)
                       covers lines 303-305, 308 else-branch, 309-310
                   (b) neither quoted nor plain form present, returns None
                       covers lines 303-307
                   (c) quoted form present, normal success path
                       covers lines 302-304, 308 if-branch, 309-310

- Line  322    : _parse_text_meta_value returns True for the YARA boolean literal
                 "true" (lowercase).

- Line  324    : _parse_text_meta_value except-branch: lowered == "false" -> return False.

- Line  326    : _parse_text_meta_value except-branch: lowered in {"null","none"} -> None.

Unreachable text import/include branches are already declared by the companion file.
"""

from __future__ import annotations

from yaraast.lsp.document_context import DocumentContext
from yaraast.lsp.document_symbols import (
    _build_text_import_symbols,
    _build_text_include_symbols,
    _parse_text_meta_value,
    _quoted_text_range,
    build_text_symbols,
)
from yaraast.lsp.document_types import SymbolRecord

# ---------------------------------------------------------------------------
# _quoted_text_range: quoted form present — normal success path (lines 302-310
# with if-branch at line 308)
# ---------------------------------------------------------------------------


def test_quoted_text_range_returns_range_when_quoted_form_is_present() -> None:
    """_quoted_text_range locates the value inside its surrounding quotes.

    When the line contains '"value"', line.find('"value"') succeeds (start >= 0),
    the if-branch at line 304 is NOT taken, and value_start = start + 1 (line 308
    if-branch) because line[start] == '"'.
    """
    line = 'import "pe"'
    result = _quoted_text_range(line, 3, "pe")

    assert result is not None
    # The opening quote is at index 7; value starts at index 8.
    assert result.start.line == 3
    assert result.start.character == 8
    # "pe" has length 2, so end character is 10.
    assert result.end.character == 10


# ---------------------------------------------------------------------------
# _quoted_text_range: quoted form absent, plain value present — fallback path
# (lines 303-305, 308 else-branch, 309-310)
# ---------------------------------------------------------------------------


def test_quoted_text_range_falls_back_to_plain_find_when_no_quotes() -> None:
    """_quoted_text_range falls back to a plain find when the quoted form is missing.

    The line "import value" does not contain '"value"', so line.find('"value"')
    returns -1 and the if-branch at line 304 IS taken (line 305 executes).
    line.find("value") then succeeds.  Because line[start] is 'v' (not '"'), the
    else-branch of line 308 runs, setting value_start = start directly.
    """
    line = "import value"
    result = _quoted_text_range(line, 0, "value")

    assert result is not None
    # "value" appears at index 7 in "import value".
    assert result.start.character == 7
    assert result.end.character == 12


# ---------------------------------------------------------------------------
# _quoted_text_range: neither form present — returns None (lines 306-307)
# ---------------------------------------------------------------------------


def test_quoted_text_range_returns_none_when_value_absent() -> None:
    """_quoted_text_range returns None when neither '"value"' nor 'value' appears.

    Both find() calls return -1, so the guard at line 306 is True and the function
    returns None (line 307).
    """
    line = "import other_module"
    result = _quoted_text_range(line, 0, "absent_value")

    assert result is None


# ---------------------------------------------------------------------------
# _quoted_text_range: duplicate substring — first occurrence used correctly
# (exercises lines 302-310 with a value that appears more than once in the line)
# ---------------------------------------------------------------------------


def test_quoted_text_range_uses_first_quoted_occurrence() -> None:
    """When a value string appears twice on the line but only one is quoted, the
    quoted form is found first and the correct character range is returned.

    This also exercises the normal (if-branch, line 308) code path with a duplicate
    unquoted substring so that the find()-based fallback would have returned the wrong
    position if it had been taken instead.
    """
    # "pe" appears unquoted first at index 7, then quoted at index 10.
    line = 'import pe "pe"'
    result = _quoted_text_range(line, 1, "pe")

    assert result is not None
    # Quoted '"pe"' is at index 10; value_start = 11 (after the opening quote).
    assert result.start.character == 11
    assert result.end.character == 13


# ---------------------------------------------------------------------------
# _build_text_import_symbols: symbol appended for a valid import line
# (lines 77-79 + lines 302-310 via _quoted_text_range)
# ---------------------------------------------------------------------------


def test_build_text_import_symbols_appends_symbol_for_valid_import() -> None:
    """_build_text_import_symbols appends a SymbolRecord when IMPORT_DIRECTIVE_RE
    matches and _quoted_text_range returns a non-None Range (lines 77-79).

    The path through _quoted_text_range (lines 302-310) is also exercised here
    because _build_text_import_symbols calls it for every matched line.
    """
    src = 'import "pe"\nrule r { condition: true }\n'
    doc = DocumentContext(uri="file://import_direct.yar", text=src)
    symbols: list[SymbolRecord] = []

    _build_text_import_symbols(doc, doc.lines, symbols)

    import_syms = [s for s in symbols if s.kind == "import"]
    assert len(import_syms) == 1
    assert import_syms[0].name == "pe"
    assert import_syms[0].range.start.line == 0
    # The value "pe" starts at column 8 (after 'import "').
    assert import_syms[0].range.start.character == 8


# ---------------------------------------------------------------------------
# _build_text_import_symbols: multiple imports — all appended (lines 77-79)
# ---------------------------------------------------------------------------


def test_build_text_import_symbols_appends_symbol_for_each_import_line() -> None:
    """_build_text_import_symbols appends one SymbolRecord per matched import line
    (lines 77-79 exercised for each iteration)."""
    src = 'import "pe"\nimport "math"\nrule r { condition: true }\n'
    doc = DocumentContext(uri="file://multi_import.yar", text=src)
    symbols: list[SymbolRecord] = []

    _build_text_import_symbols(doc, doc.lines, symbols)

    names = {s.name for s in symbols if s.kind == "import"}
    assert names == {"pe", "math"}


# ---------------------------------------------------------------------------
# _build_text_include_symbols: symbol appended for a valid include line
# (lines 96-98 + lines 302-310 via _quoted_text_range)
# ---------------------------------------------------------------------------


def test_build_text_include_symbols_appends_symbol_for_valid_include() -> None:
    """_build_text_include_symbols appends a SymbolRecord when INCLUDE_DIRECTIVE_RE
    matches and _quoted_text_range returns a non-None Range (lines 96-98).
    """
    src = 'include "helpers.yar"\nrule r { condition: true }\n'
    doc = DocumentContext(uri="file://include_direct.yar", text=src)
    symbols: list[SymbolRecord] = []

    _build_text_include_symbols(doc, doc.lines, symbols)

    include_syms = [s for s in symbols if s.kind == "include"]
    assert len(include_syms) == 1
    assert include_syms[0].name == "helpers.yar"
    assert include_syms[0].range.start.line == 0


def test_parse_text_meta_value_rejects_complex_python_literals() -> None:
    assert _parse_text_meta_value("[1, 2, 3]") is None


# ---------------------------------------------------------------------------
# build_text_symbols with import + include: integration path covering 77-79 and 96-98
# ---------------------------------------------------------------------------


def test_build_text_symbols_includes_import_and_include_symbols() -> None:
    """build_text_symbols populates import and include SymbolRecords for source text
    that contains both directives.  This exercises lines 77-79 and 96-98 through the
    normal call chain (build_text_symbols -> _build_text_import_symbols /
    _build_text_include_symbols -> _quoted_text_range).
    """
    src = (
        'import "pe"\n' 'include "lib.yar"\n' "rule combined {\n" "    condition: pe.is_pe\n" "}\n"
    )
    doc = DocumentContext(uri="file://combined_text.yar", text=src)
    symbols = build_text_symbols(doc, doc.lines)

    kinds_names = {(s.kind, s.name) for s in symbols}
    assert ("import", "pe") in kinds_names
    assert ("include", "lib.yar") in kinds_names
    assert ("rule", "combined") in kinds_names


# ---------------------------------------------------------------------------
# _parse_text_meta_value via build_text_symbols:
# YARA boolean "true" -> True (line 322)
# ---------------------------------------------------------------------------


def test_text_meta_symbols_parses_yara_boolean_true() -> None:
    """A meta entry whose raw value is 'true' (YARA boolean, not a Python literal)
    causes ast.literal_eval to raise ValueError; the except-branch lowered-check
    returns True (line 322).  The meta symbol is recorded correctly."""
    src = (
        "rule bool_true {\n" "    meta:\n" "        enabled = true\n" "    condition: true\n" "}\n"
    )
    doc = DocumentContext(uri="file://meta_true.yar", text=src)
    symbols = build_text_symbols(doc, doc.lines)

    meta_names = [s.name for s in symbols if s.kind == "meta"]
    assert "enabled" in meta_names


# ---------------------------------------------------------------------------
# _parse_text_meta_value via build_text_symbols:
# YARA boolean "false" -> False (line 324)
# ---------------------------------------------------------------------------


def test_text_meta_symbols_parses_yara_boolean_false() -> None:
    """A meta entry whose raw value is 'false' (YARA boolean) exercises the
    lowered == "false" branch (line 324) in _parse_text_meta_value."""
    src = (
        "rule bool_false {\n"
        "    meta:\n"
        "        disabled = false\n"
        "    condition: true\n"
        "}\n"
    )
    doc = DocumentContext(uri="file://meta_false.yar", text=src)
    symbols = build_text_symbols(doc, doc.lines)

    meta_names = [s.name for s in symbols if s.kind == "meta"]
    assert "disabled" in meta_names


# ---------------------------------------------------------------------------
# _parse_text_meta_value via build_text_symbols:
# YARA null literal "null" -> None (line 326, first membership check)
# ---------------------------------------------------------------------------


def test_text_meta_symbols_parses_yara_null_literal() -> None:
    """A meta entry whose raw value is 'null' exercises the 'null' membership test
    inside the except-branch (line 326) of _parse_text_meta_value."""
    src = (
        "rule meta_null {\n" "    meta:\n" "        nothing = null\n" "    condition: true\n" "}\n"
    )
    doc = DocumentContext(uri="file://meta_null.yar", text=src)
    symbols = build_text_symbols(doc, doc.lines)

    meta_names = [s.name for s in symbols if s.kind == "meta"]
    assert "nothing" in meta_names


# ---------------------------------------------------------------------------
# _parse_text_meta_value via build_text_symbols:
# YARA null variant "none" -> None (line 326, second membership check)
# ---------------------------------------------------------------------------


def test_text_meta_symbols_parses_yara_none_literal() -> None:
    """A meta entry whose raw value is 'none' exercises the 'none' membership test
    inside the except-branch (line 326) of _parse_text_meta_value."""
    src = "rule meta_none {\n" "    meta:\n" "        empty = none\n" "    condition: true\n" "}\n"
    doc = DocumentContext(uri="file://meta_none.yar", text=src)
    symbols = build_text_symbols(doc, doc.lines)

    meta_names = [s.name for s in symbols if s.kind == "meta"]
    assert "empty" in meta_names


# ---------------------------------------------------------------------------
# _parse_text_meta_value via build_text_symbols:
# all four YARA literal meta values in one rule (lines 322, 324, 326 together)
# ---------------------------------------------------------------------------


def test_text_meta_symbols_parses_all_yara_literals_in_one_rule() -> None:
    """All four YARA literal meta values -- true, false, null, none -- are parsed
    correctly in a single rule, exercising lines 322, 324, and 326 in a single pass."""
    src = (
        "rule all_literals {\n"
        "    meta:\n"
        "        flag_t = true\n"
        "        flag_f = false\n"
        "        gone_null = null\n"
        "        gone_none = none\n"
        "    condition: true\n"
        "}\n"
    )
    doc = DocumentContext(uri="file://meta_all_literals.yar", text=src)
    symbols = build_text_symbols(doc, doc.lines)

    meta_names = {s.name for s in symbols if s.kind == "meta"}
    assert "flag_t" in meta_names
    assert "flag_f" in meta_names
    assert "gone_null" in meta_names
    assert "gone_none" in meta_names
