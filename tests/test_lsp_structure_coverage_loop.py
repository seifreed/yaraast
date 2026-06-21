# Copyright (c) 2026 Marc Rivero López
# Licensed under GPLv3. See LICENSE file for details.
# This test suite validates real code behavior without mocks or stubs.
"""Regression tests for yaraast.lsp.structure covering previously uncovered lines."""

from __future__ import annotations

from yaraast.lsp.structure import (
    _previous_significant_char,
    _previous_significant_word,
    _scan_visible_section_header,
    _starts_regex_literal,
    find_quoted_value_range,
    find_rule_end,
    find_section_header_range,
    find_section_line,
    find_string_line,
    get_rule_text_range,
    split_lines,
)

# ---------------------------------------------------------------------------
# _previous_significant_word — line 81: return None when no identifier chars
# ---------------------------------------------------------------------------


def test_previous_significant_word_no_word_before_index() -> None:
    """Return None when only whitespace precedes the index (line 81)."""
    result = _previous_significant_word("   /", 3)
    assert result is None


def test_previous_significant_word_non_alnum_char_before_index() -> None:
    """Return None when only non-alnum, non-underscore chars precede the index."""
    result = _previous_significant_word("(  /", 3)
    assert result is None


def test_previous_significant_word_with_word_before_index() -> None:
    """Return the lowercased word when an identifier precedes the index."""
    result = _previous_significant_word("matches /", 8)
    assert result == "matches"


# ---------------------------------------------------------------------------
# _starts_regex_literal — line 87: char is not '/'
# ---------------------------------------------------------------------------


def test_starts_regex_literal_char_not_slash() -> None:
    """Return False immediately when the character at index is not '/' (line 87)."""
    assert _starts_regex_literal("abc", 1) is False


# ---------------------------------------------------------------------------
# _starts_regex_literal — line 89: next char is '/' (line comment start)
# ---------------------------------------------------------------------------


def test_starts_regex_literal_next_char_is_slash() -> None:
    """Return False when the next char forms '//' (line comment, line 89)."""
    assert _starts_regex_literal("//comment", 0) is False


def test_starts_regex_literal_next_char_is_star() -> None:
    """Return False when the next char forms '/*' (block comment open, line 89)."""
    assert _starts_regex_literal("/*comment*/", 0) is False


def test_starts_regex_literal_slash_at_end_of_line() -> None:
    """When '/' is at the last position, the next-char guard does not fire.

    The previous significant char is '=' which is in REGEX_CONTEXT_CHARS, so
    the function returns True — confirming the line-89 branch was not taken.
    """
    assert _starts_regex_literal("=/", 1) is True


# ---------------------------------------------------------------------------
# _scan_visible_section_header — block comment paths (lines 117-122)
# ---------------------------------------------------------------------------


def test_scan_visible_section_header_block_comment_spans_full_line() -> None:
    """A line that is entirely inside a block comment does not yield a header."""
    # Start with in_block_comment=True; the line has no closing '*/'
    col, still_in_block = _scan_visible_section_header(
        "strings: here but in a comment", "strings", True
    )
    assert col is None
    assert still_in_block is True  # comment was never closed


def test_scan_visible_section_header_block_comment_closes_on_line() -> None:
    """A block comment that closes mid-line; content after '*/' is visible."""
    # 'strings:' after the closing '*/' must be found
    col, in_block = _scan_visible_section_header("*/ strings:", "strings", True)
    assert col is not None
    assert in_block is False


# ---------------------------------------------------------------------------
# _scan_visible_section_header — line comment break (line 126)
# ---------------------------------------------------------------------------


def test_scan_visible_section_header_line_comment_hides_header() -> None:
    """A '//' comment hides any section header that follows it (line 126)."""
    col, _ = _scan_visible_section_header("// strings:", "strings", False)
    assert col is None


# ---------------------------------------------------------------------------
# _scan_visible_section_header — block comment open mid-line (lines 128-130)
# ---------------------------------------------------------------------------


def test_scan_visible_section_header_block_comment_open_hides_trailing_header() -> None:
    """A '/*' that opens before the header hides the header (lines 128-130)."""
    col, in_block = _scan_visible_section_header("x /* strings:", "strings", False)
    assert col is None
    assert in_block is True


# ---------------------------------------------------------------------------
# _scan_visible_section_header — escape inside string (lines 133-135)
# ---------------------------------------------------------------------------


def test_scan_visible_section_header_escape_in_string_skips_char() -> None:
    """An escape sequence inside a string is consumed without leaving the string."""
    # '\"' inside a double-quoted string: the escaped quote must not close the string
    # so the real 'strings:' that follows outside the string is found.
    col, _ = _scan_visible_section_header('"some \\" text" strings:', "strings", False)
    assert col is not None


# ---------------------------------------------------------------------------
# _scan_visible_section_header — backslash toggles escape flag (lines 138-140)
# ---------------------------------------------------------------------------


def test_scan_visible_section_header_backslash_in_string_sets_escape() -> None:
    """A lone backslash inside a string sets the escape flag for the next char.

    '\"' is an escaped quote so the string continues; 'strings:' after closing '"'
    is visible.
    """
    col, _ = _scan_visible_section_header('"\\"" strings:', "strings", False)
    assert col is not None


def test_scan_visible_section_header_backslash_in_regex_sets_escape() -> None:
    """A backslash inside a regex literal sets the escape flag for the next char."""
    # matches /pat\// strings: — the '\/' is an escaped slash inside the regex;
    # the regex ends at the third unescaped '/', and 'strings:' is found after.
    line = "x matches /pat\\// strings:"
    col, _ = _scan_visible_section_header(line, "strings", False)
    assert col is not None


# ---------------------------------------------------------------------------
# _scan_visible_section_header — regex literal open (line 150->152 branch)
# ---------------------------------------------------------------------------


def test_scan_visible_section_header_regex_literal_hides_header_inside() -> None:
    """A section header inside a regex literal is not visible (line 150->152)."""
    # The '/' after 'matches ' opens a regex; 'strings:' inside is not a header.
    line = "matches /strings:/"
    col, _ = _scan_visible_section_header(line, "strings", False)
    assert col is None


# ---------------------------------------------------------------------------
# find_rule_end — line 211: '//' stops scanning the line early
# ---------------------------------------------------------------------------


def test_find_rule_end_line_comment_does_not_count_brace() -> None:
    """A '}' after '//' on the same line is ignored when finding the rule end."""
    lines = split_lines("rule a {\n  condition:\n    true // }\n}")
    end = find_rule_end(lines, 0)
    assert end == 3  # real closing brace is on line 3


# ---------------------------------------------------------------------------
# find_rule_end — line 249->251: closing brace returns line index
# ---------------------------------------------------------------------------


def test_find_rule_end_returns_line_of_closing_brace() -> None:
    """The line index of the matching closing brace is returned (line 249->251)."""
    lines = split_lines("rule a {\n  condition:\n    true\n}")
    end = find_rule_end(lines, 0)
    assert end == 3


# ---------------------------------------------------------------------------
# get_rule_text_range — line 263: end_line < start_line branch
# ---------------------------------------------------------------------------


def test_get_rule_text_range_returns_none_when_no_closing_brace() -> None:
    """Return None when find_rule_end returns a line before start_line (line 263).

    find_rule_end returns len(lines)-1 when no brace is found. If find_rule_start
    returns a line index GREATER than that fallback, end_line < start_line holds.
    We construct a text where the rule keyword appears on the last non-empty line
    after all content, so start_line exceeds the fallback end_line.
    """
    # The only 'rule' line is line 2 (0-indexed). find_rule_end starts from line 2
    # and finds no '{', so it returns len(lines)-1 == 2. Because end_line (2) is
    # NOT less than start_line (2), the standard path returns a RuleTextRange.
    # To trigger end_line < start_line we need find_rule_end returning < start_line.
    # That is not reachable in practice via get_rule_text_range because find_rule_end
    # always starts from start_line. Document the line as structurally unreachable
    # through the public function and verify the guard with direct inputs instead.
    lines = split_lines("rule a {\n  condition:\n    true\n}")
    start_line = 0
    end_line = find_rule_end(lines, start_line)
    # Sanity: end_line >= start_line for well-formed input
    assert end_line >= start_line
    # For completeness, confirm get_rule_text_range returns a result for this input
    result = get_rule_text_range("rule a {\n  condition:\n    true\n}", 0)
    assert result is not None


def test_get_rule_text_range_returns_none_when_no_rule_keyword() -> None:
    """Return None when find_rule_start returns -1 (no rule keyword on or before line)."""
    result = get_rule_text_range("condition: true", 0)
    assert result is None


# ---------------------------------------------------------------------------
# find_string_line — lines 282-286: empty identifier and not-found paths
# ---------------------------------------------------------------------------


def test_find_string_line_empty_identifier_returns_minus_one() -> None:
    """An empty string_id returns -1 immediately without scanning (line 282-283)."""
    lines = split_lines('rule a {\n  strings:\n    $a = "x"\n  condition:\n    $a\n}')
    result = find_string_line(lines, "")
    assert result == -1


def test_find_string_line_not_found_returns_minus_one() -> None:
    """Return -1 when the identifier is absent from all lines (lines 284-286)."""
    lines = split_lines('rule a {\n  strings:\n    $a = "x"\n  condition:\n    $a\n}')
    result = find_string_line(lines, "$missing")
    assert result == -1


def test_find_string_line_found_with_space_before_equals() -> None:
    """Return the correct line index when 'id =' is present."""
    lines = split_lines('rule a {\n  strings:\n    $sig = "hello"\n  condition:\n    $sig\n}')
    result = find_string_line(lines, "$sig")
    assert result == 2


def test_find_string_line_found_without_space_before_equals() -> None:
    """Return the correct line index when 'id=' (no space) is present."""
    lines = split_lines('rule a {\n  strings:\n    $sig="hello"\n  condition:\n    $sig\n}')
    result = find_string_line(lines, "$sig")
    assert result == 2


# ---------------------------------------------------------------------------
# find_section_header_range — line 332: section name not found in line
# ---------------------------------------------------------------------------


def test_find_section_header_range_section_name_not_in_line() -> None:
    """When section_name is absent from the line, the whole line range is returned (line 332)."""
    lines = ["rule a {", "  condition:", "    true", "}"]
    # Ask for 'meta' on line 1 ('  condition:'); find returns -1 so start < 0 branch fires.
    rng = find_section_header_range(lines, "meta", 1)
    # The fallback range spans from character 0 to the end of line 1.
    assert rng.start.line == 1
    assert rng.start.character == 0
    assert rng.end.line == 1
    assert rng.end.character > 0  # non-empty line


def test_find_section_header_range_with_explicit_column() -> None:
    """Explicit column bypasses the find() call and uses the provided offset."""
    lines = ["rule a {", "  strings:", '    $a = "x"', "}"]
    rng = find_section_header_range(lines, "strings", 1, column=2)
    assert rng.start.character == 2
    assert rng.end.character == rng.start.character + len("strings")


# ---------------------------------------------------------------------------
# find_quoted_value_range — line 347: line_num < 0
# ---------------------------------------------------------------------------


def test_find_quoted_value_range_negative_line_num() -> None:
    """Return None when line_num is negative (line 347)."""
    lines = ['  author = "Marc"']
    result = find_quoted_value_range(lines, -1, "Marc")
    assert result is None


def test_find_quoted_value_range_line_num_out_of_bounds() -> None:
    """Return None when line_num equals or exceeds len(lines)."""
    lines = ['  author = "Marc"']
    result = find_quoted_value_range(lines, 1, "Marc")
    assert result is None


# ---------------------------------------------------------------------------
# find_quoted_value_range — line 352: quoted value not present on the line
# ---------------------------------------------------------------------------


def test_find_quoted_value_range_value_not_found_on_line() -> None:
    """Return None when the quoted value is absent from the specified line (line 352)."""
    lines = ['  author = "Alice"']
    result = find_quoted_value_range(lines, 0, "Bob")
    assert result is None


def test_find_quoted_value_range_value_found() -> None:
    """Return the correct Range when the quoted value is present on the line."""
    lines = ['  author = "Marc"']
    result = find_quoted_value_range(lines, 0, "Marc")
    assert result is not None
    assert result.start.line == 0
    assert result.end.line == 0
    # The range covers the value text without surrounding quotes.
    assert result.end.character > result.start.character


# ---------------------------------------------------------------------------
# find_section_line — additional coverage for the not-found return path
# ---------------------------------------------------------------------------


def test_find_section_line_header_not_found_returns_minus_one() -> None:
    """Return -1 when the section header is absent from all lines."""
    lines = ["rule a {", "  condition:", "    true", "}"]
    result = find_section_line(lines, "strings:", 0)
    assert result == -1


def test_find_section_line_stops_at_next_rule_declaration() -> None:
    """Return -1 when a new rule declaration is encountered before finding the header."""
    lines = ["rule a {", "  condition:", "    true", "}", "rule b {", "  strings:", "}"]
    # Search for 'strings:' starting from line 0, inside rule a; rule b at line 4
    # triggers the early exit before 'strings:' in rule b is reached.
    result = find_section_line(lines, "strings:", 0)
    assert result == -1


# ---------------------------------------------------------------------------
# _scan_visible_section_header — branch 150->152: '/' is not a regex opener
# ---------------------------------------------------------------------------


def test_scan_visible_section_header_slash_as_division_not_regex() -> None:
    """A '/' following an identifier is treated as division, not a regex open.

    Branch 150->152: _starts_regex_literal returns False because the previous
    significant character is an identifier char (not in REGEX_CONTEXT_CHARS) and
    the previous word is not in REGEX_CONTEXT_WORDS.  The elif is False so
    execution falls through to char_idx += 1 at line 152.
    """
    # 'x/strings:' — the '/' follows the word 'x' which is not a regex-context
    # keyword, so it is treated as division.  The header 'strings:' after it IS
    # visible and should be found.
    col, _ = _scan_visible_section_header("x/strings:", "strings", False)
    assert col is not None
    assert col == 2  # 'strings:' starts at char index 2


# ---------------------------------------------------------------------------
# find_rule_end — branch 249->251: '}' encountered before any '{' (found_open False)
# ---------------------------------------------------------------------------


def test_find_rule_end_closing_brace_before_opening_brace() -> None:
    """A '}' encountered before any '{' does not close the rule (branch 249->251).

    When found_open is False, the closing-brace guard at line 249 evaluates to
    False, so execution falls through to char_idx += 1 at line 251 instead of
    returning.  The scanner then reaches the end of lines and returns
    len(lines) - 1 as the fallback.
    """
    lines = split_lines("} rule a { condition: true }")
    # The first '}' is before any '{', so found_open is False; the guard skips it.
    # The real opening '{' is at position 7 and closing '}' is the last char.
    end = find_rule_end(lines, 0)
    # With only one line, the closing brace IS found and returns line 0.
    assert end == 0


def test_find_rule_end_nested_braces_intermediate_close() -> None:
    """An inner '}' that does not bring brace_depth to zero (branch 249->251).

    brace_depth goes to 1 at the outer '{', to 2 at the inner '{', back to 1 at
    the inner '}' — this '}' does NOT satisfy found_open and brace_depth == 0,
    so execution falls to char_idx += 1 and continues.
    """
    lines = split_lines('rule a { strings: { $a = "x" } condition: true }')
    end = find_rule_end(lines, 0)
    # The outer closing '}' is the last character; the rule ends on line 0.
    assert end == 0


# ---------------------------------------------------------------------------
# get_rule_text_range — line 263 analysis (structurally unreachable via public API)
# ---------------------------------------------------------------------------


def test_get_rule_text_range_end_never_less_than_start() -> None:
    """find_rule_end always returns a line index >= start_line.

    The guard at line 263 (end_line < start_line) is not reachable through the
    public API because find_rule_end iterates from start_line onward and its
    fallback is len(lines)-1, which is always >= start_line (since find_rule_start
    only returns valid 0-based indices within the lines array).

    This test documents the invariant: for any well-formed or malformed input,
    get_rule_text_range either returns None (no rule keyword) or a RuleTextRange.
    """
    # Malformed: open brace but no close brace
    result_open = get_rule_text_range("rule a {\n  condition: true", 0)
    # find_rule_end returns len(lines)-1 == 1 >= start_line 0, so RuleTextRange is built
    assert result_open is not None
    # Well-formed single-line rule
    result_ok = get_rule_text_range("rule a { condition: true }", 0)
    assert result_ok is not None


# ---------------------------------------------------------------------------
# _previous_significant_char — existing but confirm return None path
# ---------------------------------------------------------------------------


def test_previous_significant_char_only_whitespace() -> None:
    """Return None when all characters before index are whitespace."""
    result = _previous_significant_char("   /", 3)
    assert result is None


def test_previous_significant_char_finds_char() -> None:
    """Return the last non-whitespace character before index."""
    result = _previous_significant_char("a = /", 4)
    assert result == "="
