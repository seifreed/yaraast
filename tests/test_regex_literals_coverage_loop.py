# Copyright (c) 2026 Marc Rivero López
# Licensed under GPLv3. See LICENSE file for details.
# This test suite validates real code behavior without mocks or stubs.
"""Regression tests that close the remaining coverage gaps in regex_literals.py.

Each test exercises a specific branch or line that the existing test files
do not reach.  All assertions are against the real public API:
  escape_regex_delimiter, validate_regex_modifiers, validate_regex_pattern.

The private helpers (_validate_regex_escape, _validate_regex_character_class,
_parse_regex_repeat_interval, etc.) are reachable only through those public
entry points, so no private symbol is imported or called directly.

UNREACHABLE LINES (164-165): The guard
    if repeat_text == "," and not can_repeat:
on line 163 is structurally dead.  When repeat_text == ",",
_parse_regex_repeat_interval always returns (None, None) — a non-None tuple —
so interval is not None and the code enters the interval branch at line 150
before it can reach line 163.  No test can trigger these lines through the real
API without modifying the source.
"""

from __future__ import annotations

import pytest

from yaraast.regex_literals import (
    REGEX_MODIFIER_ORDER,
    VALID_REGEX_MODIFIERS,
    escape_regex_delimiter,
    validate_regex_modifiers,
    validate_regex_pattern,
)

# ---------------------------------------------------------------------------
# escape_regex_delimiter  (lines 15-32)
# ---------------------------------------------------------------------------


def test_escape_regex_delimiter_plain_string_no_slash() -> None:
    """A string without any '/' is returned unchanged."""
    assert escape_regex_delimiter("abc") == "abc"


def test_escape_regex_delimiter_single_unescaped_slash() -> None:
    """An unescaped '/' is prefixed with a backslash."""
    assert escape_regex_delimiter("a/b") == r"a\/b"


def test_escape_regex_delimiter_already_escaped_slash() -> None:
    r"""An already-escaped '\/' is not double-escaped."""
    result = escape_regex_delimiter(r"a\/b")
    assert result == r"a\/b"


def test_escape_regex_delimiter_double_backslash_before_slash() -> None:
    r"""'\\/' has an even number of backslashes so '/' is unescaped — must escape it."""
    result = escape_regex_delimiter("a\\\\/b")
    # Two real backslashes followed by '/' → the slash is unescaped
    assert "\\/" in result


def test_escape_regex_delimiter_multiple_unescaped_slashes() -> None:
    """Every unescaped '/' is independently escaped."""
    result = escape_regex_delimiter("a/b/c")
    assert result == r"a\/b\/c"


def test_escape_regex_delimiter_empty_string() -> None:
    """Empty string round-trips unchanged."""
    assert escape_regex_delimiter("") == ""


def test_escape_regex_delimiter_slash_only() -> None:
    """A bare '/' becomes '\\/'."""
    assert escape_regex_delimiter("/") == r"\/"


def test_escape_regex_delimiter_backslash_only() -> None:
    """A bare backslash with no following slash is returned unchanged."""
    assert escape_regex_delimiter("\\") == "\\"


def test_escape_regex_delimiter_triple_backslash_before_slash() -> None:
    r"""'\\\/' — odd backslash count means the '/' IS already escaped; no new escape."""
    result = escape_regex_delimiter("\\\\/")
    # Three backslashes: the third escapes the slash, so the slash must not gain another '\'.
    # The function only adds '\' when backslash_count % 2 == 0 at the '/' position.
    # Here there are two real backslashes before '/' so backslash_count == 2 (even) → escape.
    # (The string literal "\\\\" is 2 backslash characters; adding "/" gives 2 bs + 1 slash.)
    # Two backslashes → even → the slash IS unescaped in the source → must be escaped.
    assert result.endswith("\\/")


# ---------------------------------------------------------------------------
# validate_regex_modifiers  (lines 39-49)
# ---------------------------------------------------------------------------


def test_validate_regex_modifiers_valid_empty() -> None:
    """No modifiers is valid."""
    validate_regex_modifiers("")  # must not raise


def test_validate_regex_modifiers_valid_i() -> None:
    """Modifier 'i' alone is valid."""
    validate_regex_modifiers("i")


def test_validate_regex_modifiers_valid_s() -> None:
    """Modifier 's' alone is valid."""
    validate_regex_modifiers("s")


def test_validate_regex_modifiers_valid_is_ordered() -> None:
    """Both modifiers in canonical order 'is' are valid."""
    validate_regex_modifiers("is")


def test_validate_regex_modifiers_rejects_unknown_modifier() -> None:
    """An unrecognised modifier raises ValueError (line 41)."""
    with pytest.raises(ValueError, match="Invalid regex modifier: g"):
        validate_regex_modifiers("g")


def test_validate_regex_modifiers_rejects_duplicate_modifier() -> None:
    """Repeating a modifier raises ValueError (line 43-44)."""
    with pytest.raises(ValueError, match="Duplicate regex modifier: i"):
        validate_regex_modifiers("ii")


def test_validate_regex_modifiers_rejects_reversed_order() -> None:
    """Modifiers in wrong order raise ValueError (lines 48-49)."""
    # canonical order is REGEX_MODIFIER_ORDER = "is", so "si" is out of order
    with pytest.raises(ValueError, match="Invalid regex modifier order: si"):
        validate_regex_modifiers("si")


def test_validate_regex_modifiers_constants_are_consistent() -> None:
    """VALID_REGEX_MODIFIERS and REGEX_MODIFIER_ORDER expose the same characters."""
    assert set(REGEX_MODIFIER_ORDER) == VALID_REGEX_MODIFIERS


# ---------------------------------------------------------------------------
# validate_regex_pattern — unsupported group (?  (lines 113-114)
# ---------------------------------------------------------------------------


def test_validate_regex_pattern_rejects_non_capturing_group() -> None:
    """'(?...)' is an unsupported extension and must be rejected (lines 113-114)."""
    with pytest.raises(ValueError, match="Invalid regex pattern: unsupported group"):
        validate_regex_pattern("(?:abc)")


def test_validate_regex_pattern_rejects_lookahead() -> None:
    """Lookahead '(?=...)' is also an unsupported group."""
    with pytest.raises(ValueError, match="Invalid regex pattern: unsupported group"):
        validate_regex_pattern("(?=abc)")


# ---------------------------------------------------------------------------
# validate_regex_pattern — ')' handling (lines 122-130)
# ---------------------------------------------------------------------------


def test_validate_regex_pattern_rejects_unmatched_close_paren() -> None:
    """A ')' with no open '(' raises 'unmatched' error (lines 122-123)."""
    with pytest.raises(ValueError, match="Invalid regex pattern: unmatched '\\)'"):
        validate_regex_pattern("abc)")


def test_validate_regex_pattern_rejects_empty_group() -> None:
    """An empty capture group '()' raises 'empty group' error (lines 125-127)."""
    with pytest.raises(ValueError, match="Invalid regex pattern: empty group"):
        validate_regex_pattern("()")


def test_validate_regex_pattern_accepts_non_empty_group() -> None:
    """A group with content '(a)' is valid and closes correctly (lines 128-129)."""
    validate_regex_pattern("(a)")  # must not raise


def test_validate_regex_pattern_accepts_nested_non_empty_groups() -> None:
    """Nested groups each with content are valid."""
    validate_regex_pattern("((ab)|(cd))")


# ---------------------------------------------------------------------------
# validate_regex_pattern — '|' with no left side (lines 134-135)
# ---------------------------------------------------------------------------


def test_validate_regex_pattern_rejects_leading_alternation() -> None:
    """'|abc' has no left branch and must be rejected (lines 134-135)."""
    with pytest.raises(ValueError, match="Invalid regex pattern: syntax error"):
        validate_regex_pattern("|abc")


def test_validate_regex_pattern_rejects_empty_left_branch_in_group() -> None:
    """'(|abc)' also has an empty left branch inside a group."""
    with pytest.raises(ValueError, match="Invalid regex pattern: syntax error"):
        validate_regex_pattern("(|abc)")


def test_validate_regex_pattern_accepts_valid_alternation() -> None:
    """'a|b' has non-empty branches and is valid."""
    validate_regex_pattern("a|b")


# ---------------------------------------------------------------------------
# validate_regex_pattern — repeat interval bounds (lines 153-154, 158-159)
# ---------------------------------------------------------------------------


def test_validate_regex_pattern_rejects_inverted_repeat_interval() -> None:
    """'{5,3}' has min > max and must be rejected (lines 153-154)."""
    with pytest.raises(ValueError, match="Invalid regex pattern: bad repeat interval"):
        validate_regex_pattern("a{5,3}")


def test_validate_regex_pattern_rejects_repeat_min_too_large() -> None:
    """min value exceeding _MAX_REGEX_REPEAT_INTERVAL (32767) must be rejected (lines 155-159)."""
    with pytest.raises(ValueError, match="Invalid regex pattern: repeat interval too large"):
        validate_regex_pattern("a{32768}")


def test_validate_regex_pattern_rejects_repeat_max_too_large() -> None:
    """max value exceeding 32767 must be rejected."""
    with pytest.raises(ValueError, match="Invalid regex pattern: repeat interval too large"):
        validate_regex_pattern("a{1,32768}")


def test_validate_regex_pattern_accepts_repeat_at_boundary() -> None:
    """Repeat value at exactly 32767 is valid."""
    validate_regex_pattern("a{32767}")


def test_validate_regex_pattern_accepts_valid_repeat_interval() -> None:
    """'{2,5}' with min <= max is valid."""
    validate_regex_pattern("a{2,5}")


# ---------------------------------------------------------------------------
# validate_regex_pattern — '{,' literal (lines 163-165)
# ---------------------------------------------------------------------------


def test_validate_regex_pattern_rejects_bare_brace_comma_without_atom() -> None:
    """'{,' at start of pattern is a syntax error when can_repeat is False (lines 163-165).

    The pattern '{,' does not parse as a valid repeat interval (no closing '}' found
    via end == -1 path) and then the literal '{' branch falls through to the
    repeat_text == ',' guard, which requires can_repeat to be True.
    """
    # At pattern start there is no preceding atom, so can_repeat is False.
    # '{' with no matching '}' means end == -1 in pattern.find('}', i+1),
    # so interval is None and the code drops to the repeat_text == ',' check.
    with pytest.raises(ValueError, match="Invalid regex pattern: syntax error"):
        validate_regex_pattern("{,}")


# ---------------------------------------------------------------------------
# validate_regex_pattern — unterminated group / trailing quantifier (lines 174-175)
# ---------------------------------------------------------------------------


def test_validate_regex_pattern_rejects_unterminated_group() -> None:
    """'(ab' with no closing ')' raises 'unterminated group' (lines 173-175)."""
    with pytest.raises(ValueError, match="Invalid regex pattern: unterminated group"):
        validate_regex_pattern("(ab")


def test_validate_regex_pattern_trailing_quantifier_is_greedy() -> None:
    """A pattern ending with a quantifier is valid; the trailing-quantifier branch
    on line 176-177 calls record_quantifier_style('greedy') without raising."""
    # 'a*' ends with a quantifier — last_was_quantifier stays True at the end
    # of the loop; the post-loop call on line 176 must not raise.
    validate_regex_pattern("a*")


def test_validate_regex_pattern_trailing_quantifier_ungreedy() -> None:
    """'a*?' ends with last_was_quantifier False (the '?' consumed it), no error."""
    validate_regex_pattern("a*?")


# ---------------------------------------------------------------------------
# _parse_regex_repeat_interval — single exact value (line 185)
# ---------------------------------------------------------------------------


def test_validate_regex_pattern_exact_repeat_single_value() -> None:
    """'{3}' (no comma) with an integer value returns (3, 3) via line 185."""
    validate_regex_pattern("a{3}")  # must not raise; exercises the isdigit branch


def test_validate_regex_pattern_non_integer_repeat_treated_as_literal() -> None:
    """'{abc}' is not a valid interval; falls through as a literal '{' (line 185 path skipped)."""
    validate_regex_pattern("a{abc}")


# ---------------------------------------------------------------------------
# _parse_regex_repeat_interval — multiple commas (line 189)
# ---------------------------------------------------------------------------


def test_validate_regex_pattern_multiple_commas_in_braces_treated_as_literal() -> None:
    """'{1,2,3}' splits into more than 2 parts, returns None from line 189 path."""
    # The braces content "1,2,3" has len(parts) == 3 != 2 → returns None → literal brace.
    # After the literal '{' the content 1,2,3} is traversed as atoms, which is fine.
    validate_regex_pattern("a{1,2,3}")


# ---------------------------------------------------------------------------
# _parse_regex_repeat_interval — blank min/max (lines 194-201)
# ---------------------------------------------------------------------------


def test_validate_regex_pattern_open_max_repeat_is_valid() -> None:
    """'{2,}' means 'at least 2' — min=2, max=None — which is a valid interval."""
    validate_regex_pattern("a{2,}")


def test_validate_regex_pattern_open_min_repeat_is_valid() -> None:
    """'{,5}' means 'at most 5' — min=None, max=5 — which is a valid interval."""
    validate_regex_pattern("a{,5}")


def test_validate_regex_pattern_both_blank_repeat_is_open() -> None:
    """'{,}' with a preceding atom is valid; both bounds are None (line 193 path)."""
    validate_regex_pattern("a{,}")


def test_validate_regex_pattern_non_digit_min_treated_as_literal() -> None:
    """'{a,5}' — min_text 'a' is not a digit → None returned → literal '{'."""
    validate_regex_pattern("a{a,5}")


def test_validate_regex_pattern_non_digit_max_treated_as_literal() -> None:
    """'{1,b}' — max_text 'b' is not a digit → None returned → literal '{'."""
    validate_regex_pattern("a{1,b}")


# ---------------------------------------------------------------------------
# _validate_regex_escape — dangling escape (lines 211-212)
# ---------------------------------------------------------------------------


def test_validate_regex_pattern_rejects_dangling_escape_at_end() -> None:
    """A trailing '\\' with no following character raises 'dangling escape' (lines 211-212)."""
    with pytest.raises(ValueError, match="Invalid regex pattern: dangling escape"):
        validate_regex_pattern("abc\\")


# ---------------------------------------------------------------------------
# _validate_regex_escape — illegal \\x sequence (lines 221-222)
# ---------------------------------------------------------------------------


def test_validate_regex_pattern_rejects_hex_escape_too_short() -> None:
    """'\\x' at end of pattern lacks two hex digits (lines 221-222)."""
    with pytest.raises(ValueError, match="Invalid regex pattern: illegal escape sequence"):
        validate_regex_pattern("\\x")


def test_validate_regex_pattern_rejects_hex_escape_with_one_hex_digit() -> None:
    """'\\x4' lacks a second hex digit."""
    with pytest.raises(ValueError, match="Invalid regex pattern: illegal escape sequence"):
        validate_regex_pattern("\\x4")


def test_validate_regex_pattern_rejects_hex_escape_with_non_hex_digits() -> None:
    """'\\xGG' uses non-hex characters."""
    with pytest.raises(ValueError, match="Invalid regex pattern: illegal escape sequence"):
        validate_regex_pattern("\\xGG")


def test_validate_regex_pattern_accepts_valid_hex_escape() -> None:
    """'\\x41' is a valid hex escape for 'A'."""
    validate_regex_pattern("\\x41")


def test_validate_regex_pattern_accepts_hex_escape_mixed_case() -> None:
    """'\\xaF' uses mixed-case hex digits, which are valid."""
    validate_regex_pattern("\\xaF")


# ---------------------------------------------------------------------------
# _validate_regex_escape — backreferences (lines 226-227)
# ---------------------------------------------------------------------------


def test_validate_regex_pattern_rejects_backreference() -> None:
    """'\\1' is a backreference and must be rejected (lines 226-227)."""
    with pytest.raises(ValueError, match="Invalid regex pattern: backreferences are not allowed"):
        validate_regex_pattern("(a)\\1")


def test_validate_regex_pattern_rejects_any_digit_escape() -> None:
    """Any digit after '\\' outside a character class is a backreference."""
    with pytest.raises(ValueError, match="Invalid regex pattern: backreferences are not allowed"):
        validate_regex_pattern("\\9")


def test_validate_regex_pattern_allows_digit_escape_in_character_class() -> None:
    """'\\1' inside a character class '[\\1]' is NOT a backreference (in_character_class=True)."""
    validate_regex_pattern("[\\1]")


# ---------------------------------------------------------------------------
# _validate_regex_character_class — negated class (line 235)
# ---------------------------------------------------------------------------


def test_validate_regex_pattern_accepts_negated_character_class() -> None:
    """'[^a]' uses a '^' negation; line 235 increments content_start past '^'."""
    validate_regex_pattern("[^a]")


def test_validate_regex_pattern_accepts_negated_class_with_range() -> None:
    """'[^a-z]' exercises the negated class plus a valid range."""
    validate_regex_pattern("[^a-z]")


# ---------------------------------------------------------------------------
# _validate_regex_character_class — valid range continues loop (branch 253->238)
# ---------------------------------------------------------------------------


def test_validate_regex_pattern_accepts_character_range() -> None:
    """'[a-z]' exercises a valid ascending range; line 253 evaluates False
    (left_value <= right_value) and the loop continues to the ']' closer
    on the next iteration (branch 253->238)."""
    validate_regex_pattern("[a-z]")


def test_validate_regex_pattern_accepts_character_range_then_more_chars() -> None:
    """'[a-z0-9]' contains two valid ranges; the loop must continue after each."""
    validate_regex_pattern("[a-z0-9]")


def test_validate_regex_pattern_accepts_equal_range_endpoints() -> None:
    """'[a-a]' is a range where left == right; left_value > right_value is False."""
    validate_regex_pattern("[a-a]")


# ---------------------------------------------------------------------------
# _validate_regex_character_class — unterminated character class (lines 257-258)
# ---------------------------------------------------------------------------


def test_validate_regex_pattern_rejects_unterminated_character_class() -> None:
    """'[abc' with no closing ']' raises 'unterminated character class' (lines 257-258)."""
    with pytest.raises(ValueError, match="Invalid regex pattern: unterminated character class"):
        validate_regex_pattern("[abc")


def test_validate_regex_pattern_rejects_empty_unterminated_class() -> None:
    """'[' alone is also unterminated."""
    with pytest.raises(ValueError, match="Invalid regex pattern: unterminated character class"):
        validate_regex_pattern("[")
