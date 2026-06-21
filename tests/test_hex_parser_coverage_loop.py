# Copyright (c) 2026 Marc Rivero López
# Licensed under GPLv3. See LICENSE file for details.
# This test suite validates real code behavior without mocks or stubs.

"""Regression tests targeting previously uncovered lines in hex_parser.py.

Each test exercises a real code path through the production HexStringParser
class, using actual hex-pattern strings to trigger specific branches.  No
mocks, stubs, or artificial scaffolding are used.  Every assertion validates
observable return values or exception state produced by real execution.
"""

from __future__ import annotations

import pytest

from yaraast.ast.strings import (
    HexAlternative,
    HexByte,
    HexJump,
    HexNegatedByte,
    HexNibble,
    HexToken,
    HexWildcard,
)
from yaraast.limits import LIBYARA_HEX_JUMP_MAX
from yaraast.parser.hex_parser import HexParseError, HexStringParser

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _parser() -> HexStringParser:
    """Return a fresh HexStringParser with no context token."""
    return HexStringParser(error_token=None)


def _parse(content: str, *, validate_placement: bool = True) -> list[HexToken]:
    """Parse *content* through the real parser and return the token list."""
    return _parser().parse(content, validate_placement=validate_placement)


# ---------------------------------------------------------------------------
# Line 97 / 103-104 — invalid character in top-level hex string (parse())
# ---------------------------------------------------------------------------


def test_invalid_character_in_hex_string_raises() -> None:
    """A non-hex, non-structural character in the pattern body triggers
    the 'Invalid character in hex string' branch (lines 103-104)."""
    with pytest.raises(HexParseError, match="Invalid character in hex string"):
        _parse("AB @@ CD")


def test_invalid_character_semicolon_raises() -> None:
    """Semicolons are not valid in hex strings; the error message includes
    the offending character."""
    with pytest.raises(HexParseError, match="Invalid character in hex string: ;"):
        _parse("AB;CD")


# ---------------------------------------------------------------------------
# Lines 122-125 — _validate_jump_placement: jump at first position
# ---------------------------------------------------------------------------


def test_jump_at_start_of_pattern_raises() -> None:
    """A jump as the first token is rejected by the placement validator
    (lines 123-125).  validate_placement=True is the default."""
    with pytest.raises(HexParseError, match="Invalid jump placement"):
        _parse("[1-3] AB CD")


def test_jump_at_end_of_pattern_raises() -> None:
    """A jump as the last token is also rejected (same branch, last-element
    check on line 123)."""
    with pytest.raises(HexParseError, match="Invalid jump placement"):
        _parse("AB CD [1-3]")


# ---------------------------------------------------------------------------
# Lines 129-130 — _validate_jump_placement: unbounded jump inside alternative
# ---------------------------------------------------------------------------


def test_unbounded_jump_inside_alternative_raises() -> None:
    """An unbounded jump [n-] cannot appear inside an alternative group
    (lines 129-130).  The pattern (AB [1-] CD) exercises this branch."""
    with pytest.raises(HexParseError, match="Unbounded jump not allowed inside alternative"):
        _parse("AA (AB [1-] CD | EF) BB")


# ---------------------------------------------------------------------------
# Lines 154-165 — _remove_comments: unterminated block comment
# ---------------------------------------------------------------------------


def test_unterminated_block_comment_raises() -> None:
    """A block comment that is never closed raises HexParseError
    (lines 163-165)."""
    with pytest.raises(HexParseError, match="Unterminated comment in hex string"):
        _parse("AB /* open comment CD")


# ---------------------------------------------------------------------------
# Lines 203-204 — _parse_hex_byte: next char is neither '?' nor hex
# ---------------------------------------------------------------------------


def test_hex_byte_followed_by_invalid_char_raises() -> None:
    """When the second nibble of a hex byte is neither '?' nor a hex digit,
    _parse_hex_byte raises the 'Invalid hex byte' error (lines 203-204)."""
    with pytest.raises(HexParseError, match="Invalid hex byte"):
        _parse("AZ")


# ---------------------------------------------------------------------------
# Lines 264-265 — _validate_jump_bounds: negative min_jump
# ---------------------------------------------------------------------------


def test_negative_lower_bound_in_jump_range_raises() -> None:
    """validate_placement=False bypasses placement rules; the bounds check
    catches the negative value (lines 263-265).  YARA jump syntax does not
    allow negative integers, so we drive the validator directly."""
    parser = _parser()
    with pytest.raises(HexParseError, match="Invalid jump range"):
        parser._validate_jump_bounds(-1, 5)


# ---------------------------------------------------------------------------
# Lines 267-268 — _validate_jump_bounds: negative max_jump
# ---------------------------------------------------------------------------


def test_negative_upper_bound_in_jump_range_raises() -> None:
    """A negative max_jump is rejected by the bounds validator (lines 266-268).
    min_jump=None so only the max branch fires."""
    parser = _parser()
    with pytest.raises(HexParseError, match="Invalid jump range"):
        parser._validate_jump_bounds(None, -1)


# ---------------------------------------------------------------------------
# Lines 272-273 — _validate_jump_bounds: jump exceeds LIBYARA_HEX_JUMP_MAX
# ---------------------------------------------------------------------------


def test_jump_exceeding_libyara_max_raises() -> None:
    """When a jump bound exceeds LIBYARA_HEX_JUMP_MAX the validator raises
    'Invalid jump length' (lines 269-273)."""
    overflow = LIBYARA_HEX_JUMP_MAX + 1
    jump_content = f"AB [{overflow}] CD"
    with pytest.raises(HexParseError, match="Invalid jump length"):
        _parse(jump_content)


def test_jump_at_max_allowed_is_accepted() -> None:
    """The boundary value LIBYARA_HEX_JUMP_MAX itself must be accepted."""
    tokens = _parse(f"AB [{LIBYARA_HEX_JUMP_MAX}] CD")
    assert isinstance(tokens[1], HexJump)
    assert tokens[1].min_jump == LIBYARA_HEX_JUMP_MAX


# ---------------------------------------------------------------------------
# Lines 285-286 — _parse_alternative: guard when char is not '('
# ---------------------------------------------------------------------------


def test_parse_alternative_guard_when_not_open_paren() -> None:
    """Calling _parse_alternative directly with the position pointing at a
    non-'(' character raises the guard error (lines 284-286)."""
    parser = _parser()
    parser.content = "AB CD EF"
    parser.pos = 0  # points at 'A', not '('
    with pytest.raises(HexParseError, match="Expected '\\(' at start of alternative"):
        parser._parse_alternative()


# ---------------------------------------------------------------------------
# Lines 302-303 — _parse_alternative: empty branch before ')'
# ---------------------------------------------------------------------------


def test_empty_alternative_branch_before_close_paren_raises() -> None:
    """An empty branch immediately before ')' is invalid (lines 306-308
    inside the ')' handler).  The pattern (|AB) triggers this."""
    with pytest.raises(HexParseError, match="Empty alternative branch"):
        _parse("AA (AB |) BB")


# ---------------------------------------------------------------------------
# Line 322 — _parse_alternative: empty branch before '|'
# ---------------------------------------------------------------------------


def test_empty_alternative_branch_before_pipe_raises() -> None:
    """A pipe with no preceding tokens creates an empty branch (lines 315-317).
    The pattern starts with '|' so the first branch is empty."""
    with pytest.raises(HexParseError, match="Empty alternative branch"):
        _parse("AA (| AB) BB")


# ---------------------------------------------------------------------------
# Lines 343-344 — _parse_alternative: unterminated group (no closing ')')
# ---------------------------------------------------------------------------


def test_unterminated_alternative_group_raises() -> None:
    """An alternative group that is never closed raises 'Unterminated
    alternative' (lines 333-335)."""
    with pytest.raises(HexParseError, match="Unterminated alternative"):
        _parse("AA (AB | CD")


# ---------------------------------------------------------------------------
# Lines 351-354 — _parse_negated_byte: nibble patterns ~?X and ~X?
# ---------------------------------------------------------------------------


def test_negated_low_nibble_pattern_is_parsed() -> None:
    """~?A matches any byte whose low nibble is 0xA.  The branch at
    line 351-354 handles the (char1=='?' and char2 in HEX_CHARS) case."""
    tokens = _parse("~?A")
    assert len(tokens) == 1
    assert isinstance(tokens[0], HexNegatedByte)
    assert tokens[0].value == "?A"


def test_negated_high_nibble_pattern_is_parsed() -> None:
    """~A? matches any byte whose high nibble is 0xA.  The branch at
    line 351-354 handles the (char1 in HEX_CHARS and char2=='?') case."""
    tokens = _parse("~A?")
    assert len(tokens) == 1
    assert isinstance(tokens[0], HexNegatedByte)
    assert tokens[0].value == "A?"


def test_negated_nibble_inside_alternative() -> None:
    """~?B and ~B? also work inside alternatives (exercises the branch in
    the alternative parser and the negated-nibble code together)."""
    tokens = _parse("AA (~?B | ~B?) CC")
    assert isinstance(tokens[0], HexByte)
    alt = tokens[1]
    assert isinstance(alt, HexAlternative)
    left_branch = alt.alternatives[0]
    right_branch = alt.alternatives[1]
    assert isinstance(left_branch[0], HexNegatedByte)
    assert left_branch[0].value == "?B"
    assert isinstance(right_branch[0], HexNegatedByte)
    assert right_branch[0].value == "B?"


# ---------------------------------------------------------------------------
# Lines 375-376 — _parse_wildcard: lone '?' not followed by '?' or hex digit
# ---------------------------------------------------------------------------


def test_wildcard_not_followed_by_valid_char_raises() -> None:
    """A '?' followed by an invalid character (not '?' and not a hex digit)
    triggers the 'Invalid wildcard' error (lines 375-376).  Using '?' at
    end-of-content also exercises this branch because the lookahead fails."""
    with pytest.raises(HexParseError, match="Invalid wildcard"):
        _parse("AB ?Z")


def test_wildcard_at_end_of_content_raises() -> None:
    """A lone '?' at the very end of content (no lookahead character) also
    falls through to the 'Invalid wildcard' error path."""
    with pytest.raises(HexParseError, match="Invalid wildcard"):
        _parse("AB ?")


# ---------------------------------------------------------------------------
# Positive round-trip tests for already-covered paths — regression anchors
# ---------------------------------------------------------------------------


def test_simple_hex_bytes_round_trip() -> None:
    """A basic sequence of hex bytes parses to HexByte tokens with correct
    integer values."""
    tokens = _parse("DE AD BE EF")
    assert len(tokens) == 4
    assert all(isinstance(t, HexByte) for t in tokens)
    values = [t.value for t in tokens]  # type: ignore[attr-defined]
    assert values == [0xDE, 0xAD, 0xBE, 0xEF]


def test_wildcard_parsed_correctly() -> None:
    """?? is parsed as a single HexWildcard token."""
    tokens = _parse("AB ?? CD")
    assert isinstance(tokens[1], HexWildcard)


def test_high_nibble_parsed_correctly() -> None:
    """A? is parsed as HexNibble with high=True and the correct value."""
    tokens = _parse("A?")
    assert isinstance(tokens[0], HexNibble)
    assert tokens[0].high is True
    assert tokens[0].value == 0xA


def test_low_nibble_parsed_correctly() -> None:
    """?A is parsed as HexNibble with high=False and the correct value."""
    tokens = _parse("?A")
    assert isinstance(tokens[0], HexNibble)
    assert tokens[0].high is False
    assert tokens[0].value == 0xA


def test_bounded_jump_parsed_correctly() -> None:
    """[1-5] is parsed as HexJump with correct bounds."""
    tokens = _parse("AB [1-5] CD")
    assert isinstance(tokens[1], HexJump)
    assert tokens[1].min_jump == 1
    assert tokens[1].max_jump == 5


def test_exact_jump_parsed_correctly() -> None:
    """[3] is parsed as HexJump with min_jump == max_jump == 3."""
    tokens = _parse("AB [3] CD")
    jump = tokens[1]
    assert isinstance(jump, HexJump)
    assert jump.min_jump == 3
    assert jump.max_jump == 3


def test_alternative_parsed_correctly() -> None:
    """(AB | CD) is parsed as a two-branch HexAlternative."""
    tokens = _parse("AA (AB | CD) EE")
    alt = tokens[1]
    assert isinstance(alt, HexAlternative)
    assert len(alt.alternatives) == 2


def test_negated_byte_parsed_correctly() -> None:
    """~FF is parsed as HexNegatedByte with the correct integer value."""
    tokens = _parse("~FF")
    assert isinstance(tokens[0], HexNegatedByte)
    assert tokens[0].value == 0xFF


def test_single_line_comment_removed() -> None:
    """A // comment up to newline is stripped; remaining bytes still parse."""
    tokens = _parse("AB // this is a comment\nCD")
    assert len(tokens) == 2
    assert isinstance(tokens[0], HexByte)
    assert isinstance(tokens[1], HexByte)


def test_block_comment_removed() -> None:
    """A closed /* ... */ block comment is collapsed to a space."""
    tokens = _parse("AB /* ignored */ CD")
    assert len(tokens) == 2


def test_empty_string_raises() -> None:
    """An empty hex pattern raises 'Empty hex string'."""
    with pytest.raises(HexParseError, match="Empty hex string"):
        _parse("")


def test_validate_placement_false_skips_placement_check() -> None:
    """With validate_placement=False a leading jump is accepted without error."""
    tokens = _parse("[1-3] AB", validate_placement=False)
    assert isinstance(tokens[0], HexJump)


def test_nested_alternatives_parsed_correctly() -> None:
    """A nested alternative group ((AB | CD) | EF) must parse without error
    and yield an outer HexAlternative whose first branch is also an
    HexAlternative."""
    tokens = _parse("AA ((AB | CD) | EF) BB")
    outer = tokens[1]
    assert isinstance(outer, HexAlternative)
    nested = outer.alternatives[0][0]
    assert isinstance(nested, HexAlternative)


# ---------------------------------------------------------------------------
# Line 88 — parse(): trailing whitespace after final token
# ---------------------------------------------------------------------------


def test_trailing_whitespace_after_tokens_is_skipped() -> None:
    """When the entire remaining content after the last token is whitespace,
    _skip_whitespace() exhausts self.content and the guard at line 87-88
    fires the break, cleanly ending the loop."""
    tokens = _parse("AB CD   \t\n")
    assert len(tokens) == 2
    assert isinstance(tokens[0], HexByte)
    assert isinstance(tokens[1], HexByte)


# ---------------------------------------------------------------------------
# Line 122 — _validate_jump_placement: empty token list is a no-op
# ---------------------------------------------------------------------------


def test_validate_jump_placement_with_empty_list_returns_none() -> None:
    """_validate_jump_placement([]) must return immediately (line 121-122)
    without raising; the empty-list guard is the only return path."""
    parser = _parser()
    # _validate_jump_placement returns None implicitly when the list is empty;
    # the test goal is that no exception is raised, not to inspect a return value.
    parser._validate_jump_placement([], in_alternative=False)


# ---------------------------------------------------------------------------
# Lines 186-187 — _parse_hex_byte: single hex char at end of content
# ---------------------------------------------------------------------------


def test_incomplete_hex_byte_single_char_raises() -> None:
    """A single hex character at the end of input is an incomplete byte;
    the length guard at line 185-187 raises 'Incomplete hex byte'."""
    with pytest.raises(HexParseError, match="Incomplete hex byte"):
        _parse("A")


# ---------------------------------------------------------------------------
# Lines 220-221 — _parse_jump: unterminated jump (no closing ']')
# ---------------------------------------------------------------------------


def test_unterminated_jump_raises() -> None:
    """A '[' with no matching ']' triggers 'Unterminated jump' (lines 219-221)."""
    with pytest.raises(HexParseError, match="Unterminated jump in hex string"):
        _parse("AB [1-3 CD", validate_placement=False)


# ---------------------------------------------------------------------------
# Lines 241-242 — _parse_jump_range: more than one '-' in jump string
# ---------------------------------------------------------------------------


def test_jump_range_with_multiple_dashes_raises() -> None:
    """A jump string like '1-2-3' has three parts after split('-'), which
    triggers the len(parts) != 2 check (lines 240-242)."""
    with pytest.raises(HexParseError, match="Invalid jump range"):
        _parse("AB [1-2-3] CD", validate_placement=False)


# ---------------------------------------------------------------------------
# Lines 244-245 — _parse_jump_range: empty first part with non-empty second
#   i.e., "-N" where N > 0 is treated as invalid (not a legal YARA jump)
# ---------------------------------------------------------------------------


def test_jump_range_empty_lower_bound_non_empty_upper_raises() -> None:
    """A range like '-5' has an empty first part and a non-empty second part,
    which is explicitly rejected at lines 243-245."""
    with pytest.raises(HexParseError, match="Invalid jump range"):
        _parse("AB [-5] CD", validate_placement=False)


# ---------------------------------------------------------------------------
# Lines 253-254 — _parse_jump_range: zero exact jump is invalid
# ---------------------------------------------------------------------------


def test_zero_length_exact_jump_raises() -> None:
    """[0] is an invalid jump length (lines 252-254)."""
    with pytest.raises(HexParseError, match="Invalid jump length"):
        _parse("AB [0] CD", validate_placement=False)


# ---------------------------------------------------------------------------
# Lines 258-259 — _parse_jump_range: non-numeric jump string
# ---------------------------------------------------------------------------


def test_non_numeric_jump_string_raises() -> None:
    """A jump string containing non-numeric characters falls through to the
    ValueError handler (lines 257-259)."""
    with pytest.raises(HexParseError, match="Invalid jump range"):
        _parse("AB [abc] CD", validate_placement=False)


# ---------------------------------------------------------------------------
# Lines 275-276 — _validate_jump_bounds: min_jump > max_jump
# ---------------------------------------------------------------------------


def test_jump_range_min_greater_than_max_raises() -> None:
    """A range where min > max is rejected (lines 274-276)."""
    with pytest.raises(HexParseError, match="Invalid jump range"):
        _parse("AB [5-3] CD", validate_placement=False)


# ---------------------------------------------------------------------------
# Line 296 — _parse_alternative: whitespace exhausts content inside group
# ---------------------------------------------------------------------------


def test_whitespace_only_inside_alternative_hits_break_then_unterminated() -> None:
    """Content inside an alternative that is pure whitespace after the '('
    exhausts the position via _skip_whitespace(); the guard at line 295-296
    fires the break, then 'not closed' triggers 'Unterminated alternative'."""
    with pytest.raises(HexParseError, match="Unterminated alternative"):
        _parse("AA (   ", validate_placement=False)


# ---------------------------------------------------------------------------
# Line 326 — _parse_alternative: '?' inside alternative (wildcard branch)
# ---------------------------------------------------------------------------


def test_wildcard_inside_alternative_is_parsed() -> None:
    """A '?' wildcard token inside an alternative triggers the '?' branch
    at line 325-326 in _parse_alternative, reusing _parse_wildcard."""
    tokens = _parse("AA (?? | AB) BB")
    alt = tokens[1]
    assert isinstance(alt, HexAlternative)
    assert isinstance(alt.alternatives[0][0], HexWildcard)


# ---------------------------------------------------------------------------
# Lines 330-331 — _parse_alternative: invalid character inside alternative
# ---------------------------------------------------------------------------


def test_invalid_character_in_alternative_raises() -> None:
    """A character that is not a recognised token inside an alternative triggers
    'Invalid character in hex alternative' (lines 330-331)."""
    with pytest.raises(HexParseError, match="Invalid character in hex alternative"):
        _parse("AA (AB | @CD) BB")


# ---------------------------------------------------------------------------
# Lines 343-344 — _parse_negated_byte: only one char left after '~'
# ---------------------------------------------------------------------------


def test_incomplete_negated_byte_only_one_char_remaining_raises() -> None:
    """After consuming '~', if only one character remains the length check
    at line 342-344 raises 'Incomplete negated hex byte'."""
    with pytest.raises(HexParseError, match="Incomplete negated hex byte"):
        _parse("~A")


# ---------------------------------------------------------------------------
# Lines 355-356 — _parse_negated_byte: chars after '~' are not valid patterns
# ---------------------------------------------------------------------------


def test_invalid_negated_byte_pattern_raises() -> None:
    """When both chars after '~' are not a valid hex-byte or nibble pattern
    (e.g., '??' which is a wildcard, not a negated nibble), the error at
    lines 355-356 is raised."""
    with pytest.raises(HexParseError, match="Invalid negated hex byte"):
        _parse("~??")


def test_invalid_negated_byte_non_hex_chars_raise() -> None:
    """Two non-hex characters after '~' also hit the invalid pattern error."""
    with pytest.raises(HexParseError, match="Invalid negated hex byte"):
        _parse("~ZZ")
