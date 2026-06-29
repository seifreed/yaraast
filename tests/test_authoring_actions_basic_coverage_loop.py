# Copyright (c) 2026 Marc Rivero López
# Licensed under GPLv3. See LICENSE file for details.
# This test suite validates real code behavior without mocks or stubs.
"""Coverage-loop tests for yaraast.lsp.authoring_actions_basic.

These tests target the lines in authoring_actions_basic.py that are not
reached by the existing test suite.

Missing-line analysis (85.63% before this file):

COVERABLE missing lines (addressed here):

  33  -- _hex_escape_byte: returns None when the two characters after \\x are
         not valid hexadecimal digits (e.g. "\\xGG").

  47-49 -- _plain_string_source_bytes: trailing lone backslash at the very end
           of the string body.  When position + 1 >= len(value) the guard
           appends the literal backslash byte and advances.

  58  -- _plain_string_source_bytes: \\x escape with invalid hex digits causes
         _hex_escape_byte to return None, so the raw two bytes b"\\x" are
         appended to the decoded buffer.

  62  -- _plain_string_source_bytes: \\r carriage-return escape decodes to
         byte 0x0D.

  68  -- _plain_string_source_bytes: unrecognised escape sequence (e.g. \\z)
         passes through as the literal two-byte sequence \\z.

  82  -- create_missing_string: returns None when find_rule_start returns -1,
         which happens when the diagnostic range points to a line that has no
         enclosing rule declaration (e.g. a top-level import statement).

  85  -- create_missing_string: returns None when find_section_line returns -1
         for "condition:", which happens when the rule has no condition section.

  89->96, 94->89 -- create_missing_string: loop inside the strings section that
         advances insert_line past each existing $-string.  Line 94 is the
         break guard that fires when the scanner encounters a non-$-string line
         that ends with ":", indicating the start of the next section.

  114 -- normalize_string_modifiers: returns None when selection.start.line is
         beyond the last line of the document.

  129 -- normalize_string_modifiers: returns None when the modifiers are already
         in the canonical order (normalize_modifiers returns the same list).

  149 -- convert_plain_string_to_hex: returns None when selection.start.line is
         beyond the last line of the document.

STRUCTURALLY UNREACHABLE via the real public API (none in this module beyond
what the existing suite already documents).
"""

from __future__ import annotations

from lsprotocol.types import Position, Range

from yaraast.lsp.authoring_actions_basic import (
    _hex_escape_byte,
    _plain_string_source_bytes,
    convert_plain_string_to_hex,
    create_missing_string,
    normalize_string_modifiers,
)

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _range(line: int, char_start: int = 0, char_end: int = 0) -> Range:
    return Range(
        start=Position(line=line, character=char_start),
        end=Position(line=line, character=char_end),
    )


# ---------------------------------------------------------------------------
# _hex_escape_byte — line 33 (return None for invalid hex digits)
# ---------------------------------------------------------------------------


def test_hex_escape_byte_returns_none_for_non_hex_digits() -> None:
    # "\\xGG" — position 0 means hex_start = 2, hex_digits = "GG"
    # "G" is not a valid hex character, so the function must return None.
    result = _hex_escape_byte("\\xGG", 0)
    assert result is None


def test_hex_escape_byte_returns_none_when_too_short() -> None:
    # Only one character after \\x: len(hex_digits) < 2, must return None.
    result = _hex_escape_byte("\\x4", 0)
    assert result is None


def test_hex_escape_byte_returns_none_at_end_of_string() -> None:
    # Position points past the last character so there are 0 hex digits.
    result = _hex_escape_byte("\\x", 0)
    assert result is None


# ---------------------------------------------------------------------------
# _plain_string_source_bytes — lines 47-49 (trailing lone backslash)
# ---------------------------------------------------------------------------


def test_plain_string_source_bytes_trailing_backslash() -> None:
    # A string body that ends with a lone backslash must survive and append
    # the raw backslash byte (0x5C) without raising an IndexError.
    result = _plain_string_source_bytes("a\\")
    assert result == b"a\\"


def test_plain_string_source_bytes_only_backslash() -> None:
    # A string body consisting of a single backslash.
    result = _plain_string_source_bytes("\\")
    assert result == b"\\"


# ---------------------------------------------------------------------------
# _plain_string_source_bytes — line 58 (\\x with invalid hex, append b"\\x")
# ---------------------------------------------------------------------------


def test_plain_string_source_bytes_invalid_hex_escape_passthrough() -> None:
    # "\\xGG" — _hex_escape_byte returns None so the raw bytes b"\\x" are
    # appended and the scanner then continues from the character after \\x
    # (position advances by 2).  The two "G" characters are then processed
    # as ordinary characters.
    result = _plain_string_source_bytes("\\xGG")
    assert result == b"\\xGG"


def test_plain_string_source_bytes_incomplete_hex_at_end() -> None:
    # "\\x4" — only one hex digit after \\x so _hex_escape_byte returns None.
    # The raw b"\\x" bytes are appended, then "4" is appended as a plain char.
    result = _plain_string_source_bytes("\\x4")
    assert result == b"\\x4"


# ---------------------------------------------------------------------------
# _plain_string_source_bytes — line 62 (\\r -> 0x0D)
# ---------------------------------------------------------------------------


def test_plain_string_source_bytes_carriage_return_escape() -> None:
    result = _plain_string_source_bytes("\\r")
    assert result == b"\r"


def test_plain_string_source_bytes_mixed_with_carriage_return() -> None:
    # Validates that \\r in the middle of a string decodes correctly alongside
    # other characters and escape sequences.
    result = _plain_string_source_bytes("a\\rb")
    assert result == b"a\rb"


# ---------------------------------------------------------------------------
# _plain_string_source_bytes — line 68 (unknown escape -> literal \\z)
# ---------------------------------------------------------------------------


def test_plain_string_source_bytes_unknown_escape_passthrough() -> None:
    # "\\z" is not a known YARA escape sequence; the two-byte literal is kept.
    result = _plain_string_source_bytes("\\z")
    assert result == b"\\z"


def test_plain_string_source_bytes_unknown_escape_in_context() -> None:
    # Unknown escape in the middle of a plain string.
    result = _plain_string_source_bytes("a\\zb")
    assert result == b"a\\zb"


# ---------------------------------------------------------------------------
# create_missing_string — line 82 (rule_start < 0, return None)
# ---------------------------------------------------------------------------


def test_create_missing_string_returns_none_outside_any_rule() -> None:
    # An import statement at line 0 with no enclosing rule block.  The
    # diagnostic range points to line 0 so find_rule_start returns -1.
    text = 'import "pe"\n\nrule r {\n    condition:\n        true\n}\n'
    result = create_missing_string(text, "$missing", _range(0, 0, 11))
    assert result is None


def test_create_missing_string_returns_none_for_empty_document() -> None:
    # An empty document has no rule declarations at all.
    result = create_missing_string("", "$x", _range(0, 0, 0))
    assert result is None


# ---------------------------------------------------------------------------
# create_missing_string — line 85 (condition_line < 0, return None)
# ---------------------------------------------------------------------------


def test_create_missing_string_returns_none_when_no_condition_section() -> None:
    # A rule block that has a rule keyword but no "condition:" line.  The
    # scanner will find rule_start >= 0 but condition_line will be -1.
    text = 'rule broken {\n    strings:\n        $a = "x"\n}\n'
    # Line 0 is the rule declaration; line 2 is inside the rule.
    result = create_missing_string(text, "$b", _range(2, 0, 0))
    assert result is None


# ---------------------------------------------------------------------------
# create_missing_string — lines 89->96, 94->89
# (loop over existing strings, break on next section header)
# ---------------------------------------------------------------------------


def test_create_missing_string_inserts_after_last_existing_string() -> None:
    # A rule with a strings section containing one existing string definition
    # followed by the condition section.  The loop must advance insert_line
    # past the existing $a entry (line 89 / 92 path) and then break when it
    # sees "condition:" (line 94 path).
    text = 'rule demo {\n    strings:\n        $a = "x"\n    condition:\n        $missing\n}\n'
    # diagnostic range points into the condition body (line 4)
    result = create_missing_string(text, "$missing", _range(4, 8, 16))
    assert result is not None
    # The new string must be inserted between $a and the condition section,
    # so its range must start at line 3 (one past the $a line).
    assert result.edit.range.start.line == 3
    assert '$missing = ""' in result.edit.new_text


def test_create_missing_string_inserts_after_multiple_existing_strings() -> None:
    # A strings section with two existing entries: $a and $b.  The loop
    # must step past both (advancing insert_line twice) then break on
    # "condition:".
    text = (
        "rule multi {\n"
        "    strings:\n"
        '        $a = "x"\n'
        '        $b = "y"\n'
        "    condition:\n"
        "        $missing\n"
        "}\n"
    )
    result = create_missing_string(text, "$missing", _range(5, 8, 16))
    assert result is not None
    # Insert line must be 4 (one past $b at line 3).
    assert result.edit.range.start.line == 4
    assert '$missing = ""' in result.edit.new_text


def test_create_missing_string_preview_mentions_strings_section() -> None:
    # When a strings section already exists the preview must say "strings".
    text = 'rule preview {\n    strings:\n        $a = "x"\n    condition:\n        $missing\n}\n'
    result = create_missing_string(text, "$missing", _range(4, 8, 16))
    assert result is not None
    assert result.preview is not None
    assert "strings" in result.preview


def test_create_missing_string_loop_exhausts_without_break() -> None:
    # Branch arc 89->96: the for-loop that scans lines after "strings:"
    # completes all iterations without hitting break.  This happens when the
    # closing "}" of the rule appears after all $-string lines (the brace
    # does not end with ":" so line 94 is False, giving 94->89) and then the
    # range is exhausted, giving 89->96.
    #
    # A YARA rule where "condition:" appears BEFORE "strings:" is unusual but
    # syntactically accepted by the scanner; the section-finder locates both
    # independently.  After finding strings_line=3, the loop covers line 4
    # ($a, continue) and line 5 ("}", 94 is False giving 94->89), then the
    # range is exhausted (89->96) and execution falls through to line 96.
    text = 'rule r {\n    condition:\n        $x\n    strings:\n        $a = "x"\n}\n'
    result = create_missing_string(text, "$x", _range(2, 8, 10))
    assert result is not None
    # insert_line must be 5 (one past the $a on line 4)
    assert result.edit.range.start.line == 5
    assert '$x = ""' in result.edit.new_text


def test_create_missing_string_loop_continues_past_non_section_line() -> None:
    # Branch arc 94->89: a line in the strings section body that does not
    # start with "$" and does not end with ":" causes neither continue nor
    # break to fire; execution returns to the top of the for loop (89).
    # A blank line between the last $-string and "condition:" is such a line.
    text = 'rule r {\n    strings:\n        $a = "x"\n\n    condition:\n        $x\n}\n'
    result = create_missing_string(text, "$x", _range(5, 8, 10))
    assert result is not None
    # insert_line must be 3 (one past $a at line 2); the blank at line 3
    # triggers 94->89 and then "condition:" triggers the break.
    assert result.edit.range.start.line == 3
    assert '$x = ""' in result.edit.new_text


# ---------------------------------------------------------------------------
# normalize_string_modifiers — line 114 (line_num >= len(lines), return None)
# ---------------------------------------------------------------------------


def test_normalize_string_modifiers_returns_none_for_out_of_range_line() -> None:
    # A single-line document; requesting line 10 must return None immediately.
    text = 'rule r { strings: $a = "x" ascii wide  condition: $a }'
    result = normalize_string_modifiers(text, _range(10, 0, 0))
    assert result is None


def test_normalize_string_modifiers_returns_none_for_empty_document() -> None:
    result = normalize_string_modifiers("", _range(5, 0, 0))
    assert result is None


# ---------------------------------------------------------------------------
# normalize_string_modifiers — line 129 (modifiers already normalized)
# ---------------------------------------------------------------------------


def test_normalize_string_modifiers_returns_none_when_already_normalized() -> None:
    # "ascii wide" is the correct canonical order per PREFERRED_MODIFIER_ORDER;
    # normalize_modifiers will return the same list so the function returns None.
    text = 'rule r {\n    strings:\n        $a = "x" ascii wide\n    condition:\n        $a\n}\n'
    result = normalize_string_modifiers(text, _range(2, 8, 28))
    assert result is None


def test_normalize_string_modifiers_returns_none_for_single_modifier() -> None:
    # A single modifier cannot be reordered or deduplicated.
    text = 'rule r {\n    strings:\n        $a = "x" ascii\n    condition:\n        $a\n}\n'
    result = normalize_string_modifiers(text, _range(2, 8, 22))
    assert result is None


# ---------------------------------------------------------------------------
# convert_plain_string_to_hex — line 149 (line_num >= len(lines), return None)
# ---------------------------------------------------------------------------


def test_convert_plain_string_to_hex_returns_none_for_out_of_range_line() -> None:
    # Request conversion on a line number that does not exist in the document.
    text = 'rule r {\n    strings:\n        $a = "abc"\n    condition:\n        $a\n}\n'
    result = convert_plain_string_to_hex(text, _range(99, 0, 0))
    assert result is None


def test_convert_plain_string_to_hex_returns_none_for_empty_document() -> None:
    result = convert_plain_string_to_hex("", _range(3, 0, 0))
    assert result is None


# ---------------------------------------------------------------------------
# Regression: valid paths still work after the new edge-case inputs above
# ---------------------------------------------------------------------------


def test_plain_string_source_bytes_known_escapes_still_correct() -> None:
    # Confirm that the well-exercised escape paths produce the expected bytes
    # so that the new test additions above have not accidentally broken them.
    assert _plain_string_source_bytes("\\n") == b"\n"
    assert _plain_string_source_bytes("\\t") == b"\t"
    assert _plain_string_source_bytes('\\"') == b'"'
    assert _plain_string_source_bytes("\\\\") == b"\\"
    assert _plain_string_source_bytes("\\x41") == b"A"
    assert _plain_string_source_bytes("\\xFF") == b"\xff"


def test_hex_escape_byte_valid_digits_still_correct() -> None:
    assert _hex_escape_byte("\\x41rest", 0) == 0x41
    assert _hex_escape_byte("\\xFF", 0) == 0xFF
    assert _hex_escape_byte("\\x00", 0) == 0x00
