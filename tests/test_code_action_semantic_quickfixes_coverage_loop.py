"""
Copyright (c) 2026 Marc Rivero López
Licensed under GPLv3. See LICENSE file for details.
This test suite validates real code behavior without mocks or stubs.

Regression tests that raise coverage of
yaraast.lsp.code_action_semantic_quickfixes to ~100 % by exercising
every branch that the existing test suite leaves uncovered.

All tests call the production functions directly with real inputs and
assert on the observed return values.  No mocks, no stubs, no
suppressions.
"""

from __future__ import annotations

from lsprotocol.types import Diagnostic, Position, Range

from yaraast.lsp.code_action_semantic_quickfixes import (
    _find_diagnostic_call_close,
    _find_diagnostic_occurrence,
    _find_matching_call_close_in_lines,
    _split_top_level_arguments,
    create_add_missing_arguments_action,
    create_add_placeholder_argument_action,
    create_rename_duplicate_action,
    create_replace_builtin_function_actions,
    create_replace_module_function_actions,
    create_trim_arguments_action,
)

# ---------------------------------------------------------------------------
# Helpers shared across tests
# ---------------------------------------------------------------------------


def _diag(line: int, start: int, end: int, msg: str = "x") -> Diagnostic:
    return Diagnostic(
        range=Range(
            start=Position(line=line, character=start),
            end=Position(line=line, character=end),
        ),
        message=msg,
    )


URI = "file://test.yar"


# ---------------------------------------------------------------------------
# _find_matching_call_close_in_lines
# ---------------------------------------------------------------------------


def test_find_matching_call_close_returns_none_when_no_closing_paren() -> None:
    """Line 93: the function exhausts all lines without finding ')' → returns None."""
    lines = ["fn(abc"]
    result = _find_matching_call_close_in_lines(lines, 0, 2)
    assert result is None


def test_find_matching_call_close_handles_block_comment_spanning_full_line() -> None:
    """Line 70: block comment has no '*/' on its start line; the inner loop breaks
    and moves to the next line where the comment ends before ')' is found."""
    lines = ["fn(/* comment without close", "still open"]
    # Both lines are exhausted without a ')' → None
    result = _find_matching_call_close_in_lines(lines, 0, 2)
    assert result is None


def test_find_matching_call_close_handles_block_comment_that_closes_on_next_line() -> None:
    """Verify that a block comment whose '*/' appears on a later line does not
    swallow the closing parenthesis on that same line."""
    lines = ["fn(/* start", "end */ a)"]
    result = _find_matching_call_close_in_lines(lines, 0, 2)
    # The ')' is on line 1, column 8
    assert result == (1, 8)


# ---------------------------------------------------------------------------
# _find_diagnostic_call_close
# ---------------------------------------------------------------------------


def test_find_diagnostic_call_close_returns_none_when_line_out_of_range() -> None:
    """Line 103: diagnostic points to a line beyond the document → None."""
    result = _find_diagnostic_call_close(["single line"], "fn", _diag(99, 0, 5))
    assert result is None


def test_find_diagnostic_call_close_returns_none_when_needle_absent() -> None:
    """Line 117: the needle 'fn(' is not in the line → break → return fallback (None)."""
    result = _find_diagnostic_call_close(["no match here"], "fn", _diag(0, 0, 5))
    assert result is None


def test_find_diagnostic_call_close_returns_fallback_when_overlap_check_misses() -> None:
    """Lines 120-128: close is not None for the first occurrence but the range
    overlap check excludes it; there is no second occurrence so fallback is returned."""
    # Arrange: diagnostic at (0, 5, 5) — zero-width after the call 'fn(a)'.
    # start_col=0, range_end=5: 0 < 5 is True, but close_col=4, close_col+1=5 > range_start=5
    # is False → overlap check fails → fall through to search_start update → no more occurrences
    # → return fallback which equals the first call span.
    lines = ["fn(a)"]
    diag = _diag(0, 5, 5)
    result = _find_diagnostic_call_close(lines, "fn", diag)
    # fallback is the first (and only) call span found
    assert result == (0, 2, 0, 4)


def test_find_diagnostic_call_close_skips_unclosed_first_occurrence() -> None:
    """Arc 120->127: first 'fn(' has no matching ')'; close is None → skip the if-body
    (line 120 → line 127) and advance search_start; the second 'fn(' is closed and matched."""
    # 'fn( nope fn(ok)' — first fn( at col 0 has no close; second fn( at col 9 has ')' at col 14.
    lines = ["fn( nope fn(ok)"]
    diag = _diag(0, 9, 15)
    result = _find_diagnostic_call_close(lines, "fn", diag)
    assert result == (9, 11, 0, 14)


# ---------------------------------------------------------------------------
# _find_diagnostic_occurrence
# ---------------------------------------------------------------------------


def test_find_diagnostic_occurrence_returns_fallback_when_no_range_overlap() -> None:
    """Lines 142 + 147: the needle is found in the line, but every occurrence lies
    outside the diagnostic range; the inner loop eventually gets start_col < 0
    (line 142 break) and the function returns fallback (line 147)."""
    # 'fn' is at col 4; diagnostic range is col 12-13 (past the end of 'fn')
    line = "abc fn(x) abc"
    diag = _diag(0, 12, 13)
    # fallback is the first find() result = 4
    result = _find_diagnostic_occurrence(line, "fn", diag)
    assert result == 4


# ---------------------------------------------------------------------------
# _split_top_level_arguments
# ---------------------------------------------------------------------------


def test_split_top_level_arguments_handles_line_comment_without_trailing_newline() -> None:
    """Line 163: '//' comment that reaches the end of the string (no newline) → break."""
    result = _split_top_level_arguments("a // no newline")
    # Everything after '//' is part of the comment; only 'a' appears before it
    assert result == ["a // no newline"]


def test_split_top_level_arguments_handles_block_comment_without_close() -> None:
    """Line 169: '/*' whose '*/' never appears → break."""
    result = _split_top_level_arguments("a /* no close")
    assert result == ["a /* no close"]


# ---------------------------------------------------------------------------
# create_replace_module_function_actions
# ---------------------------------------------------------------------------


def test_replace_module_function_actions_empty_when_no_alternatives() -> None:
    """Line 225: available_functions is empty → early return []."""
    result = create_replace_module_function_actions(
        "pe.entry_point == 0", _diag(0, 0, 14), URI, "pe", "entry_point", []
    )
    assert result == []


def test_replace_module_function_actions_empty_when_line_out_of_range() -> None:
    """Line 230: diagnostic line number exceeds document → []."""
    result = create_replace_module_function_actions(
        "single line", _diag(99, 0, 5), URI, "pe", "fn", ["other_fn"]
    )
    assert result == []


def test_replace_module_function_actions_empty_when_needle_absent() -> None:
    """Line 235: module.function not present on the diagnostic line → []."""
    result = create_replace_module_function_actions(
        "condition: true", _diag(0, 0, 9), URI, "pe", "fn", ["other_fn"]
    )
    assert result == []


def test_replace_module_function_actions_produces_actions() -> None:
    """Happy path: needle is on the diagnostic line → one action per suggestion (capped at 3)."""
    line = "condition: pe.bad_fn == 0"
    result = create_replace_module_function_actions(
        line, _diag(0, 11, 18), URI, "pe", "bad_fn", ["good_fn", "also_fn"]
    )
    assert len(result) == 2
    assert result[0].title == "Replace with pe.good_fn"
    assert result[1].title == "Replace with pe.also_fn"


# ---------------------------------------------------------------------------
# create_replace_builtin_function_actions
# ---------------------------------------------------------------------------


def test_replace_builtin_function_actions_empty_when_no_suggestions() -> None:
    """Line 270: suggested_functions is empty → early return []."""
    result = create_replace_builtin_function_actions("uint8(0)", _diag(0, 0, 5), URI, "uint8", [])
    assert result == []


def test_replace_builtin_function_actions_empty_when_line_out_of_range() -> None:
    """Line 275: diagnostic line exceeds document length → []."""
    result = create_replace_builtin_function_actions(
        "line0", _diag(99, 0, 5), URI, "uint8", ["uint16"]
    )
    assert result == []


def test_replace_builtin_function_actions_empty_when_function_not_on_line() -> None:
    """Line 280: function_name not found on the line → []."""
    result = create_replace_builtin_function_actions(
        "condition: true", _diag(0, 0, 9), URI, "uint8", ["uint16"]
    )
    assert result == []


def test_replace_builtin_function_actions_produces_actions() -> None:
    """Happy path: function is on the diagnostic line → one action per suggestion."""
    line = "condition: uint8(0) == 0"
    result = create_replace_builtin_function_actions(
        line, _diag(0, 11, 16), URI, "uint8", ["uint16", "uint32"]
    )
    assert len(result) == 2
    assert result[0].title == "Replace with uint16()"
    assert result[1].title == "Replace with uint32()"


# ---------------------------------------------------------------------------
# create_add_placeholder_argument_action
# ---------------------------------------------------------------------------


def test_add_placeholder_argument_empty_when_line_out_of_range() -> None:
    """Line 318: diagnostic line exceeds document → []."""
    result = create_add_placeholder_argument_action("line0", _diag(99, 0, 5), URI, "fn")
    assert result == []


def test_add_placeholder_argument_empty_when_call_not_found() -> None:
    """Line 322: no call of 'fn(' on the line → call_span is None → []."""
    result = create_add_placeholder_argument_action("condition: true", _diag(0, 0, 9), URI, "fn")
    assert result == []


def test_add_placeholder_argument_empty_when_args_already_present() -> None:
    """Line 326: args_text is non-empty (call already has arguments) → []."""
    result = create_add_placeholder_argument_action("fn(existing)", _diag(0, 0, 12), URI, "fn")
    assert result == []


def test_add_placeholder_argument_produces_action() -> None:
    """Happy path: empty call → produces a single action inserting '0'."""
    result = create_add_placeholder_argument_action("fn()", _diag(0, 0, 4), URI, "fn")
    assert len(result) == 1
    assert result[0].title == "Add placeholder argument to fn()"
    assert result[0].edit is not None


# ---------------------------------------------------------------------------
# create_add_missing_arguments_action
# ---------------------------------------------------------------------------


def test_add_missing_arguments_empty_when_count_is_zero() -> None:
    """Line 353: missing_count == 0 → early return []."""
    result = create_add_missing_arguments_action("fn(a)", _diag(0, 0, 5), URI, "fn", 0)
    assert result == []


def test_add_missing_arguments_empty_when_count_is_negative() -> None:
    """Line 353: missing_count < 0 → early return []."""
    result = create_add_missing_arguments_action("fn(a)", _diag(0, 0, 5), URI, "fn", -1)
    assert result == []


def test_add_missing_arguments_empty_when_line_out_of_range() -> None:
    """Line 357: diagnostic line exceeds document → []."""
    result = create_add_missing_arguments_action("line0", _diag(99, 0, 5), URI, "fn", 1)
    assert result == []


def test_add_missing_arguments_empty_when_call_not_found() -> None:
    """Line 360: 'fn(' not present on the diagnostic line → []."""
    result = create_add_missing_arguments_action("no call here", _diag(0, 0, 5), URI, "fn", 1)
    assert result == []


def test_add_missing_arguments_produces_action_with_single_arg() -> None:
    """Happy path — empty call, one argument to add; insertion has no leading comma."""
    result = create_add_missing_arguments_action("fn()", _diag(0, 0, 4), URI, "fn", 1)
    assert len(result) == 1
    assert "fn()" in result[0].title
    edit = result[0].edit
    assert edit is not None
    changes = edit.changes
    assert changes is not None
    text_edits = list(changes[URI])
    assert text_edits[0].new_text == "0"


def test_add_missing_arguments_produces_action_with_existing_arg() -> None:
    """Line 364: close_paren > open_paren + 1 → insertion gains leading ', '."""
    result = create_add_missing_arguments_action("fn(a)", _diag(0, 0, 5), URI, "fn", 2)
    assert len(result) == 1
    edit = result[0].edit
    assert edit is not None
    changes = edit.changes
    assert changes is not None
    inserted = next(iter(changes[URI])).new_text
    assert inserted.startswith(", ")


def test_add_missing_arguments_multiline_call_uses_prepend_comma() -> None:
    """Line 363: close_line > line_num → insertion prepends ', '."""
    text = "fn(\n)"
    result = create_add_missing_arguments_action(text, _diag(0, 0, 4), URI, "fn", 2)
    assert len(result) == 1
    edit = result[0].edit
    assert edit is not None
    changes = edit.changes
    assert changes is not None
    inserted = next(iter(changes[URI])).new_text
    assert inserted.startswith(", ")


# ---------------------------------------------------------------------------
# create_trim_arguments_action
# ---------------------------------------------------------------------------


def test_trim_arguments_empty_when_line_out_of_range() -> None:
    """Line 398: diagnostic line exceeds document → []."""
    result = create_trim_arguments_action("line0", _diag(99, 0, 5), URI, "fn", 1)
    assert result == []


def test_trim_arguments_empty_when_keep_args_negative() -> None:
    """Line 398 (keep_args < 0 branch): keep_args=-1 → []."""
    result = create_trim_arguments_action("fn(a, b)", _diag(0, 0, 8), URI, "fn", -1)
    assert result == []


def test_trim_arguments_empty_when_call_not_found() -> None:
    """Line 402: 'fn(' not in the text → call_span is None → []."""
    result = create_trim_arguments_action("no call", _diag(0, 0, 7), URI, "fn", 1)
    assert result == []


def test_trim_arguments_empty_when_parts_le_keep_args() -> None:
    """Line 408: call has fewer or equal arguments than keep_args → nothing to trim → []."""
    result = create_trim_arguments_action("fn(a)", _diag(0, 0, 5), URI, "fn", 5)
    assert result == []


def test_trim_arguments_produces_action() -> None:
    """Happy path: 'fn(a, b, c)' keeping 1 arg → action with new_text 'a'."""
    result = create_trim_arguments_action("fn(a, b, c)", _diag(0, 0, 11), URI, "fn", 1)
    assert len(result) == 1
    assert result[0].title == "Remove extra argument(s) from fn()"
    edit = result[0].edit
    assert edit is not None
    changes = edit.changes
    assert changes is not None
    new_text = next(iter(changes[URI])).new_text
    assert new_text == "a"


# ---------------------------------------------------------------------------
# create_rename_duplicate_action
# ---------------------------------------------------------------------------


def test_rename_duplicate_empty_when_identifier_is_bare_dollar() -> None:
    """Line 461: identifier == '$' → base_name is '' after removeprefix → early return []."""
    result = create_rename_duplicate_action(
        'rule a { strings: $a = "x" condition: $a }',
        _diag(0, 0, 5),
        URI,
        "$",
    )
    assert result == []


def test_rename_duplicate_empty_when_col_not_found_on_line() -> None:
    """Line 461: identifier has a valid base_name but is not present on the
    diagnostic line → _find_diagnostic_occurrence returns -1 → []."""
    # The text has no '$missing_var' on line 0
    text = "rule a { condition: true }"
    result = create_rename_duplicate_action(text, _diag(0, 0, 1), URI, "$missing_var")
    assert result == []


def test_rename_duplicate_produces_action_and_skips_existing_suffix() -> None:
    """Confirms that the counter skips already-used suffixes when building the new name."""
    text = (
        'rule a {\n  strings:\n    $a = "x"\n    $a_2 = "y"\n    $a = "z"\n  condition:\n    $a\n}'
    )
    diag = _diag(4, 4, 6, "Duplicate string identifier '$a'")
    result = create_rename_duplicate_action(text, diag, URI, "$a")
    assert len(result) == 1
    assert result[0].title == "Rename to $a_3"
