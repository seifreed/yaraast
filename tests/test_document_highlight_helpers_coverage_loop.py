"""
Regression tests targeting the uncovered branches in
yaraast/lsp/document_highlight_helpers.py (lines 51-52, 83-84, 86-87,
92, 106, 117-118).

Copyright (c) 2026 Marc Rivero López
Licensed under GPLv3. See LICENSE file for details.
This test suite validates real code behavior without mocks or stubs.

Each test drives real production code through the specific branch being
covered and asserts on observable return values.  No mocking frameworks
or test doubles are used.
"""

from __future__ import annotations

from lsprotocol.types import DocumentHighlightKind

from yaraast.lsp.document_highlight_helpers import (
    _is_string_definition_occurrence,
    highlight_identifier,
    highlight_string_identifier,
)

# ---------------------------------------------------------------------------
# Lines 51-52  — highlight_identifier skips in-string / in-comment tokens
# ---------------------------------------------------------------------------


def test_highlight_identifier_skips_occurrence_inside_string_literal() -> None:
    """Line 51-52: _is_code_occurrence returns False → col = end_idx; continue.

    'alpha' appears once inside a double-quoted string (non-code) and once as
    a bare identifier.  Only the bare occurrence must be returned.
    """
    text = 'rule r {\n  condition:\n    "alpha" and alpha\n}'
    results = highlight_identifier(text, "alpha")
    lines_hit = {h.range.start.line for h in results}
    # The in-string occurrence (line 2, before 'and') must be absent.
    # The bare occurrence (after 'and') must be present.
    assert len(results) == 1
    assert lines_hit == {2}
    # The bare 'alpha' starts after '    "alpha" and '
    assert results[0].range.start.character == text.splitlines()[2].index("alpha", 10)


def test_highlight_identifier_skips_occurrence_inside_line_comment() -> None:
    """Line 51-52: identifier inside a // comment is non-code and must be skipped."""
    text = "rule r {\n  condition:\n    // beta\n    beta\n}"
    results = highlight_identifier(text, "beta")
    # Only the bare 'beta' on line 3 should be found.
    assert len(results) == 1
    assert results[0].range.start.line == 3


def test_highlight_identifier_multiple_non_code_occurrences_all_skipped() -> None:
    """Line 51-52: every in-comment token is skipped; only bare tokens returned."""
    text = "rule r {\n  condition:\n    // gamma gamma\n    gamma\n}"
    results = highlight_identifier(text, "gamma")
    assert len(results) == 1
    assert results[0].range.start.line == 3


# ---------------------------------------------------------------------------
# Lines 83-84  — highlight_string_identifier boundary fail for a pattern
# ---------------------------------------------------------------------------


def test_highlight_string_identifier_skips_embedded_count_prefix() -> None:
    """Lines 83-84: _is_identifier_boundary returns False → col = end_idx; continue.

    '#abc' contains '#a' but 'b' immediately follows, violating the identifier
    boundary.  The longer token must not produce a highlight for '$a'.
    """
    text = 'rule r {\n  strings:\n    $a = "x"\n  condition:\n    #abc > 0 and #a > 0\n}'
    results = highlight_string_identifier(text, "$a")
    condition_line = text.splitlines()[4]
    char_positions = {h.range.start.character for h in results if h.range.start.line == 4}
    # '#abc' starts at position 4; that occurrence must be absent.
    abc_start = condition_line.index("#abc")
    assert abc_start not in char_positions
    # '#a > 0' starts after '#abc > 0 and '; that occurrence must be present.
    valid_start = condition_line.index("#a", abc_start + 4)
    assert valid_start in char_positions


def test_highlight_string_identifier_skips_embedded_at_prefix() -> None:
    """Lines 83-84: '@ab' is not a boundary-clean match for '$a' → skipped."""
    text = 'rule r {\n  strings:\n    $a = "x"\n  condition:\n    @ab[0] == @a[0]\n}'
    results = highlight_string_identifier(text, "$a")
    condition_line = text.splitlines()[4]
    char_positions = {h.range.start.character for h in results if h.range.start.line == 4}
    at_ab_start = condition_line.index("@ab")
    assert at_ab_start not in char_positions
    valid_at_start = condition_line.index("@a[")
    assert valid_at_start in char_positions


def test_highlight_string_identifier_skips_embedded_dollar_prefix() -> None:
    """Lines 83-84: '$ab' does not match boundary for '$a' → skipped."""
    text = 'rule r {\n  strings:\n    $a = "x"\n    $ab = "y"\n  condition:\n    $ab and $a\n}'
    results = highlight_string_identifier(text, "$a")
    condition_line = text.splitlines()[5]
    char_positions = {h.range.start.character for h in results if h.range.start.line == 5}
    dollar_ab_start = condition_line.index("$ab")
    assert dollar_ab_start not in char_positions
    dollar_a_start = condition_line.index("$a", dollar_ab_start + 3)
    assert dollar_a_start in char_positions


# ---------------------------------------------------------------------------
# Lines 86-87  — highlight_string_identifier skips non-code occurrences
# ---------------------------------------------------------------------------


def test_highlight_string_identifier_skips_dollar_in_string_value() -> None:
    """Lines 86-87: _is_code_occurrence returns False → col = end_idx; continue.

    '$a' embedded inside a quoted string value is non-code and must be skipped.
    """
    text = 'rule r {\n  strings:\n    $a = "$a literal"\n  condition:\n    $a\n}'
    results = highlight_string_identifier(text, "$a")
    line_numbers = {h.range.start.line for h in results}
    # Line 2: '$a = "$a literal"' — the '$a' inside the quoted value is non-code.
    # Only the definition occurrence (also on line 2, but at col 4) and the
    # condition occurrence (line 4) should appear.
    assert 4 in line_numbers
    # The in-string '$a' starts at col 10 on line 2; ensure it is absent.
    strings_line = text.splitlines()[2]
    in_string_char = strings_line.index("$a", strings_line.index('"'))
    definition_char = strings_line.index("$a")
    chars_on_line_2 = {h.range.start.character for h in results if h.range.start.line == 2}
    assert in_string_char not in chars_on_line_2
    assert definition_char in chars_on_line_2


def test_highlight_string_identifier_skips_count_in_line_comment() -> None:
    """Lines 86-87: '#a' inside a // comment is non-code and must be skipped."""
    text = 'rule r {\n  strings:\n    $a = "x"\n  condition:\n    // #a is special\n    #a > 0\n}'
    results = highlight_string_identifier(text, "$a")
    line_numbers = {h.range.start.line for h in results}
    # Line 4 is the comment; line 5 has the real '#a'.
    assert 4 not in line_numbers
    assert 5 in line_numbers


# ---------------------------------------------------------------------------
# Line 92  — highlight_string_identifier assigns Write kind for definition
# ---------------------------------------------------------------------------


def test_highlight_string_identifier_assigns_write_kind_for_definition() -> None:
    """Line 92: a '$'-prefixed occurrence in the strings section with '=' following
    receives DocumentHighlightKind.Write; uses in the condition receive Read.
    """
    text = 'rule r {\n  strings:\n    $msg = "hello"\n  condition:\n    $msg and $msg\n}'
    results = highlight_string_identifier(text, "$msg")
    kinds_by_line = {h.range.start.line: h.kind for h in results}
    # Line 2 is the definition; must be Write.
    assert kinds_by_line[2] == DocumentHighlightKind.Write
    # Line 4 occurrences must be Read.
    read_results = [h for h in results if h.range.start.line == 4]
    assert all(h.kind == DocumentHighlightKind.Read for h in read_results)


def test_highlight_string_identifier_write_kind_not_assigned_outside_strings_section() -> None:
    """Line 92: '$x' in the condition section does NOT get Write kind even when
    the rule has a strings section, because it is not a definition occurrence.
    """
    text = 'rule r {\n  strings:\n    $x = "val"\n  condition:\n    $x\n}'
    results = highlight_string_identifier(text, "$x")
    condition_results = [h for h in results if h.range.start.line == 4]
    assert condition_results
    assert all(h.kind == DocumentHighlightKind.Read for h in condition_results)


# ---------------------------------------------------------------------------
# Line 106  — _is_string_definition_occurrence when rule_text_range is None
# ---------------------------------------------------------------------------


def test_is_string_definition_occurrence_returns_false_outside_any_rule() -> None:
    """Line 106: get_rule_text_range returns None for a line not inside a rule block.

    The function must return False immediately without attempting to access
    rule_text_range fields.
    """
    text = "some random text without a rule block"
    result = _is_string_definition_occurrence(text, 0, 4)
    assert result is False


def test_is_string_definition_occurrence_returns_false_for_blank_document() -> None:
    """Line 106: empty document has no rule context → returns False."""
    result = _is_string_definition_occurrence("", 0, 0)
    assert result is False


def test_is_string_definition_occurrence_returns_false_for_line_before_rule() -> None:
    """Line 106: a header comment before any rule has no enclosing rule block."""
    text = "// global header\nrule r {\n  condition:\n    true\n}"
    result = _is_string_definition_occurrence(text, 0, 4)
    assert result is False


# ---------------------------------------------------------------------------
# Lines 117-118  — _is_string_definition_occurrence True/False return paths
# ---------------------------------------------------------------------------


def test_is_string_definition_occurrence_true_when_equals_follows_in_strings_section() -> None:
    """Lines 117-118: string identifier in the strings section followed by '=' → True."""
    text = 'rule r {\n  strings:\n    $a = "val"\n  condition:\n    $a\n}'
    strings_line = text.splitlines()[2]
    end_idx = strings_line.index("$a") + len("$a")
    result = _is_string_definition_occurrence(text, 2, end_idx)
    assert result is True


def test_is_string_definition_occurrence_false_when_no_equals_in_strings_section() -> None:
    """Lines 117-118: identifier in strings section but NOT followed by '=' → False.

    This exercises the lstrip().startswith('=') check returning False.
    The end_idx is placed past the end of the identifier and the rest of the
    line does not start with '=' (it starts with a space-then-comment).
    """
    # Use a line where '$a' appears but is followed by a comment, not '='.
    # We construct a strings section line where the raw content after the
    # token position does not start with '=' after lstrip.
    text = 'rule r {\n  strings:\n    $a = "x$a"\n  condition:\n    $a\n}'
    strings_line = text.splitlines()[2]
    # '$a' inside the quoted value — after '\"x', i.e., position inside the string.
    # Find the second '$a' occurrence (the one inside the string value).
    first_idx = strings_line.index("$a")
    in_value_idx = strings_line.index("$a", first_idx + len("$a"))
    end_idx = in_value_idx + len("$a")
    # After this end_idx the line has '"' (closing quote), not '='
    assert not strings_line[end_idx:].lstrip().startswith("=")
    result = _is_string_definition_occurrence(text, 2, end_idx)
    assert result is False


def test_is_string_definition_occurrence_false_when_line_in_condition_not_strings() -> None:
    """Lines 113-116 guard: line is inside the rule but in condition, not strings.

    section_range check fails → returns False before reaching lines 117-118.
    """
    text = 'rule r {\n  strings:\n    $b = "y"\n  condition:\n    $b\n}'
    result = _is_string_definition_occurrence(text, 4, 6)
    assert result is False


def test_is_string_definition_occurrence_true_with_leading_spaces_before_equals() -> None:
    """Lines 117-118: spaces between string id and '=' are handled by lstrip()."""
    text = 'rule r {\n  strings:\n    $z   =   "spaced"\n  condition:\n    $z\n}'
    strings_line = text.splitlines()[2]
    end_idx = strings_line.index("$z") + len("$z")
    result = _is_string_definition_occurrence(text, 2, end_idx)
    assert result is True
