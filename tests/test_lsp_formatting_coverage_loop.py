# Copyright (c) 2026 Marc Rivero López
# Licensed under GPLv3. See LICENSE file for details.
# This test suite validates real code behavior without mocks or stubs.
"""Regression tests covering missing branches in yaraast/lsp/formatting.py.

Target gaps identified by --cov-report=term-missing (prior run at 89.90%):
  - Line 89  : _format_range_safe falls back to whole-document format when no
               enclosing rule is found (rule_info is None)
  - Line 122 : structurally unreachable — find_rule_line always succeeds for
               any rule produced by parsing the same source text
  - Line 125 : structurally unreachable — find_rule_end always returns a value
               in [0, len(lines)-1], never negative or out of bounds
  - Line 135 : _find_enclosing_rule returns None after exhausting all rules
               without finding one that contains the requested range
  - Line 140 : _line_end_position guard branch for empty lines list or
               out-of-range line_num; exercised via the public module export

Lines 122 and 125 are not tested because they are dead code under the current
implementation contracts:

  Line 122: find_rule_line is called with a rule name taken directly from the
  AST produced by parsing the same source text.  find_rule_line searches that
  same text for "rule <name>", and YARA rule names are restricted to
  [A-Za-z0-9_] identifiers, so the regex will always find the declaration.

  Line 125: find_rule_end scans from the rule's opening line and returns at
  most len(lines)-1.  It never returns a negative value, and the returned
  index is always a valid index into the lines list.

All tests exercise real production code paths.  No mocks, stubs, or test
doubles are used.
"""

from __future__ import annotations

from lsprotocol.types import Position

from yaraast.lsp.formatting import FormattingProvider, _line_end_position

# ---------------------------------------------------------------------------
# Line 89 + Line 135: _format_range_safe fallback to full-document format
# ---------------------------------------------------------------------------


class TestFormatRangeFallback:
    """Verify that format_range delegates to full-document formatting when the
    requested range does not fall inside any rule body."""

    def test_range_on_blank_line_between_rules_falls_back_to_document(self) -> None:
        """A range on the blank line between two rules matches no rule, so
        _find_enclosing_rule returns None (line 135) and format_range falls
        back to _format_document_safe (line 89)."""
        provider = FormattingProvider()
        text = "rule a { condition: true }\n\nrule b { condition: true }"

        # line 1 is the blank line; neither rule spans it
        edits = provider.format_range(
            text,
            Position(line=1, character=0),
            Position(line=1, character=0),
        )

        assert edits, "fallback must return at least one edit"
        formatted = edits[0].new_text
        # Both rules must appear in the full-document result
        assert "rule a" in formatted
        assert "rule b" in formatted

    def test_range_before_first_rule_falls_back_to_document(self) -> None:
        """A range that starts before the first rule declaration is not
        enclosed by any rule, triggering the None return (line 135) and the
        fallback path (line 89)."""
        provider = FormattingProvider()
        # Add a comment before the rule so line 0 is outside any rule body
        text = "// preamble comment\nrule c { condition: true }"

        edits = provider.format_range(
            text,
            Position(line=0, character=0),
            Position(line=0, character=5),
        )

        assert edits, "fallback must produce at least one edit"
        assert "rule c" in edits[0].new_text

    def test_range_after_last_rule_falls_back_to_document(self) -> None:
        """A range positioned after the closing brace of the only rule is
        outside any rule body, producing a None result from
        _find_enclosing_rule (line 135) and a whole-document edit (line 89)."""
        provider = FormattingProvider()
        text = "rule d { condition: true }\n// trailing comment"

        # line 1 is after the rule ends at line 0
        edits = provider.format_range(
            text,
            Position(line=1, character=0),
            Position(line=1, character=5),
        )

        assert edits, "fallback must produce at least one edit"
        assert "rule d" in edits[0].new_text

    def test_range_spanning_multiple_rules_falls_back_to_document(self) -> None:
        """A range that begins inside one rule and ends inside another cannot
        be attributed to a single enclosing rule.  The loop in
        _find_enclosing_rule will reject every candidate because
        end.line > rule_end for the first rule and start.line < rule_line for
        the second, exhausting the loop and returning None (line 135) which
        then triggers the fallback (line 89)."""
        provider = FormattingProvider()
        text = "rule e { condition: true }\nrule f { condition: true }"

        # start inside rule e (line 0), end inside rule f (line 1)
        edits = provider.format_range(
            text,
            Position(line=0, character=5),
            Position(line=1, character=5),
        )

        assert edits, "fallback must produce at least one edit"
        assert "rule e" in edits[0].new_text
        assert "rule f" in edits[0].new_text

    def test_range_falls_back_and_result_is_valid_yara(self) -> None:
        """The document produced by the fallback path is a well-formed,
        formatted YARA snippet — verify structural tokens are present."""
        provider = FormattingProvider()
        text = 'rule g { strings: $s = "hello" condition: $s }\n\n// gap\n'

        # Range on the gap comment line, outside the rule
        edits = provider.format_range(
            text,
            Position(line=2, character=0),
            Position(line=2, character=3),
        )

        assert edits
        formatted = edits[0].new_text
        assert "rule g" in formatted
        assert "condition:" in formatted


# ---------------------------------------------------------------------------
# Line 140: _line_end_position guard for invalid inputs
# ---------------------------------------------------------------------------


class TestLineEndPositionGuard:
    """Directly exercise the module-level _line_end_position helper to cover
    the early-return guard on line 140.

    _line_end_position is only reachable internally through call chains whose
    invariants prevent the guard from firing.  The guard is a defensive
    boundary that must be validated through the exported symbol directly.
    """

    def test_empty_lines_list_returns_origin(self) -> None:
        """When lines is an empty list the guard fires and Position(0,0) is
        returned to avoid an IndexError."""
        result = _line_end_position([], 0)
        assert result.line == 0
        assert result.character == 0

    def test_negative_line_num_returns_origin(self) -> None:
        """A negative line_num satisfies line_num < 0 in the guard and
        Position(0,0) is returned."""
        result = _line_end_position(["rule a { condition: true }"], -1)
        assert result.line == 0
        assert result.character == 0

    def test_line_num_at_exact_length_returns_origin(self) -> None:
        """line_num equal to len(lines) satisfies line_num >= len(lines) and
        triggers the guard."""
        lines = ["rule a { condition: true }"]
        result = _line_end_position(lines, len(lines))
        assert result.line == 0
        assert result.character == 0

    def test_line_num_beyond_length_returns_origin(self) -> None:
        """Any line_num strictly greater than the last valid index also
        satisfies the guard and returns Position(0,0)."""
        lines = ["rule a { condition: true }", "rule b { condition: true }"]
        result = _line_end_position(lines, 99)
        assert result.line == 0
        assert result.character == 0

    def test_valid_ascii_line_returns_correct_position(self) -> None:
        """Confirm the normal path still works: a valid line_num produces a
        Position whose line matches line_num and character equals the UTF-16
        length of the ASCII content."""
        lines = ["rule a { condition: true }"]
        result = _line_end_position(lines, 0)
        assert result.line == 0
        assert result.character == len(lines[0])

    def test_valid_unicode_line_returns_utf16_character_count(self) -> None:
        """A line containing surrogate-pair characters (emoji) has a UTF-16
        length greater than its UTF-8 len() value; the normal path must use
        the UTF-16 column helper, not len()."""
        # Each emoji is U+1F600, encoded as a surrogate pair in UTF-16
        lines = ["ab\U0001f600cd"]
        result = _line_end_position(lines, 0)
        assert result.line == 0
        # 'a','b' = 2 units; emoji = 2 surrogates; 'c','d' = 2 units → 6
        assert result.character == 6

    def test_empty_line_string_returns_zero_character(self) -> None:
        """An empty string at a valid index is a legal input; character must
        be 0 since the line has no content."""
        lines = [""]
        result = _line_end_position(lines, 0)
        assert result.line == 0
        assert result.character == 0
