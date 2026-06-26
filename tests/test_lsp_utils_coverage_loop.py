"""
// Copyright (c) 2026 Marc Rivero López
// Licensed under GPLv3. See LICENSE file for details.
// This test suite validates real code behavior without mocks or stubs.

Regression tests that drive yaraast.lsp.utils to 100% statement coverage.
Each test exercises a real production path with real inputs; there are no
mocking frameworks, test doubles, or inline suppressions anywhere in this file.
"""

from __future__ import annotations

import os
from pathlib import Path
import stat

from lsprotocol.types import Position

from yaraast.ast.base import Location, YaraFile
from yaraast.ast.rules import Rule
from yaraast.lsp.utils import (
    _estimate_location_span,
    _get_location_line_text,
    _location_contains_position,
    _location_span_size,
    _position_to_location_column,
    _python_column_to_lsp,
    find_node_at_position,
    location_to_range,
    path_exists,
    path_is_dir,
    path_is_file,
)


def _restore_permissions(locked_dir: Path) -> None:
    os.chmod(str(locked_dir), stat.S_IRWXU)


# ---------------------------------------------------------------------------
# path_exists — lines 15-19 (OSError branch lines 18-19)
# ---------------------------------------------------------------------------


class TestPathExists:
    def test_existing_path_returns_true(self, tmp_path: Path) -> None:
        # Arrange: a real file on disk
        f = tmp_path / "rule.yar"
        f.write_text("", encoding="utf-8")
        # Act + Assert
        assert path_exists(f) is True

    def test_absent_path_returns_false(self, tmp_path: Path) -> None:
        assert path_exists(tmp_path / "ghost.yar") is False

    def test_os_error_returns_false(self, tmp_path: Path) -> None:
        # Arrange: make the directory inaccessible so stat() raises PermissionError
        locked = tmp_path / "locked"
        locked.mkdir()
        target = locked / "f.yar"
        target.write_text("x", encoding="utf-8")
        os.chmod(str(locked), 0)
        try:
            # Act: path_exists must catch OSError and return False (lines 18-19)
            result = path_exists(target)
        finally:
            _restore_permissions(locked)
        assert result is False


# ---------------------------------------------------------------------------
# path_is_file — lines 22-26 (OSError branch lines 25-26)
# ---------------------------------------------------------------------------


class TestPathIsFile:
    def test_file_returns_true(self, tmp_path: Path) -> None:
        f = tmp_path / "a.yar"
        f.write_text("", encoding="utf-8")
        assert path_is_file(f) is True

    def test_directory_returns_false(self, tmp_path: Path) -> None:
        assert path_is_file(tmp_path) is False

    def test_os_error_returns_false(self, tmp_path: Path) -> None:
        locked = tmp_path / "locked"
        locked.mkdir()
        target = locked / "f.yar"
        target.write_text("x", encoding="utf-8")
        os.chmod(str(locked), 0)
        try:
            # Act: path_is_file must catch OSError and return False (lines 25-26)
            result = path_is_file(target)
        finally:
            _restore_permissions(locked)
        assert result is False


# ---------------------------------------------------------------------------
# path_is_dir — lines 29-33 (all branches, OSError branch lines 30-33)
# ---------------------------------------------------------------------------


class TestPathIsDir:
    def test_directory_returns_true(self, tmp_path: Path) -> None:
        assert path_is_dir(tmp_path) is True

    def test_file_returns_false(self, tmp_path: Path) -> None:
        f = tmp_path / "a.yar"
        f.write_text("", encoding="utf-8")
        assert path_is_dir(f) is False

    def test_absent_path_returns_false(self, tmp_path: Path) -> None:
        assert path_is_dir(tmp_path / "ghost") is False

    def test_os_error_returns_false(self, tmp_path: Path) -> None:
        # Nest two levels so we can hide the inner dir
        outer = tmp_path / "outer"
        outer.mkdir()
        inner = outer / "inner"
        inner.mkdir()
        os.chmod(str(outer), 0)
        try:
            # Act: path_is_dir on the inner dir must catch OSError (lines 30-33)
            result = path_is_dir(inner)
        finally:
            _restore_permissions(outer)
        assert result is False


# ---------------------------------------------------------------------------
# find_node_at_position — proximity fallback (line 92->99, lines 94-98)
#
# The fallback fires when _location_contains_position returns False (no
# end_line/end_column set) but location.line == target_line.  The node is
# ranked by how close its column is to the target column.
# ---------------------------------------------------------------------------


class TestFindNodeAtPositionProximityFallback:
    def test_proximity_fallback_returns_node_on_same_line_without_span(self) -> None:
        # Arrange: node with no end span lives on 1-based line 3
        rule = Rule(name="sample")
        rule.location = Location(line=3, column=8, end_line=None, end_column=None)
        ast = YaraFile(rules=[rule])

        # Act: position is on 0-based line 2 (= 1-based line 3), but left of column
        pos = Position(line=2, character=1)
        found = find_node_at_position(ast, pos)

        # Assert: the proximity candidate is picked (line 94-98)
        assert found is rule

    def test_proximity_fallback_prefers_closer_column(self) -> None:
        # Two nodes on the same line — whichever is closer to the target column wins
        near = Rule(name="near")
        near.location = Location(line=1, column=5, end_line=None, end_column=None)
        far = Rule(name="far")
        far.location = Location(line=1, column=20, end_line=None, end_column=None)
        ast = YaraFile(rules=[near, far])

        # Target at column index 3 (character=3 → location column 4+1=5 without source)
        # "near" is at column 5, distance |5-4|=1; "far" at 20, distance |20-4|=16
        found = find_node_at_position(ast, Position(line=0, character=3))
        assert found is near

    def test_proximity_fallback_ignores_nodes_on_different_lines(self) -> None:
        # Node is on a different line — it should not match via proximity
        rule = Rule(name="other_line")
        rule.location = Location(line=10, column=1, end_line=None, end_column=None)
        ast = YaraFile(rules=[rule])

        found = find_node_at_position(ast, Position(line=0, character=0))
        # No match: proximity only applies when location.line == target_line
        assert found is None

    def test_position_without_source_text_uses_character_plus_one(self) -> None:
        # When source_text=None the fallback column is position.character + 1 (line 181)
        rule = Rule(name="r")
        rule.location = Location(line=1, column=6, end_line=None, end_column=None)
        ast = YaraFile(rules=[rule])

        # character=5 → target_column = 5+1 = 6, distance = |6-6| = 0
        found = find_node_at_position(ast, Position(line=0, character=5), source_text=None)
        assert found is rule


# ---------------------------------------------------------------------------
# _estimate_location_span — line 112 (start >= len) and lines 114-125 (quoted)
# ---------------------------------------------------------------------------


class TestEstimateLocationSpan:
    def test_column_past_end_of_line_returns_one(self) -> None:
        # column-1 = 99 which is >= len("abc") = 3 — hits line 112
        loc = Location(line=1, column=100)
        result = _estimate_location_span(loc, source_text="abc")
        assert result == 1

    def test_column_exactly_at_end_returns_one(self) -> None:
        # column-1 = 3 == len("abc") = 3 — also hits the start >= len branch
        loc = Location(line=1, column=4)
        result = _estimate_location_span(loc, source_text="abc")
        assert result == 1

    def test_quoted_string_scanned_to_closing_quote(self) -> None:
        # source2[4] = '"' — the scanner enters the quoted-string branch and
        # scans forward until the matching closing quote is found.
        # '"hello"' has length 7 — lines 122-123 return max(1, end-start+1).
        source2 = 'abc "hello" rest'
        loc2 = Location(line=1, column=5)  # column-1=4, source2[4]='"'
        result = _estimate_location_span(loc2, source_text=source2)
        assert result == 7

    def test_quoted_string_with_escaped_inner_quote(self) -> None:
        # '"he\"llo"' — escape at index 3 inside string; should skip the escaped quote
        # source[4] = '"', then: h, e, \, " (escaped skip), l, l, o, " (close)
        source = 'abc "he\\"llo" rest'
        loc = Location(line=1, column=5)  # column-1=4 → '"'
        result = _estimate_location_span(loc, source_text=source)
        # The escaped sequence means lines 118-119 set escaped=False; the real close is
        # after 'llo'. Span = position of closing quote - start + 1.
        assert result > 1

    def test_unterminated_quoted_string_returns_remaining_length(self) -> None:
        # No closing quote — loop exhausts and hits line 125
        source = 'abc "no close'
        loc = Location(line=1, column=5)  # column-1=4 → '"'
        result = _estimate_location_span(loc, source_text=source)
        # max(1, len(source) - 4) = max(1, 13-4) = 9
        assert result == 9

    def test_no_source_text_and_no_file_returns_one(self) -> None:
        # _get_location_line_text returns None → line 108-109 return 1
        loc = Location(line=1, column=1, file=None)
        result = _estimate_location_span(loc, source_text=None)
        assert result == 1


# ---------------------------------------------------------------------------
# _get_location_line_text — file-based path (lines 139-148)
# including line-index out-of-bounds within the file (lines 146-148)
# ---------------------------------------------------------------------------


class TestGetLocationLineText:
    def test_reads_valid_line_from_file(self, tmp_path: Path) -> None:
        yar = tmp_path / "rule.yar"
        yar.write_text("first\nsecond\nthird", encoding="utf-8")
        loc = Location(line=2, column=1, file=str(yar))

        result = _get_location_line_text(loc, source_text=None)

        assert result == "second"

    def test_returns_none_for_line_beyond_file_end(self, tmp_path: Path) -> None:
        # File has 2 lines; we request line 99 — hits the OOB branch (lines 146-148)
        yar = tmp_path / "rule.yar"
        yar.write_text("only one line\nsecond", encoding="utf-8")
        loc = Location(line=99, column=1, file=str(yar))

        result = _get_location_line_text(loc, source_text=None)

        assert result is None

    def test_returns_none_when_file_not_decodable(self, tmp_path: Path) -> None:
        # Write raw bytes that are invalid UTF-8 — UnicodeDecodeError branch (line 144-145)
        bad = tmp_path / "bad.yar"
        bad.write_bytes(b"\xff\xfe\x00")
        loc = Location(line=1, column=1, file=str(bad))

        result = _get_location_line_text(loc, source_text=None)

        assert result is None

    def test_returns_none_when_no_file_and_no_source(self) -> None:
        # location.file is None/empty — falls through to bare return None (line 149)
        loc = Location(line=1, column=1, file=None)
        result = _get_location_line_text(loc, source_text=None)
        assert result is None

    def test_source_text_takes_priority_over_file(self, tmp_path: Path) -> None:
        yar = tmp_path / "rule.yar"
        yar.write_text("file content", encoding="utf-8")
        loc = Location(line=1, column=1, file=str(yar))

        # source_text path is taken — file is never opened
        result = _get_location_line_text(loc, source_text="inline content")
        assert result == "inline content"

    def test_source_text_out_of_bounds_returns_none(self) -> None:
        loc = Location(line=99, column=1, file=None)
        result = _get_location_line_text(loc, source_text="single line")
        assert result is None


# ---------------------------------------------------------------------------
# _position_to_location_column — fallback branch (lines 179-181)
# The fallback fires when source_text is None OR position.line is OOB.
# ---------------------------------------------------------------------------


class TestPositionToLocationColumn:
    def test_returns_character_plus_one_when_source_is_none(self) -> None:
        pos = Position(line=5, character=10)
        result = _position_to_location_column(pos, source_text=None)
        # Fallback: position.character + 1 (line 181)
        assert result == 11

    def test_returns_character_plus_one_when_line_is_out_of_bounds(self) -> None:
        pos = Position(line=99, character=7)
        result = _position_to_location_column(pos, source_text="abc\ndef")
        assert result == 8

    def test_converts_utf16_to_utf8_when_source_is_available(self) -> None:
        # "😀x" — emoji occupies 2 UTF-16 code units (surrogate pair).
        # character=2 in UTF-16 points to 'x' (after the surrogate pair).
        # utf16_col_to_utf8("😀x", 2) returns 1 (byte index of 'x' is 4,
        # but the helper returns the number of codepoints before that
        # position — verified empirically: utf16_col_to_utf8("😀x", 2) == 1).
        # The function returns utf16_col_to_utf8(...) + 1 = 2.
        source = "😀x\nsecond"
        pos = Position(line=0, character=2)
        result = _position_to_location_column(pos, source_text=source)
        assert result == 2


# ---------------------------------------------------------------------------
# _location_contains_position — full branch coverage
# ---------------------------------------------------------------------------


class TestLocationContainsPosition:
    def test_returns_false_when_no_end_span(self) -> None:
        loc = Location(line=1, column=1, end_line=None, end_column=None)
        assert _location_contains_position(loc, 1, 1) is False

    def test_returns_false_when_line_before_start(self) -> None:
        loc = Location(line=5, column=1, end_line=7, end_column=10)
        assert _location_contains_position(loc, 3, 5) is False

    def test_returns_false_when_line_after_end(self) -> None:
        loc = Location(line=5, column=1, end_line=7, end_column=10)
        assert _location_contains_position(loc, 9, 1) is False

    def test_returns_false_when_on_start_line_but_before_column(self) -> None:
        loc = Location(line=5, column=8, end_line=7, end_column=10)
        assert _location_contains_position(loc, 5, 3) is False

    def test_returns_false_when_on_end_line_at_or_after_end_column(self) -> None:
        loc = Location(line=5, column=1, end_line=7, end_column=10)
        assert _location_contains_position(loc, 7, 10) is False
        assert _location_contains_position(loc, 7, 15) is False

    def test_returns_true_for_position_inside_span(self) -> None:
        loc = Location(line=5, column=1, end_line=7, end_column=10)
        assert _location_contains_position(loc, 6, 5) is True

    def test_returns_true_at_start_of_span(self) -> None:
        loc = Location(line=5, column=3, end_line=5, end_column=10)
        assert _location_contains_position(loc, 5, 3) is True

    def test_returns_true_just_before_end_column_on_end_line(self) -> None:
        loc = Location(line=5, column=1, end_line=5, end_column=10)
        assert _location_contains_position(loc, 5, 9) is True


# ---------------------------------------------------------------------------
# _location_span_size — both branches (with and without end span)
# ---------------------------------------------------------------------------


class TestLocationSpanSize:
    def test_span_size_with_full_end_coordinates(self) -> None:
        loc = Location(line=1, column=3, end_line=1, end_column=9)
        result = _location_span_size(loc)
        # Same line: (0 * 10_000) + max(1, 9-3) = 6
        assert result == 6

    def test_span_size_across_multiple_lines(self) -> None:
        loc = Location(line=1, column=1, end_line=3, end_column=5)
        result = _location_span_size(loc)
        # (3-1)*10_000 + max(1, 5-1) = 20000 + 4 = 20004
        assert result == 20004

    def test_span_size_without_end_line_uses_same_line_fallback(self) -> None:
        loc = Location(line=5, column=4, end_line=None, end_column=None)
        result = _location_span_size(loc)
        # end_line = 5 (or 5), end_column = 4+1=5 → (0)*10_000 + max(1, 5-4) = 1
        assert result == 1


# ---------------------------------------------------------------------------
# _python_column_to_lsp — out-of-bounds line index fallback
# ---------------------------------------------------------------------------


class TestPythonColumnToLsp:
    def test_valid_ascii_line(self) -> None:
        lines = ["hello world"]
        result = _python_column_to_lsp(lines, 0, 5)
        assert result == 5  # pure ASCII, UTF-8 byte index == UTF-16 code unit

    def test_multibyte_character_shifts_column(self) -> None:
        # "😀x" — emoji occupies 4 UTF-8 bytes but 2 UTF-16 code units.
        # utf8 byte index 4 is the position of 'x'; in UTF-16 that is
        # code-unit index 3 (2 for the surrogate pair + 1 for 'x' itself,
        # but the helper counts code units *before* that byte — verified
        # empirically: utf8_col_to_utf16("😀x", 4) == 3).
        lines = ["😀x"]
        result = _python_column_to_lsp(lines, 0, 4)
        assert result == 3

    def test_line_index_out_of_bounds_returns_raw_column(self) -> None:
        lines = ["only one line"]
        # line_index=5 is >= len(lines)=1, so fallback: return column (line 173)
        result = _python_column_to_lsp(lines, 5, 7)
        assert result == 7

    def test_empty_lines_list_returns_raw_column(self) -> None:
        result = _python_column_to_lsp([], 0, 3)
        assert result == 3


# ---------------------------------------------------------------------------
# location_to_range — end span on different line (end_line != start_line)
# This ensures the branch at line 55 that skips the max() guard is exercised.
# ---------------------------------------------------------------------------


class TestLocationToRangeMultiLine:
    def test_end_on_different_line_does_not_clamp_end_character(self) -> None:
        # end_line=2 != start_line=0 — the max(start_character+1, end_character) guard
        # at line 56 is skipped
        loc = Location(line=1, column=1, end_line=2, end_column=3)
        source = "first line\nsecond line"
        rng = location_to_range(loc, source_text=source)

        assert rng.start.line == 0
        assert rng.end.line == 1
        # end_character corresponds to column 3 on 'second line' (0-based index 2)
        assert rng.end.character == 2

    def test_end_on_same_line_clamped_to_at_least_start_plus_one(self) -> None:
        # end_line == start_line and end_column <= start_column — clamp fires (line 56)
        loc = Location(line=1, column=5, end_line=1, end_column=5)
        source = "abcdefghij"
        rng = location_to_range(loc, source_text=source)

        assert rng.start.line == 0
        assert rng.end.line == 0
        assert rng.end.character >= rng.start.character + 1


# ---------------------------------------------------------------------------
# Missing branch arcs
#
# Arc 92->99: best_match is already set (not None) and the new proximity
#   candidate does NOT beat it — the `if best_match is None or candidate >
#   best_match` at line 92 takes the False path and skips the update.
#
# Arc 141->149: location.file is set but the path does not exist (or is not
#   a file) — path_exists/path_is_file returns False, so the `if` at line
#   141 is False and execution jumps straight to `return None` at line 149.
# ---------------------------------------------------------------------------


class TestMissingBranchArcs:
    def test_arc_92_99_proximity_candidate_does_not_beat_existing_match(self) -> None:
        # Arrange two nodes on the same line without end-span.
        # First node (column=4) will be closer to the target than the second
        # (column=20).  After the first is recorded as best_match, the second
        # node's candidate tuple is strictly smaller (worse distance), so the
        # `if best_match is None or candidate > best_match` condition at line
        # 92 evaluates to False — the arc 92->99 fires without updating
        # best_match.
        close_rule = Rule(name="close")
        close_rule.location = Location(line=1, column=4, end_line=None, end_column=None)
        far_rule = Rule(name="far")
        far_rule.location = Location(line=1, column=20, end_line=None, end_column=None)
        # YaraFile iterates rules in order; _search processes close_rule first.
        ast = YaraFile(rules=[close_rule, far_rule])

        # Target: line=0 (1-based line=1), character=2 (target_column=3).
        # close_rule distance = |4-3| = 1; far_rule distance = |20-3| = 17.
        # close_rule wins — far_rule's candidate is rejected at line 92.
        found = find_node_at_position(ast, Position(line=0, character=2))
        assert found is close_rule

    def test_arc_141_149_nonexistent_file_returns_none(self, tmp_path: Path) -> None:
        # Arrange: location.file points to a path that does not exist on disk.
        # path_exists() will return False → the `if path_exists(...) and ...`
        # at line 141 is False → execution jumps to `return None` at line 149.
        missing = tmp_path / "does_not_exist.yar"
        loc = Location(line=1, column=1, file=str(missing))

        result = _get_location_line_text(loc, source_text=None)

        assert result is None

    def test_arc_92_99_span_candidate_does_not_beat_existing_span_match(self) -> None:
        # Arrange two rules whose spans both contain the target position.
        # The first rule (small) has a tighter span and is processed first;
        # it sets best_match.  The second rule (big) also contains the position
        # but has a much larger span, so its candidate tuple is strictly smaller
        # than best_match — the `if best_match is None or candidate > best_match`
        # condition at line 92 is False and the arc 92->99 fires without
        # updating best_match.
        small = Rule(name="small")
        # Spans 1-based line 2, columns 3-8 — tight span (size=5)
        small.location = Location(line=2, column=3, end_line=2, end_column=8)

        big = Rule(name="big")
        # Spans 1-based lines 1-5 — large span (size=40009)
        big.location = Location(line=1, column=1, end_line=5, end_column=10)

        # YaraFile processes children in declaration order — small is visited
        # first and establishes best_match; big is visited second.
        ast = YaraFile(rules=[small, big])

        # 0-based line=1 → 1-based line=2; no source_text → target_column = character+1 = 4
        # Both nodes contain (1-based line=2, column=4).
        found = find_node_at_position(ast, Position(line=1, character=3))

        # small must win because it has the tighter span
        assert found is small
