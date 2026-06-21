# Copyright (c) 2026 Marc Rivero López
# Licensed under GPLv3. See LICENSE file for details.
# This test suite validates real code behavior without mocks or stubs.
"""Regression tests covering missing lines in rename, selection_range, and
document_query_resolution_ranges LSP modules."""

from __future__ import annotations

from pathlib import Path

from lsprotocol.types import Position, Range
import pytest

from yaraast.lsp.document_context import DocumentContext
from yaraast.lsp.document_query_resolution_ranges import (
    narrow_range_to_name,
    range_contains_position,
    resolved_if_contains,
)
from yaraast.lsp.document_types import ResolvedSymbol
from yaraast.lsp.rename import RenameProvider
from yaraast.lsp.selection_range import SelectionRangeProvider

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _pos(line: int, char: int) -> Position:
    return Position(line=line, character=char)


def _range(sl: int, sc: int, el: int, ec: int) -> Range:
    return Range(start=_pos(sl, sc), end=_pos(el, ec))


_RULE_TEXT = """\
rule alpha {
    meta:
        author = "x"
    strings:
        $a = "y"
    condition:
        $a
}
"""


# ---------------------------------------------------------------------------
# RenameProvider — missing lines 59-60, 62-63, 81, 87->89, 90->93, 97-98, 100-101
# ---------------------------------------------------------------------------


class TestRenameProviderValidationGuards:
    """Cover the isinstance guards in RenameProvider that existing tests miss."""

    def test_validate_text_must_be_string_prepare_rename(self) -> None:
        """Line 97-98: _validate_symbol_request raises TypeError when text is not str."""
        provider = RenameProvider()
        with pytest.raises(TypeError, match="text must be a string"):
            provider.prepare_rename(123, _pos(0, 0))  # type: ignore[arg-type]

    def test_validate_position_must_be_position_prepare_rename(self) -> None:
        """Line 100-101: _validate_symbol_request raises TypeError when position is not Position."""
        provider = RenameProvider()
        with pytest.raises(TypeError, match="position must be an LSP Position"):
            provider.prepare_rename("rule a { condition: true }", (0, 0))  # type: ignore[arg-type]

    def test_validate_text_must_be_string_rename(self) -> None:
        """Line 97-98: rename also runs _validate_symbol_request on non-str text."""
        provider = RenameProvider()
        with pytest.raises(TypeError, match="text must be a string"):
            provider.rename(42, _pos(0, 0), "new_name", "file://test.yar")  # type: ignore[arg-type]

    def test_validate_position_must_be_position_rename(self) -> None:
        """Line 100-101: rename raises TypeError when position is wrong type."""
        provider = RenameProvider()
        with pytest.raises(TypeError, match="position must be an LSP Position"):
            provider.rename("rule a { condition: true }", "bad", "x", "file://x.yar")  # type: ignore[arg-type]

    def test_rename_new_name_must_be_string(self) -> None:
        """Lines 59-60: rename raises TypeError when new_name is not a str."""
        provider = RenameProvider()
        with pytest.raises(TypeError, match="new_name must be a string"):
            provider.rename(
                "rule a { condition: true }",
                _pos(0, 5),
                99,  # type: ignore[arg-type]
                "file://test.yar",
            )

    def test_rename_new_name_must_not_be_empty(self) -> None:
        """Lines 62-63: rename raises ValueError when new_name is whitespace-only."""
        provider = RenameProvider()
        with pytest.raises(ValueError, match="new_name must not be empty"):
            provider.rename(
                "rule a { condition: true }",
                _pos(0, 5),
                "   ",
                "file://test.yar",
            )

    def test_rename_new_name_empty_string_raises(self) -> None:
        """Lines 62-63: rename raises ValueError when new_name is the empty string."""
        provider = RenameProvider()
        with pytest.raises(ValueError, match="new_name must not be empty"):
            provider.rename(
                "rule a { condition: true }",
                _pos(0, 5),
                "",
                "file://test.yar",
            )


class TestRenameProviderStringEditsNone:
    """Cover line 81: string rename returns None when no edits are produced."""

    def test_string_rename_no_edits_returns_none(self) -> None:
        """Line 81: build_string_rename_edits returns [] when identifier has no section hits.

        A string-like token (dollar-prefixed) can appear outside all YARA
        sections in a malformed/parse-error document.  The text-based resolver
        identifies it as kind='string' because the word starts with '$'.  The
        rename edits builder then scans for that identifier in the allowed
        sections (strings, condition, ...) but finds nothing, returning an
        empty list.  The rename method reaches line 81 and returns None.
        """
        # This document has $phantom_string on a line that is not inside any
        # recognized YARA section.  The AST is None (parse error), so the
        # text-based resolver picks up $phantom_string as kind='string'.
        # build_string_rename_edits then scans allowed sections and finds no
        # occurrences of $phantom_string there, returning [].
        text = """\
rule r {
    $phantom_string
    condition:
        true
}"""
        provider = RenameProvider()
        result = provider.rename(text, _pos(1, 5), "new_name", "file://r.yar")
        assert result is None


class TestRenameProviderRuleBranchCoverage:
    """Cover branches 87->89 and 90->93: rule rename with/without runtime edits."""

    def test_rename_rule_without_runtime_produces_edits(self) -> None:
        """Lines 84-93: rule rename without runtime calls doc.rename_rule_edits.

        When runtime is None, the code skips the runtime.rename_rule block and
        calls doc.rename_rule_edits directly (lines 89-91).  With a rule that
        has occurrences, the edits list is non-empty so WorkspaceEdit is built.
        """
        text = """\
rule alpha { condition: true }
rule beta { condition: alpha }
"""
        provider = RenameProvider()
        result = provider.rename(text, _pos(0, 6), "gamma", "file://x.yar")
        from lsprotocol.types import WorkspaceEdit

        assert isinstance(result, WorkspaceEdit)
        assert result.changes is not None
        all_new_texts = [edit.new_text for edits in result.changes.values() for edit in edits]
        assert "gamma" in all_new_texts

    def test_rename_at_non_symbol_position_returns_none_at_line_72(self) -> None:
        """Line 72: resolved is None when cursor is not on any symbol.

        Position 0,7 is the '{' brace character.  resolve_symbol returns None
        for punctuation tokens, so the `if resolved is None: return None`
        guard at lines 71-72 is exercised.
        """
        text = "rule a { condition: true }"
        provider = RenameProvider()
        result = provider.rename(text, _pos(0, 7), "b", "file://x.yar")
        assert result is None

    def test_rename_string_with_edits_returns_workspace_edit_at_line_80(self) -> None:
        """Line 80: string rename path returns WorkspaceEdit when edits are non-empty.

        A well-formed rule with $a defined in strings: and referenced in
        condition: produces a non-empty list from build_string_rename_edits.
        The `if edits:` condition at line 79 is True, so line 80 (the
        `return WorkspaceEdit(...)` in the string rename path) is executed.
        """
        text = """\
rule r {
    strings:
        $a = "x"
    condition:
        $a
}
"""
        provider = RenameProvider()
        from lsprotocol.types import WorkspaceEdit

        result = provider.rename(text, _pos(4, 9), "b", "file://r.yar")
        assert isinstance(result, WorkspaceEdit)
        assert result.changes is not None
        all_texts = [edit.new_text for edits in result.changes.values() for edit in edits]
        assert "$b" in all_texts

    def test_prepare_rename_on_string_identifier_returns_range(self) -> None:
        """Lines 28-36: prepare_rename happy path returns Range for string identifier.

        Covers the body of prepare_rename() which resolves the symbol and
        returns its range when kind is 'string'.
        """
        text = """\
rule r {
    strings:
        $a = "x"
    condition:
        $a
}
"""
        provider = RenameProvider()
        rng = provider.prepare_rename(text, _pos(4, 9))
        assert rng is not None
        assert isinstance(rng, Range)

    def test_prepare_rename_on_non_renameable_returns_none(self) -> None:
        """Lines 28-36: prepare_rename returns None for non-renameable symbols.

        Cursor on a brace position returns resolved=None, so prepare_rename
        returns None.  This exercises the `if resolved is not None and ...`
        check returning False.
        """
        provider = RenameProvider()
        result = provider.prepare_rename("rule a { condition: true }", _pos(0, 7))
        assert result is None

    def test_rename_identifier_kind_falls_through_to_line_93(self) -> None:
        """Line 93: return None when resolved.kind is neither 'string' nor 'rule'.

        Cursor on 'true' in the condition resolves to kind='identifier'.
        Neither the string branch nor the rule branch matches, so execution
        falls through all the if-blocks and reaches the final `return None`
        at line 93.
        """
        text = "rule a { condition: true }"
        provider = RenameProvider()
        # Position on 'true' (col 21) resolves to kind='identifier'
        result = provider.rename(text, _pos(0, 21), "b", "file://x.yar")
        assert result is None

    def test_rename_rule_with_runtime_no_docs_open_falls_through_to_doc_edits(
        self, tmp_path: Path
    ) -> None:
        """Branch 87->89: runtime.rename_rule returns {} when no docs are open.

        When runtime exists but no documents have been opened with
        open_document(), runtime.rename_rule() returns an empty dict (falsy).
        The `if changes:` condition at line 87 evaluates False, so the branch
        falls through to line 89 and calls doc.rename_rule_edits instead.
        This covers the 87->89 branch (the False path of `if changes:`).
        """
        from lsprotocol.types import WorkspaceEdit

        from yaraast.lsp.runtime import LspRuntime, path_to_uri

        yar: Path = tmp_path / "noopen.yar"
        yar.write_text(
            """\
rule target { condition: true }
rule consumer { condition: target }
""",
            encoding="utf-8",
        )
        runtime = LspRuntime()
        uri = path_to_uri(yar)
        text = yar.read_text(encoding="utf-8")
        # Deliberately do NOT call runtime.open_document() so that
        # runtime.rename_rule returns an empty dict.

        provider = RenameProvider(runtime)
        # Resolving at line 0, char 6 ('target' rule name) returns kind='rule'
        # via the text fallback (runtime uses the passed text).
        result = provider.rename(text, _pos(0, 6), "renamed", uri)
        # Falls through to doc.rename_rule_edits which returns the declaration
        # and reference edits.
        assert isinstance(result, WorkspaceEdit)
        assert result.changes is not None
        all_texts = [edit.new_text for edits in result.changes.values() for edit in edits]
        assert "renamed" in all_texts

    def test_rename_rule_with_runtime_and_open_doc_uses_runtime_changes(
        self, tmp_path: Path
    ) -> None:
        """Branch 87->88 (True): runtime.rename_rule returns non-empty changes.

        When runtime has the document open, runtime.rename_rule finds the
        occurrences and returns a non-empty dict.  The `if changes:` condition
        at line 87 evaluates True so the WorkspaceEdit is returned immediately
        at line 88, covering the True branch of `if changes:`.
        """
        from lsprotocol.types import WorkspaceEdit

        from yaraast.lsp.runtime import LspRuntime, path_to_uri

        yar: Path = tmp_path / "open.yar"
        yar.write_text(
            """\
rule source_rule { condition: true }
rule referrer { condition: source_rule }
""",
            encoding="utf-8",
        )
        runtime = LspRuntime()
        uri = path_to_uri(yar)
        text = yar.read_text(encoding="utf-8")
        runtime.open_document(uri, text)

        provider = RenameProvider(runtime)
        result = provider.rename(text, _pos(0, 6), "renamed_rule", uri)
        assert isinstance(result, WorkspaceEdit)
        assert result.changes is not None
        all_texts = [edit.new_text for edits in result.changes.values() for edit in edits]
        assert "renamed_rule" in all_texts


# ---------------------------------------------------------------------------
# SelectionRangeProvider — missing lines 21, 29-64, 67, 70
# ---------------------------------------------------------------------------


class TestSelectionRangeProviderBasic:
    """Cover get_selection_ranges and type guards (lines 29-64)."""

    def test_raises_type_error_for_non_string_text(self) -> None:
        """Lines 29-30: TypeError when text is not str."""
        provider = SelectionRangeProvider()
        with pytest.raises(TypeError, match="text must be a string"):
            provider.get_selection_ranges(123, [_pos(0, 0)])  # type: ignore[arg-type]

    def test_raises_type_error_for_non_list_positions(self) -> None:
        """Lines 32-33: TypeError when positions is not a list."""
        provider = SelectionRangeProvider()
        with pytest.raises(TypeError, match="positions must be a list"):
            provider.get_selection_ranges("rule a { condition: true }", _pos(0, 0))  # type: ignore[arg-type]

    def test_raises_type_error_for_non_position_in_list(self) -> None:
        """Lines 35-37: TypeError when any element in positions is not a Position."""
        provider = SelectionRangeProvider()
        with pytest.raises(TypeError, match="positions must be a list"):
            provider.get_selection_ranges(
                "rule a { condition: true }",
                [(0, 5)],  # type: ignore[list-item]
            )

    def test_empty_positions_returns_empty_list(self) -> None:
        """Lines 39-40, 42-43: empty positions list returns empty result."""
        provider = SelectionRangeProvider()
        result = provider.get_selection_ranges("rule a { condition: true }", [])
        assert result == []

    def test_position_beyond_line_count_is_skipped(self) -> None:
        """Line 44-45: position.line >= len(lines) causes the position to be skipped."""
        provider = SelectionRangeProvider()
        text = "rule a { condition: true }"
        # Line 99 does not exist.
        result = provider.get_selection_ranges(text, [_pos(99, 0)])
        assert result == []

    def test_position_with_no_word_appends_parent(self) -> None:
        """Lines 60, 62-63: position on whitespace has no word, parent appended."""
        provider = SelectionRangeProvider()
        text = _RULE_TEXT
        # Whitespace-only position: column 0 of the first line is 'r' (a word),
        # so we use a line that is entirely whitespace (e.g., an empty line
        # inside the rule, but that requires a multi-line rule).  Position on
        # column 0 of line 1 ("    meta:") starts with spaces; the word at
        # col 0 is empty because position is before any word character, and the
        # word extractor returns empty when the character under cursor is space.
        result = provider.get_selection_ranges(text, [_pos(1, 0)])
        assert len(result) >= 1
        from lsprotocol.types import SelectionRange

        assert isinstance(result[0], SelectionRange)

    def test_position_on_word_appends_word_range_with_parent(self) -> None:
        """Lines 60-61: position on a real word appends SelectionRange with parent."""
        provider = SelectionRangeProvider()
        text = _RULE_TEXT
        # _pos(0, 5) = 'p' in 'alpha' on line 0
        result = provider.get_selection_ranges(text, [_pos(0, 5)])
        assert len(result) == 1
        from lsprotocol.types import SelectionRange

        sr = result[0]
        assert isinstance(sr, SelectionRange)
        # The word range should be narrower than the line range.
        assert sr.range.start.character <= 6

    def test_multiple_positions_returns_multiple_entries(self) -> None:
        """Lines 43-63: iteration over multiple positions works correctly."""
        provider = SelectionRangeProvider()
        text = _RULE_TEXT
        positions = [_pos(0, 5), _pos(2, 9)]
        result = provider.get_selection_ranges(text, positions)
        assert len(result) == 2

    def test_provider_without_runtime_uses_none_doc(self) -> None:
        """Lines 40, 51: get_optional_document_context returns None when runtime is None.

        When runtime is None and uri is None, get_optional_document_context
        returns None, so the `if doc is not None:` branch at line 51 is False
        and parent is set to the plain line SelectionRange.
        """
        provider = SelectionRangeProvider()
        text = _RULE_TEXT
        # With runtime=None (default), doc will be None, parent = line-only SelectionRange.
        result = provider.get_selection_ranges(text, [_pos(0, 5)], uri=None)
        assert len(result) == 1

    def test_provider_with_uri_but_no_runtime_still_works(self) -> None:
        """Line 40: get_optional_document_context with uri but no runtime returns None."""
        provider = SelectionRangeProvider()
        result = provider.get_selection_ranges(_RULE_TEXT, [_pos(0, 5)], uri="file://test.yar")
        assert len(result) == 1

    def test_provider_with_runtime_and_uri_builds_doc_context(self, tmp_path: Path) -> None:
        """Line 51-58: when runtime + uri present, doc is not None and parent is richer."""
        from yaraast.lsp.runtime import LspRuntime, path_to_uri

        yar: Path = tmp_path / "sel.yar"
        yar.write_text(_RULE_TEXT, encoding="utf-8")

        runtime = LspRuntime()
        uri = path_to_uri(yar)
        runtime.open_document(uri, _RULE_TEXT)

        provider = SelectionRangeProvider(runtime)
        result = provider.get_selection_ranges(_RULE_TEXT, [_pos(6, 8)], uri=uri)
        assert len(result) == 1
        from lsprotocol.types import SelectionRange

        assert isinstance(result[0], SelectionRange)


class TestSelectionRangeProviderPrivateMethods:
    """Cover _find_enclosing_rule_range (line 67) and _find_enclosing_section_range (line 70)."""

    def test_find_enclosing_rule_range_inside_rule(self) -> None:
        """Line 67: _find_enclosing_rule_range delegates to find_enclosing_rule_range."""
        provider = SelectionRangeProvider()
        result = provider._find_enclosing_rule_range(_RULE_TEXT, _pos(2, 8))
        assert result is not None
        assert isinstance(result, Range)

    def test_find_enclosing_rule_range_outside_any_rule(self) -> None:
        """Line 67: returns None when position is outside any rule."""
        provider = SelectionRangeProvider()
        result = provider._find_enclosing_rule_range("\n\n", _pos(0, 0))
        assert result is None

    def test_find_enclosing_section_range_inside_strings(self) -> None:
        """Line 70: _find_enclosing_section_range returns Range for position in strings section."""
        provider = SelectionRangeProvider()
        result = provider._find_enclosing_section_range(_RULE_TEXT, _pos(4, 8))
        assert result is not None
        assert isinstance(result, Range)

    def test_find_enclosing_section_range_outside_any_rule(self) -> None:
        """Line 70: returns None when position is outside any rule."""
        provider = SelectionRangeProvider()
        result = provider._find_enclosing_section_range("\n\n", _pos(0, 0))
        assert result is None


# ---------------------------------------------------------------------------
# document_query_resolution_ranges — missing lines 18 and 23
# ---------------------------------------------------------------------------


class TestNarrowRangeToName:
    """Cover the two early-return paths in narrow_range_to_name."""

    def _make_ctx(self, text: str) -> DocumentContext:
        return DocumentContext("file://test.yar", text)

    def test_empty_name_returns_node_range_unchanged(self) -> None:
        """Line 18: when name is empty string, node_range is returned as-is."""
        ctx = self._make_ctx("rule a { condition: true }")
        node_range = _range(0, 0, 0, 26)
        result = narrow_range_to_name(ctx, node_range, "")
        assert result is node_range

    def test_name_not_found_in_line_returns_node_range(self) -> None:
        """Line 23: when line.find(name) returns -1, node_range is returned."""
        ctx = self._make_ctx("rule a { condition: true }")
        # 'nonexistent' is not in the line at column 0+
        node_range = _range(0, 5, 0, 6)
        result = narrow_range_to_name(ctx, node_range, "nonexistent_symbol_xyz")
        assert result is node_range

    def test_name_found_narrows_range(self) -> None:
        """Smoke test: happy path returns a range narrowed to the name."""
        ctx = self._make_ctx("rule alpha { condition: true }")
        node_range = _range(0, 0, 0, 30)
        result = narrow_range_to_name(ctx, node_range, "alpha")
        assert result.start.character == 5
        assert result.end.character == 10

    def test_empty_name_with_multiline_doc(self) -> None:
        """Line 18: empty name guard fires regardless of document line count."""
        ctx = self._make_ctx(_RULE_TEXT)
        node_range = _range(2, 8, 2, 14)
        result = narrow_range_to_name(ctx, node_range, "")
        assert result is node_range

    def test_name_at_position_zero_is_found(self) -> None:
        """Happy path where name starts at column 0."""
        ctx = self._make_ctx("rule x { condition: true }")
        node_range = _range(0, 0, 0, 4)
        result = narrow_range_to_name(ctx, node_range, "rule")
        assert result.start.character == 0
        assert result.end.character == 4


class TestRangeContainsPosition:
    """Smoke tests for range_contains_position (already covered but added for completeness)."""

    def test_position_before_start_line(self) -> None:
        r = _range(2, 0, 5, 10)
        assert not range_contains_position(r, _pos(1, 0))

    def test_position_after_end_line(self) -> None:
        r = _range(2, 0, 5, 10)
        assert not range_contains_position(r, _pos(6, 0))

    def test_position_exactly_at_end_character_excluded(self) -> None:
        r = _range(0, 0, 0, 10)
        assert not range_contains_position(r, _pos(0, 10))

    def test_position_inside_range(self) -> None:
        r = _range(0, 0, 0, 10)
        assert range_contains_position(r, _pos(0, 5))


class TestResolvedIfContains:
    """Smoke tests for resolved_if_contains."""

    def _make_resolved(self, sl: int, sc: int, el: int, ec: int) -> ResolvedSymbol:
        return ResolvedSymbol(
            uri="file://test.yar",
            name="alpha",
            normalized_name="alpha",
            kind="rule",
            range=_range(sl, sc, el, ec),
        )

    def test_position_inside_returns_resolved(self) -> None:
        resolved = self._make_resolved(0, 5, 0, 10)
        result = resolved_if_contains(_pos(0, 7), resolved)
        assert result is resolved

    def test_position_outside_returns_none(self) -> None:
        resolved = self._make_resolved(0, 5, 0, 10)
        result = resolved_if_contains(_pos(0, 3), resolved)
        assert result is None
