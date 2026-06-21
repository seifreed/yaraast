# Copyright (c) 2026 Marc Rivero López
# Licensed under GPLv3. See LICENSE file for details.
# This test suite validates real code behavior without mocks or stubs.
"""
Regression tests that raise coverage of
yaraast.lsp.code_action_structured to 100% by exercising every branch
that the existing test suite leaves uncovered.

Missing lines before this file (81.33%): 25, 31, 40, 48, 74, 78, 97.

All tests call the production mixin methods directly through the real
CodeActionsProvider (which inherits StructuredCodeActionMixin) with
concrete inputs.  No mocks, stubs, or suppressions of any kind.
"""

from __future__ import annotations

from lsprotocol.types import Diagnostic, Position, Range

from yaraast.lsp.code_actions import CodeActionsProvider

# ---------------------------------------------------------------------------
# Shared helpers
# ---------------------------------------------------------------------------

URI = "file://test.yar"


def _range(sl: int, sc: int, el: int, ec: int) -> Range:
    return Range(
        start=Position(line=sl, character=sc),
        end=Position(line=el, character=ec),
    )


def _provider() -> CodeActionsProvider:
    return CodeActionsProvider()


# ---------------------------------------------------------------------------
# _get_diagnostic_data — line 25
# data attribute exists but is not a Mapping → must return None
# ---------------------------------------------------------------------------


def test_get_diagnostic_data_returns_none_when_data_is_not_a_mapping() -> None:
    """Line 25: data is set to a non-Mapping value; method must return None."""
    provider = _provider()
    diag = Diagnostic(range=_range(0, 0, 0, 1), message="x", data=42)
    result = provider._get_diagnostic_data(diag)
    assert result is None


def test_get_diagnostic_data_returns_mapping_when_data_is_dict() -> None:
    """Positive path: data is a dict; method must return it as-is."""
    provider = _provider()
    payload: dict[str, object] = {"key": "value"}
    diag = Diagnostic(range=_range(0, 0, 0, 1), message="x", data=payload)
    result = provider._get_diagnostic_data(diag)
    assert result == payload


def test_get_diagnostic_data_returns_none_when_data_is_absent() -> None:
    """No data attribute at all; getattr returns None which is not a Mapping."""
    provider = _provider()
    diag = Diagnostic(range=_range(0, 0, 0, 1), message="x")
    result = provider._get_diagnostic_data(diag)
    assert result is None


# ---------------------------------------------------------------------------
# _create_structured_actions — line 31
# data attribute is not a dict → must return []
# ---------------------------------------------------------------------------


def test_create_structured_actions_returns_empty_when_data_is_not_dict() -> None:
    """Line 31: data is a list, not a dict; method returns []."""
    provider = _provider()
    diag = Diagnostic(range=_range(0, 0, 0, 1), message="Fix it", data=["not", "a", "dict"])
    result = provider._create_structured_actions(diag, URI)
    assert result == []


def test_create_structured_actions_returns_empty_when_data_is_none() -> None:
    """Line 31: data is None (not a dict); method returns []."""
    provider = _provider()
    diag = Diagnostic(range=_range(0, 0, 0, 1), message="Fix it", data=None)
    result = provider._create_structured_actions(diag, URI)
    assert result == []


def test_create_structured_actions_returns_empty_when_patches_missing() -> None:
    """Patches key absent from data dict; method returns []."""
    provider = _provider()
    diag = Diagnostic(range=_range(0, 0, 0, 1), message="Fix it", data={"other": 1})
    result = provider._create_structured_actions(diag, URI)
    assert result == []


def test_create_structured_actions_returns_empty_when_patches_empty_list() -> None:
    """Patches is an empty list; method returns []."""
    provider = _provider()
    diag = Diagnostic(range=_range(0, 0, 0, 1), message="Fix it", data={"patches": []})
    result = provider._create_structured_actions(diag, URI)
    assert result == []


# ---------------------------------------------------------------------------
# _create_structured_actions — line 40
# a patch element is not a Mapping → continue (skip that element)
# ---------------------------------------------------------------------------


def test_create_structured_actions_skips_non_mapping_patch() -> None:
    """Line 40: first patch is a string (not a Mapping); it is skipped.

    The title-suffix logic checks len(patches) — the raw list length —
    not the count of valid patches.  Because there are two elements the
    surviving action receives the '(2)' suffix even though only one
    action is produced.
    """
    provider = _provider()
    patch = {
        "range": {
            "start": {"line": 0, "character": 0},
            "end": {"line": 0, "character": 5},
        },
        "replacement": "fixed",
    }
    diag = Diagnostic(
        range=_range(0, 0, 0, 5),
        message="Fix it",
        data={"patches": ["not-a-mapping", patch]},
    )
    result = provider._create_structured_actions(diag, URI)
    # The non-Mapping element is skipped; the valid patch produces one action.
    # len(patches) == 2 so the suffix "(2)" is added (idx starts at 1, patch
    # is index 2 in enumeration because it is the second element).
    assert len(result) == 1
    assert result[0].title == "Fix: Fix it (2)"


def test_create_structured_actions_skips_all_non_mapping_patches() -> None:
    """All patches are non-Mapping scalars; result is empty."""
    provider = _provider()
    diag = Diagnostic(
        range=_range(0, 0, 0, 1),
        message="Fix it",
        data={"patches": [99, None, True]},
    )
    result = provider._create_structured_actions(diag, URI)
    assert result == []


# ---------------------------------------------------------------------------
# _create_structured_actions — line 44
# patch is a Mapping but coerced range is None or replacement is not str
# → continue (skip that patch)
# ---------------------------------------------------------------------------


def test_create_structured_actions_skips_patch_with_invalid_range() -> None:
    """Line 44: patch is a Mapping but range dict has bad coords → skip."""
    provider = _provider()
    bad_range_patch = {
        "range": {"start": {"line": -1, "character": 0}, "end": {"line": 0, "character": 1}},
        "replacement": "ok",
    }
    diag = Diagnostic(
        range=_range(0, 0, 0, 1),
        message="Fix it",
        data={"patches": [bad_range_patch]},
    )
    result = provider._create_structured_actions(diag, URI)
    assert result == []


def test_create_structured_actions_skips_patch_with_non_string_replacement() -> None:
    """Line 44: patch range is valid but replacement is an int → skip."""
    provider = _provider()
    bad_replacement_patch = {
        "range": {
            "start": {"line": 0, "character": 0},
            "end": {"line": 0, "character": 3},
        },
        "replacement": 123,
    }
    diag = Diagnostic(
        range=_range(0, 0, 0, 3),
        message="Fix it",
        data={"patches": [bad_replacement_patch]},
    )
    result = provider._create_structured_actions(diag, URI)
    assert result == []


def test_create_structured_actions_skips_patch_missing_replacement() -> None:
    """Line 44: replacement key absent (None from .get()) → not str → skip."""
    provider = _provider()
    no_replacement = {
        "range": {
            "start": {"line": 0, "character": 0},
            "end": {"line": 0, "character": 3},
        },
    }
    diag = Diagnostic(
        range=_range(0, 0, 0, 3),
        message="Fix it",
        data={"patches": [no_replacement]},
    )
    result = provider._create_structured_actions(diag, URI)
    assert result == []


# ---------------------------------------------------------------------------
# _create_structured_actions — line 48
# multiple valid patches → title gets an "(idx)" suffix appended
# ---------------------------------------------------------------------------


def test_create_structured_actions_appends_index_when_multiple_patches() -> None:
    """Line 48: two valid patches → titles become 'Fix: Msg (1)' and 'Fix: Msg (2)'."""
    provider = _provider()
    patch_a = {
        "range": {
            "start": {"line": 0, "character": 0},
            "end": {"line": 0, "character": 3},
        },
        "replacement": "aaa",
    }
    patch_b = {
        "range": {
            "start": {"line": 0, "character": 0},
            "end": {"line": 0, "character": 3},
        },
        "replacement": "bbb",
    }
    diag = Diagnostic(
        range=_range(0, 0, 0, 3),
        message="Suggestion",
        data={"patches": [patch_a, patch_b]},
    )
    result = provider._create_structured_actions(diag, URI)
    assert len(result) == 2
    assert result[0].title == "Fix: Suggestion (1)"
    assert result[1].title == "Fix: Suggestion (2)"


def test_create_structured_actions_no_index_when_single_patch() -> None:
    """Single patch → title has no index suffix."""
    provider = _provider()
    patch = {
        "range": {
            "start": {"line": 0, "character": 0},
            "end": {"line": 0, "character": 3},
        },
        "replacement": "xyz",
    }
    diag = Diagnostic(
        range=_range(0, 0, 0, 3),
        message="Suggestion",
        data={"patches": [patch]},
    )
    result = provider._create_structured_actions(diag, URI)
    assert len(result) == 1
    assert result[0].title == "Fix: Suggestion"


# ---------------------------------------------------------------------------
# _coerce_range — line 74
# value is already a Range object → returned directly
# ---------------------------------------------------------------------------


def test_coerce_range_returns_range_unchanged_when_already_a_range() -> None:
    """Line 74: passing a Range instance bypasses all dict logic and returns it."""
    provider = _provider()
    existing = _range(1, 2, 1, 5)
    result = provider._coerce_range(existing)
    assert result is existing


# ---------------------------------------------------------------------------
# _coerce_range — line 78
# value is a Mapping but start or end is not a Mapping → return None
# ---------------------------------------------------------------------------


def test_coerce_range_returns_none_when_start_is_not_mapping() -> None:
    """Line 78: start key holds an integer, not a Mapping → return None."""
    provider = _provider()
    bad = {"start": 0, "end": {"line": 0, "character": 5}}
    result = provider._coerce_range(bad)
    assert result is None


def test_coerce_range_returns_none_when_end_is_not_mapping() -> None:
    """Line 78: end key holds a string, not a Mapping → return None."""
    provider = _provider()
    bad = {"start": {"line": 0, "character": 0}, "end": "bad"}
    result = provider._coerce_range(bad)
    assert result is None


def test_coerce_range_returns_none_when_start_missing() -> None:
    """start key is absent (None) → not a Mapping → return None."""
    provider = _provider()
    bad = {"end": {"line": 0, "character": 5}}
    result = provider._coerce_range(bad)
    assert result is None


# ---------------------------------------------------------------------------
# _coerce_range — line 97
# (end_line, end_char) < (start_line, start_char) → return None
# ---------------------------------------------------------------------------


def test_coerce_range_returns_none_when_end_before_start_on_same_line() -> None:
    """Line 97: end character is before start character on the same line."""
    provider = _provider()
    inverted = {
        "start": {"line": 0, "character": 10},
        "end": {"line": 0, "character": 5},
    }
    result = provider._coerce_range(inverted)
    assert result is None


def test_coerce_range_returns_none_when_end_line_before_start_line() -> None:
    """Line 97: end line is earlier than start line."""
    provider = _provider()
    inverted = {
        "start": {"line": 5, "character": 0},
        "end": {"line": 3, "character": 0},
    }
    result = provider._coerce_range(inverted)
    assert result is None


def test_coerce_range_returns_range_when_end_equals_start() -> None:
    """Zero-length range (cursor position) is valid; must succeed."""
    provider = _provider()
    cursor = {
        "start": {"line": 2, "character": 4},
        "end": {"line": 2, "character": 4},
    }
    result = provider._coerce_range(cursor)
    assert isinstance(result, Range)
    assert result.start.line == 2
    assert result.start.character == 4


def test_coerce_range_returns_none_for_negative_coordinates() -> None:
    """Negative coordinate value → return None (line 94 guard)."""
    provider = _provider()
    negative = {
        "start": {"line": -1, "character": 0},
        "end": {"line": 0, "character": 0},
    }
    result = provider._coerce_range(negative)
    assert result is None


def test_coerce_range_returns_none_when_bool_passed_as_int() -> None:
    """Bool subclasses int; explicit isinstance bool checks fire → return None."""
    provider = _provider()
    bool_coord = {
        "start": {"line": True, "character": 0},
        "end": {"line": 1, "character": 0},
    }
    result = provider._coerce_range(bool_coord)
    assert result is None


def test_coerce_range_returns_none_for_non_mapping_value() -> None:
    """value is neither a Range nor a Mapping (it is a list) → return None."""
    provider = _provider()
    result = provider._coerce_range([0, 0, 1, 5])
    assert result is None


# ---------------------------------------------------------------------------
# Integration: full _create_structured_actions happy path
# validates WorkspaceEdit structure and TextEdit content
# ---------------------------------------------------------------------------


def test_create_structured_actions_produces_correct_workspace_edit() -> None:
    """Single valid patch produces a WorkspaceEdit with the right TextEdit."""
    provider = _provider()
    patch = {
        "range": {
            "start": {"line": 3, "character": 4},
            "end": {"line": 3, "character": 10},
        },
        "replacement": "new_value",
    }
    diag = Diagnostic(
        range=_range(3, 4, 3, 10),
        message="Use new_value here\ncontinuation",
        data={"patches": [patch]},
    )
    result = provider._create_structured_actions(diag, URI)
    assert len(result) == 1
    action = result[0]
    assert action.title == "Fix: Use new_value here"
    assert action.edit is not None
    changes = action.edit.changes
    assert changes is not None
    assert URI in changes
    edits = list(changes[URI])
    assert len(edits) == 1
    assert edits[0].new_text == "new_value"
    assert edits[0].range.start.line == 3
    assert edits[0].range.start.character == 4
    assert edits[0].range.end.line == 3
    assert edits[0].range.end.character == 10
