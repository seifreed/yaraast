# Copyright (c) 2026 Marc Rivero López
# Licensed under GPLv3. See LICENSE file for details.
# This test suite validates real code behavior without mocks or stubs.
"""Coverage-loop tests for yaraast.lsp.authoring_actions_sorting.

These tests target the lines in authoring_actions_sorting.py that are not
reached by the existing test suite (test_authoring_actions_sorting_coverage.py
and test_lsp_authoring_phase5.py).

Missing-line analysis (78.64% before this file):

COVERABLE missing lines (addressed here):
  38  -- sort_strings_by_identifier: require_rule_context returns None
  70  -- sort_meta_by_key: require_rule_context returns None
  84  -- sort_meta_by_key: meta already in sorted order -> early return
 101  -- sort_tags_alphabetically: require_rule_context returns None
 114  -- sort_tags_alphabetically: tags already in sorted order -> early return
 133  -- canonicalize_rule_structure: require_rule_context returns None
 164  -- pretty_print_rule: require_rule_context returns None
 175  -- pretty_print_rule: formatter output equals input -> early return

STRUCTURALLY UNREACHABLE via the real public API (documented here):
  43, 75, 106, 138, 169  -- len(ast.rules) != 1 after a successful parse of
                            rule_context.text.  get_rule_context extracts exactly
                            one rule's text block; that text, when parseable at
                            all, always produces exactly one rule.  If it is not
                            parseable the safe-handler catches the exception and
                            returns None (lines 40-41, 72-73, 103-104, 136-137,
                            166-167) before the len-check is ever evaluated.

  57, 88, 118             -- _safe_generate returns None.  CodeGenerator.generate
                            is wrapped by lsp_safe_handler; it only returns None
                            when the generator raises an unhandled exception.  No
                            valid Rule AST node produced by the standard parser
                            triggers such an exception.

  147, 178                -- len(regenerated_ast.rules) != 1 after regeneration.
                            The advanced generator / formatter operate on a single
                            Rule node, so their output (when it does not throw)
                            always represents exactly one rule.

  149, 152, 180, 183      -- diff.logical_changes / structural_changes / added_rules
                            / removed_rules are non-empty after canonicalization or
                            pretty-printing.  These checks guard against a generator
                            bug introducing semantic changes; they never fire for
                            a correct generator on a well-formed input.
"""

from __future__ import annotations

from lsprotocol.types import Position, Range
import pytest

from yaraast.lsp.authoring import AuthoringActions

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

_TEXT_WITH_IMPORT = 'import "pe"\n\nrule r {\n    condition:\n        true\n}\n'
"""A file whose line 0 is an import statement — no rule context on that line."""

_IMPORT_LINE_SEL = Range(start=Position(line=0, character=0), end=Position(line=0, character=0))
"""Selection anchored on line 0, which is outside any rule body."""


# ---------------------------------------------------------------------------
# Scenario 1: cursor outside any rule (require_rule_context returns None)
#
# Each function in authoring_actions_sorting begins:
#
#   rule_context = require_rule_context(text, selection.start.line)
#   if rule_context is None:          <- the guard we cover here
#       return None
#
# Lines covered: 38 (sort_strings), 70 (sort_meta), 101 (sort_tags),
#                133 (canonicalize), 164 (pretty_print).
# ---------------------------------------------------------------------------

_OUTSIDE_RULE_FUNCTIONS = [
    "sort_strings_by_identifier",
    "sort_meta_by_key",
    "sort_tags_alphabetically",
    "canonicalize_rule_structure",
    "pretty_print_rule",
]


@pytest.mark.parametrize("action", _OUTSIDE_RULE_FUNCTIONS)
def test_all_sorting_actions_return_none_when_cursor_outside_rule(action: str) -> None:
    """All five sorting/canonicalization actions return None when the cursor is
    positioned on a line that is not inside any YARA rule block."""
    # Arrange: real AuthoringActions; text whose line 0 is an import directive.
    authoring = AuthoringActions()

    # Act: invoke the action with a selection on the import line.
    result = getattr(authoring, action)(_TEXT_WITH_IMPORT, _IMPORT_LINE_SEL)

    # Assert: no edit is produced.
    assert result is None


# ---------------------------------------------------------------------------
# Scenario 2: sort_meta_by_key on already-sorted meta (line 84)
#
# The function sorts meta entries by key and checks whether the order already
# matches.  When sorted_keys == current_keys the action returns None without
# producing an edit.
# ---------------------------------------------------------------------------

_SORTED_META_RULE = (
    "rule r {\n"
    "    meta:\n"
    "        alpha = 1\n"
    "        beta = 2\n"
    '        gamma = "value"\n'
    "    condition:\n"
    "        true\n"
    "}\n"
)

_INNER_SEL = Range(start=Position(line=2, character=0), end=Position(line=2, character=0))
"""Selection inside the rule body."""


def test_sort_meta_by_key_returns_none_when_already_sorted() -> None:
    """sort_meta_by_key returns None when meta keys are already in ascending
    lexicographic order, exercising the early-return on line 84."""
    # Arrange
    authoring = AuthoringActions()

    # Act
    result = authoring.sort_meta_by_key(_SORTED_META_RULE, _INNER_SEL)

    # Assert: sorted order equals current order -> no edit needed.
    assert result is None


# ---------------------------------------------------------------------------
# Scenario 3: sort_tags_alphabetically on already-sorted tags (line 114)
#
# When the tag list is already in ascending order the function returns None.
# ---------------------------------------------------------------------------

_SORTED_TAGS_RULE = "rule r : alpha beta gamma {\n    condition:\n        true\n}\n"

_TAG_SEL = Range(start=Position(line=0, character=0), end=Position(line=0, character=0))


def test_sort_tags_alphabetically_returns_none_when_already_sorted() -> None:
    """sort_tags_alphabetically returns None when tags are already in
    ascending alphabetical order, exercising the early-return on line 114."""
    # Arrange
    authoring = AuthoringActions()

    # Act
    result = authoring.sort_tags_alphabetically(_SORTED_TAGS_RULE, _TAG_SEL)

    # Assert
    assert result is None


# ---------------------------------------------------------------------------
# Scenario 4: pretty_print_rule on a rule already formatted by the pretty
# printer (line 175)
#
# The formatter round-trips the rule through ASTFormatter(style="pretty").
# If the output matches the input (strip-wise) the action returns None.
# ---------------------------------------------------------------------------

_ALREADY_PRETTY_RULE = "rule r {\n    condition:\n        true\n}"
"""Rule already in the pretty-printer's canonical output form."""

_PRETTY_SEL = Range(start=Position(line=1, character=0), end=Position(line=1, character=0))


def test_pretty_print_rule_returns_none_when_already_formatted() -> None:
    """pretty_print_rule returns None when the formatter output is identical
    to the input, exercising the early-return on line 175."""
    # Arrange
    authoring = AuthoringActions()

    # Act
    result = authoring.pretty_print_rule(_ALREADY_PRETTY_RULE, _PRETTY_SEL)

    # Assert: formatter produced the same text -> no edit is needed.
    assert result is None


# ---------------------------------------------------------------------------
# Scenario 5: sort_meta_by_key produces an edit when meta is unsorted
# (positive assertion — ensures Scenario 2 truly differs from the normal path)
# ---------------------------------------------------------------------------

_UNSORTED_META_RULE = (
    "rule r {\n"
    "    meta:\n"
    "        zebra = 2\n"
    "        alpha = 1\n"
    "    condition:\n"
    "        true\n"
    "}\n"
)


def test_sort_meta_by_key_produces_edit_for_unsorted_meta() -> None:
    """sort_meta_by_key returns a non-None StructuralEdit when meta keys are
    not in sorted order, confirming Scenario 2 tests the correct boundary."""
    # Arrange
    authoring = AuthoringActions()

    # Act
    result = authoring.sort_meta_by_key(_UNSORTED_META_RULE, _INNER_SEL)

    # Assert: an edit was produced.
    assert result is not None
    # The title must mention the sort operation.
    assert "Sort meta by key" in result.title


# ---------------------------------------------------------------------------
# Scenario 6: sort_tags_alphabetically produces an edit when tags are unsorted
# (positive counterpart to Scenario 3)
# ---------------------------------------------------------------------------

_UNSORTED_TAGS_RULE = "rule r : zebra alpha {\n    condition:\n        true\n}\n"


def test_sort_tags_alphabetically_produces_edit_for_unsorted_tags() -> None:
    """sort_tags_alphabetically returns a non-None StructuralEdit when tags are
    not in alphabetical order, confirming Scenario 3 tests the correct boundary."""
    # Arrange
    authoring = AuthoringActions()

    # Act
    result = authoring.sort_tags_alphabetically(_UNSORTED_TAGS_RULE, _TAG_SEL)

    # Assert
    assert result is not None
    assert "Sort tags alphabetically" in result.title


# ---------------------------------------------------------------------------
# Scenario 7: pretty_print_rule produces an edit when formatting is required
# (positive counterpart to Scenario 4)
# ---------------------------------------------------------------------------

_UNFORMATTED_RULE = "rule r { condition: true }"
"""Rule written on a single line — pretty printer will expand it."""

_INLINE_SEL = Range(start=Position(line=0, character=0), end=Position(line=0, character=0))


def test_pretty_print_rule_produces_edit_for_unformatted_rule() -> None:
    """pretty_print_rule returns a non-None StructuralEdit when the rule can be
    reformatted, confirming Scenario 4 tests the correct boundary."""
    # Arrange
    authoring = AuthoringActions()

    # Act
    result = authoring.pretty_print_rule(_UNFORMATTED_RULE, _INLINE_SEL)

    # Assert
    assert result is not None
    assert "Pretty-print rule" in result.title


# ---------------------------------------------------------------------------
# Scenario 8: validate the outside-rule return value is strictly None,
# not a falsy non-None object (regression guard).
# ---------------------------------------------------------------------------


def test_outside_rule_returns_exact_none_not_falsy_empty() -> None:
    """All five actions must return the singleton None (not an empty container
    or other falsy value) when the cursor is outside a rule block."""
    authoring = AuthoringActions()

    for action in _OUTSIDE_RULE_FUNCTIONS:
        result = getattr(authoring, action)(_TEXT_WITH_IMPORT, _IMPORT_LINE_SEL)
        assert (
            result is None
        ), f"{action} returned {result!r} instead of None for an outside-rule position"
