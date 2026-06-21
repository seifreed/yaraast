# Copyright (c) 2026 Marc Rivero López
# Licensed under GPLv3. See LICENSE file for details.
# This test suite validates real code behavior without mocks or stubs.
"""Second coverage-loop pass for yaraast.lsp.authoring_actions_sorting.

This file targets the lines that remained uncovered after
test_authoring_actions_sorting_coverage_loop.py was written.

Missing-line analysis before this file (74.76% with both existing test files):

  43, 75, 106, 138, 169 -- len(ast.rules) != 1 guard in every function.
      REACHABLE: two valid rules on a single line cause get_rule_context to
      return text that parses into two rules.

  46  -- sort_strings_by_identifier: len(strings) < 2.
      REACHABLE: rule with zero or one string.

  48  -- sort_strings_by_identifier: anonymous strings guard.
      REACHABLE: rule with anonymous ('$') string definitions.

  53  -- sort_strings_by_identifier: strings already in sorted order.
      REACHABLE: rule whose string identifiers are already ascending.

  57  -- sort_strings_by_identifier: _safe_generate returns None.
      REACHABLE: unsorted strings with one unreferenced definition causes
      CodeGenerator.validate_rule_string_references to raise ValueError,
      which lsp_safe_handler catches and converts to None.

  73  -- sort_meta_by_key: ast is None (parse fails).
      REACHABLE: malformed rule body that get_rule_context accepts but the
      parser cannot fully parse.

  79  -- sort_meta_by_key: meta is empty/falsy.
      REACHABLE: rule with no meta section.

  88  -- sort_meta_by_key: _safe_generate returns None.
      REACHABLE: unsorted meta with an unreferenced string definition.

  104 -- sort_tags_alphabetically: ast is None.
      REACHABLE: same malformed-rule approach as line 73.

  110 -- sort_tags_alphabetically: len(tags) < 2.
      REACHABLE: rule with zero or one tag.

  118 -- sort_tags_alphabetically: _safe_generate returns None.
      REACHABLE: unsorted tags with an unreferenced string definition.

  136 -- canonicalize_rule_structure: ast is None.
      REACHABLE: malformed rule body.

  141 -- canonicalize_rule_structure: _safe_generate (advanced) returns None.
      REACHABLE: unreferenced string definition triggers ValueError in the
      advanced CodeGenerator as well.

  144 -- canonicalize_rule_structure: regenerated text equals original.
      REACHABLE: rule already in canonical form.

  167 -- pretty_print_rule: ast is None.
      REACHABLE: malformed rule body.

  172 -- pretty_print_rule: _safe_format_ast returns None.
      REACHABLE: ASTFormatter.format_ast calls the CodeGenerator which raises
      ValueError for unreferenced strings; lsp_safe_handler returns None.

STRUCTURALLY UNREACHABLE via real code paths (justified below):

  147, 149, 178, 180 -- regenerated_ast is None / len(regenerated_ast.rules) != 1
      after successful regeneration.  A correct CodeGenerator / ASTFormatter
      operating on a valid Rule or YaraFile node always produces syntactically
      valid YARA that parses to exactly one rule.  These guards exist to protect
      against future generator bugs, not against any presently reachable scenario.

  152, 183 -- diff has logical/structural/added/removed changes after
      canonicalization or pretty-printing.  The ASTDiffer reports no differences
      after a correct round-trip; triggering these guards requires a semantics-
      altering bug in the generator or formatter.
"""

from __future__ import annotations

from lsprotocol.types import Position, Range
import pytest

from yaraast.lsp.authoring import AuthoringActions

# ---------------------------------------------------------------------------
# Shared helpers
# ---------------------------------------------------------------------------

_SEL_LINE0 = Range(start=Position(line=0, character=0), end=Position(line=0, character=0))
_SEL_LINE1 = Range(start=Position(line=1, character=0), end=Position(line=1, character=0))

# A syntactically incomplete rule that get_rule_context accepts (finds rule keyword)
# but the parser cannot fully parse (no closing brace, truncated condition).
_MALFORMED_RULE = "rule r { condition:"


def _authoring() -> AuthoringActions:
    """Return a fresh AuthoringActions with real internal components."""
    return AuthoringActions()


# ---------------------------------------------------------------------------
# Scenario A: len(ast.rules) != 1
#
# When two valid rules share a single line the brace-counting find_rule_end
# returns end == start (the only line), so rule_context.text contains both
# rules.  The parser then produces a two-rule YaraFile, hitting the guard at
# lines 43, 75, 106, 138, 169.
# ---------------------------------------------------------------------------

_TWO_RULES_ONE_LINE = "rule a { condition: true } rule b { condition: false }"

_TWO_RULES_FUNCTIONS = [
    "sort_strings_by_identifier",
    "sort_meta_by_key",
    "sort_tags_alphabetically",
    "canonicalize_rule_structure",
    "pretty_print_rule",
]


@pytest.mark.parametrize("action", _TWO_RULES_FUNCTIONS)
def test_all_sorting_actions_return_none_when_rule_context_has_two_rules(
    action: str,
) -> None:
    """All five functions return None when the rule context text contains two
    rules (len(ast.rules) != 1 guard), covering lines 43, 75, 106, 138, 169.

    Two valid rules on a single line cause find_rule_end to capture both in
    one rule_context.text.  The parser returns a two-rule YaraFile, which the
    guard rejects without producing an edit.
    """
    # Arrange
    authoring = _authoring()

    # Act
    result = getattr(authoring, action)(_TWO_RULES_ONE_LINE, _SEL_LINE0)

    # Assert
    assert result is None


# ---------------------------------------------------------------------------
# Scenario B: sort_strings_by_identifier — len(strings) < 2 (line 46)
# ---------------------------------------------------------------------------


def test_sort_strings_by_identifier_returns_none_for_rule_with_no_strings() -> None:
    """sort_strings_by_identifier returns None for a rule with no strings
    section, exercising the len(strings) < 2 early-return (line 46)."""
    authoring = _authoring()

    result = authoring.sort_strings_by_identifier("rule r { condition: true }", _SEL_LINE0)

    assert result is None


def test_sort_strings_by_identifier_returns_none_for_rule_with_one_string() -> None:
    """sort_strings_by_identifier returns None for a rule with exactly one
    string, exercising the len(strings) < 2 early-return (line 46)."""
    authoring = _authoring()

    result = authoring.sort_strings_by_identifier(
        'rule r { strings: $a = "foo" condition: $a }', _SEL_LINE0
    )

    assert result is None


# ---------------------------------------------------------------------------
# Scenario C: sort_strings_by_identifier — anonymous strings (line 48)
# ---------------------------------------------------------------------------


def test_sort_strings_by_identifier_returns_none_for_anonymous_strings() -> None:
    """sort_strings_by_identifier returns None when the rule contains anonymous
    ('$') strings, exercising the is_anonymous guard (line 48).

    The parser assigns synthesised identifiers ($anon_1, $anon_2, ...) and
    marks them with is_anonymous=True; sorting anonymous identifiers is
    meaningless and rejected."""
    authoring = _authoring()

    result = authoring.sort_strings_by_identifier(
        'rule r { strings: $ = "foo" $ = "bar" condition: any of them }',
        _SEL_LINE0,
    )

    assert result is None


# ---------------------------------------------------------------------------
# Scenario D: sort_strings_by_identifier — already sorted (line 53)
# ---------------------------------------------------------------------------


def test_sort_strings_by_identifier_returns_none_when_strings_already_sorted() -> None:
    """sort_strings_by_identifier returns None when string identifiers are
    already in ascending lexicographic order (sorted_ids == current_ids,
    line 53)."""
    authoring = _authoring()

    result = authoring.sort_strings_by_identifier(
        'rule r { strings: $a = "alpha" $b = "beta" condition: any of them }',
        _SEL_LINE0,
    )

    assert result is None


# ---------------------------------------------------------------------------
# Scenario E: sort_strings_by_identifier — _safe_generate returns None (line 57)
#
# When the rule has unsorted strings but also contains an unreferenced string
# definition, validate_rule_string_references raises ValueError; lsp_safe_handler
# catches it and _safe_generate returns None.
# ---------------------------------------------------------------------------


def test_sort_strings_by_identifier_returns_none_when_generator_raises() -> None:
    """sort_strings_by_identifier returns None when _safe_generate returns None
    (line 57).

    A rule whose strings are out of order [$b, $a] but whose condition only
    references $b leaves $a unreferenced.  After sorting, the CodeGenerator's
    validate_rule_string_references raises ValueError for the unreferenced
    definition.  lsp_safe_handler catches this and _safe_generate returns None.
    """
    authoring = _authoring()

    # $b comes before $a -> unsorted, so the sort proceeds.
    # $a is unreferenced in the condition -> generator raises.
    result = authoring.sort_strings_by_identifier(
        'rule r { strings: $b = "bar" $a = "foo" condition: $b }',
        _SEL_LINE0,
    )

    assert result is None


# ---------------------------------------------------------------------------
# Scenario F: sort_meta_by_key — ast is None (line 73)
# ---------------------------------------------------------------------------


def test_sort_meta_by_key_returns_none_when_parse_fails() -> None:
    """sort_meta_by_key returns None when the rule text cannot be parsed
    (ast is None, line 73).

    A truncated rule is found by get_rule_context (the 'rule' keyword exists)
    but fails in the parser; lsp_safe_handler catches the error and _safe_parse
    returns None.
    """
    authoring = _authoring()

    result = authoring.sort_meta_by_key(_MALFORMED_RULE, _SEL_LINE0)

    assert result is None


# ---------------------------------------------------------------------------
# Scenario G: sort_meta_by_key — meta is empty (line 79)
# ---------------------------------------------------------------------------


def test_sort_meta_by_key_returns_none_when_rule_has_no_meta() -> None:
    """sort_meta_by_key returns None when the rule has no meta section,
    exercising the 'if not meta' early-return (line 79)."""
    authoring = _authoring()

    result = authoring.sort_meta_by_key("rule r { condition: true }", _SEL_LINE0)

    assert result is None


# ---------------------------------------------------------------------------
# Scenario H: sort_meta_by_key — _safe_generate returns None (line 88)
#
# Unsorted meta combined with an unreferenced string causes the generator to
# raise ValueError, which lsp_safe_handler converts to None.
# ---------------------------------------------------------------------------


def test_sort_meta_by_key_returns_none_when_generator_raises() -> None:
    """sort_meta_by_key returns None when _safe_generate returns None (line 88).

    A rule with unsorted meta [z, a] and an unreferenced string $b proceeds
    past all earlier guards (parse succeeds, len==1, meta is non-empty, keys are
    unsorted), but the CodeGenerator raises ValueError for the unreferenced
    string definition; lsp_safe_handler catches this and returns None.
    """
    authoring = _authoring()

    # meta keys 'z' before 'a' -> unsorted; $b is unreferenced -> generator raises.
    result = authoring.sort_meta_by_key(
        'rule r { meta: z = 1 a = 2 strings: $b = "bar" condition: true }',
        _SEL_LINE0,
    )

    assert result is None


# ---------------------------------------------------------------------------
# Scenario I: sort_tags_alphabetically — ast is None (line 104)
# ---------------------------------------------------------------------------


def test_sort_tags_alphabetically_returns_none_when_parse_fails() -> None:
    """sort_tags_alphabetically returns None when the rule text cannot be parsed
    (ast is None, line 104)."""
    authoring = _authoring()

    result = authoring.sort_tags_alphabetically(_MALFORMED_RULE, _SEL_LINE0)

    assert result is None


# ---------------------------------------------------------------------------
# Scenario J: sort_tags_alphabetically — len(tags) < 2 (line 110)
# ---------------------------------------------------------------------------


def test_sort_tags_alphabetically_returns_none_for_rule_with_no_tags() -> None:
    """sort_tags_alphabetically returns None for a rule with no tags,
    exercising the len(tags) < 2 early-return (line 110)."""
    authoring = _authoring()

    result = authoring.sort_tags_alphabetically("rule r { condition: true }", _SEL_LINE0)

    assert result is None


def test_sort_tags_alphabetically_returns_none_for_rule_with_one_tag() -> None:
    """sort_tags_alphabetically returns None for a rule with exactly one tag,
    exercising the len(tags) < 2 early-return (line 110)."""
    authoring = _authoring()

    result = authoring.sort_tags_alphabetically("rule r : alpha { condition: true }", _SEL_LINE0)

    assert result is None


# ---------------------------------------------------------------------------
# Scenario K: sort_tags_alphabetically — _safe_generate returns None (line 118)
# ---------------------------------------------------------------------------


def test_sort_tags_alphabetically_returns_none_when_generator_raises() -> None:
    """sort_tags_alphabetically returns None when _safe_generate returns None
    (line 118).

    A rule with two unsorted tags [zebra, alpha] and an unreferenced string
    proceeds past all earlier guards, but the CodeGenerator raises ValueError
    for the unreferenced string definition; lsp_safe_handler returns None.
    """
    authoring = _authoring()

    result = authoring.sort_tags_alphabetically(
        'rule r : zebra alpha { strings: $b = "bar" condition: true }',
        _SEL_LINE0,
    )

    assert result is None


# ---------------------------------------------------------------------------
# Scenario L: canonicalize_rule_structure — ast is None (line 136)
# ---------------------------------------------------------------------------


def test_canonicalize_rule_structure_returns_none_when_parse_fails() -> None:
    """canonicalize_rule_structure returns None when the rule text cannot be
    parsed (ast is None, line 136)."""
    authoring = _authoring()

    result = authoring.canonicalize_rule_structure(_MALFORMED_RULE, _SEL_LINE0)

    assert result is None


# ---------------------------------------------------------------------------
# Scenario M: canonicalize_rule_structure — _safe_generate returns None (line 141)
# ---------------------------------------------------------------------------


def test_canonicalize_rule_structure_returns_none_when_advanced_generator_raises() -> None:
    """canonicalize_rule_structure returns None when _safe_generate (advanced
    generator) returns None (line 141).

    An unreferenced string definition causes the advanced CodeGenerator to raise
    ValueError during validate_rule_string_references; lsp_safe_handler returns
    None.
    """
    authoring = _authoring()

    result = authoring.canonicalize_rule_structure(
        'rule r { strings: $b = "bar" condition: true }', _SEL_LINE0
    )

    assert result is None


# ---------------------------------------------------------------------------
# Scenario N: canonicalize_rule_structure — regenerated text equals original
# (line 144)
# ---------------------------------------------------------------------------


def test_canonicalize_rule_structure_returns_none_when_already_canonical() -> None:
    """canonicalize_rule_structure returns None when the rule is already in the
    canonical form produced by the advanced generator, exercising the
    regenerated.strip() == rule_context.text.strip() early-return (line 144)."""
    authoring = _authoring()

    # A rule already formatted in the canonical multi-line style.
    canonical_text = "rule r {\n    condition:\n        true\n}"

    result = authoring.canonicalize_rule_structure(canonical_text, _SEL_LINE1)

    assert result is None


# ---------------------------------------------------------------------------
# Scenario O: pretty_print_rule — ast is None (line 167)
# ---------------------------------------------------------------------------


def test_pretty_print_rule_returns_none_when_parse_fails() -> None:
    """pretty_print_rule returns None when the rule text cannot be parsed
    (ast is None, line 167)."""
    authoring = _authoring()

    result = authoring.pretty_print_rule(_MALFORMED_RULE, _SEL_LINE0)

    assert result is None


# ---------------------------------------------------------------------------
# Scenario P: pretty_print_rule — _safe_format_ast returns None (line 172)
#
# ASTFormatter.format_ast delegates to CodeGenerator (or pretty_print) which
# calls validate_rule_string_references.  An unreferenced string causes a
# ValueError; lsp_safe_handler catches it and _safe_format_ast returns None.
# ---------------------------------------------------------------------------


def test_pretty_print_rule_returns_none_when_formatter_raises() -> None:
    """pretty_print_rule returns None when _safe_format_ast returns None
    (line 172).

    A rule with an unreferenced string $b causes ASTFormatter.format_ast to
    raise ValueError (unreferenced string definitions for libyara output);
    lsp_safe_handler catches this exception and returns None.
    """
    authoring = _authoring()

    result = authoring.pretty_print_rule(
        'rule r { strings: $b = "bar" condition: true }', _SEL_LINE0
    )

    assert result is None


# ---------------------------------------------------------------------------
# Positive counterpart: canonicalize_rule_structure actually produces an edit
# (demonstrates that Scenario N correctly identifies the no-change boundary)
# ---------------------------------------------------------------------------


def test_canonicalize_rule_structure_produces_edit_for_inline_rule() -> None:
    """canonicalize_rule_structure returns a non-None StructuralEdit when an
    inline rule is reformatted to multi-line canonical form, confirming Scenario
    N targets the correct early-return boundary."""
    authoring = _authoring()

    inline_rule = "rule r { condition: true }"

    result = authoring.canonicalize_rule_structure(inline_rule, _SEL_LINE0)

    assert result is not None
    assert "Canonicalize" in result.title


# ---------------------------------------------------------------------------
# Positive counterpart: sort_strings_by_identifier actually produces an edit
# (demonstrates that Scenarios D and E correctly target the early-return and
# generator-failure boundaries rather than the normal success path)
# ---------------------------------------------------------------------------


def test_sort_strings_by_identifier_produces_edit_for_unsorted_referenced_strings() -> None:
    """sort_strings_by_identifier returns a non-None StructuralEdit when the
    strings are unsorted and all are referenced in the condition, confirming
    that Scenarios D/E test the correct boundary conditions."""
    authoring = _authoring()

    # Both $b and $a referenced; order is unsorted -> should produce an edit.
    result = authoring.sort_strings_by_identifier(
        'rule r { strings: $b = "bar" $a = "foo" condition: $a and $b }',
        _SEL_LINE0,
    )

    assert result is not None
    assert "Sort strings" in result.title
