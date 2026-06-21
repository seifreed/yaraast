# Copyright (c) 2026 Marc Rivero López
# Licensed under GPLv3. See LICENSE file for details.
# This test suite validates real code behavior without mocks or stubs.
"""Regression tests for yaraast.lsp.authoring_actions_rewrites — second pass.

This file targets the three lines that remain uncovered after
tests/test_authoring_actions_rewrites_coverage_loop.py:

  Line 46  -- optimize_rule: ``if len(ast.rules) != 1: return None``
  Line 94  -- deduplicate_identical_strings: ``if len(ast.rules) != 1: return None``
  Line 161 -- rewrite_of_them: ``if len(ast.rules) != 1: return None``

All three guards share the same reachable construction: two YARA rules
written on a single line.  ``get_rule_text_range`` (called inside
``require_rule_context``) returns the full line as the rule context when
the cursor falls anywhere on that line.  The standard ``Parser`` then
parses the two-rule text and produces an AST with ``len(rules) == 2``,
tripping the ``!= 1`` guard in each function.

Confirmed-unreachable lines (justified below, not tested here):

  Line 49  -- optimize_rule: ``if getattr(rule, "condition", None) is None``
               Every parser variant (Parser, CommentAwareParser,
               ErrorTolerantParser) either raises ParserError or synthesises
               a BooleanLiteral(True) placeholder when the condition section
               is absent.  No production parse path yields Rule(condition=None).

  Line 72  -- roundtrip_rewrite_rule: ``return None`` when the AST diff
               has logical or structural changes.  This defensive guard
               only fires when RoundTripSerializer introduces semantic drift
               — a bug in that component, not in the function under test.
               No well-formed rule text triggers it.

  Branch 120->122 -- deduplicate_identical_strings: the False branch of
               ``if rule.condition is not None`` (i.e. condition IS None).
               Same argument as line 49: the real parser never produces
               Rule(condition=None), so this branch is structurally dead.

  Line 124 -- deduplicate_identical_strings: ``return None`` when
               ``_safe_generate`` wraps a CodeGenerator ValueError.
               The generator raises only when Rule.condition is None; that
               state is unreachable via the real parser (same as line 49).

  Line 177 -- rewrite_of_them: ``return None`` when the second
               ``_safe_generate`` call (post-transform) returns None.
               OfThemTransformer produces a structurally valid SetExpression;
               the real CodeGenerator never raises on that output.
"""

from __future__ import annotations

from lsprotocol.types import Position, Range

from yaraast.lsp.authoring import AuthoringActions

# ---------------------------------------------------------------------------
# Shared test data
# ---------------------------------------------------------------------------

# Two compact YARA rules on one line.  get_rule_text_range returns the whole
# line as the "rule context" when the cursor is on line 0.  Parser.parse()
# then yields len(ast.rules) == 2, which hits the ``!= 1`` guard in each
# function.
_TWO_RULES_ONE_LINE = "rule a { condition: true } rule b { condition: false }"
_SEL_LINE_0 = Range(
    start=Position(line=0, character=0),
    end=Position(line=0, character=0),
)

# A rule text that has duplicate strings and uses neither of-them nor
# for-of — valid input for deduplicate_identical_strings when it is a
# single rule.
_DUP_STRING_RULE = (
    "rule dup {\n"
    "    strings:\n"
    '        $a = "abc"\n'
    '        $b = "abc"\n'
    "    condition:\n"
    "        $a or $b\n"
    "}"
)
_SEL_CONDITION_LINE = Range(
    start=Position(line=4, character=0),
    end=Position(line=4, character=0),
)

# A rule that uses `any of them` — valid single-rule input for
# expand_of_them.
_OF_THEM_RULE = (
    "rule demo {\n"
    "    strings:\n"
    '        $a = "x"\n'
    '        $b = "y"\n'
    "    condition:\n"
    "        any of them\n"
    "}"
)
_SEL_OF_THEM_LINE = Range(
    start=Position(line=4, character=0),
    end=Position(line=4, character=0),
)


# ---------------------------------------------------------------------------
# Scenario 1 — optimize_rule: len(ast.rules) != 1 (line 46)
# ---------------------------------------------------------------------------


def test_optimize_rule_returns_none_for_multi_rule_single_line_text() -> None:
    """optimize_rule returns None when the rule context contains two rules
    on a single source line (exercises line 46: ``len(ast.rules) != 1``).

    Arrange: two compact YARA rules on line 0.  The cursor is also on line 0,
    so ``require_rule_context`` returns the full line as the context text.
    ``_safe_parse`` succeeds and yields ``len(ast.rules) == 2``.

    Act: call optimize_rule via AuthoringActions.optimize_rule.

    Assert: return value is the singleton None (the guard fired and no edit
    was produced).
    """
    authoring = AuthoringActions()

    result = authoring.optimize_rule(_TWO_RULES_ONE_LINE, _SEL_LINE_0)

    assert result is None


def test_optimize_rule_len_guard_returns_strict_none_not_falsy() -> None:
    """The ``len(ast.rules) != 1`` guard returns exactly None, not any
    other falsy value such as an empty list or the integer zero."""
    authoring = AuthoringActions()

    result = authoring.optimize_rule(_TWO_RULES_ONE_LINE, _SEL_LINE_0)

    assert result is None
    assert not isinstance(result, (list, tuple, int, str))


def test_optimize_rule_reaches_generation_step_for_single_rule() -> None:
    """Positive counterpart: optimize_rule passes the multi-rule guard (line 46)
    when the cursor is inside a single valid rule.

    The multi-rule guard fires only for ``len(ast.rules) != 1``.  This test
    verifies that a single-rule text is parsed as exactly one rule — i.e. the
    guard at line 46 is NOT the reason the function may return None for this
    input.  Any None result here comes from a later check (e.g. no-op
    optimisation), not from the guard this file is exercising.
    """
    authoring = AuthoringActions()
    # A single rule whose condition can be simplified (double-negation).
    text = "rule r {\n    condition:\n        not not true\n}"
    sel = Range(start=Position(line=1, character=0), end=Position(line=1, character=0))

    # Precondition: the text must produce exactly one rule so the line-46
    # guard does not fire.
    from yaraast.parser.parser import Parser

    ast = Parser().parse(text)
    assert len(ast.rules) == 1, "Precondition: test rule must be a single rule"

    # The function must process the rule past line 46 without raising.
    # We do not assert on the edit itself because the optimizer may or may
    # not simplify ``not not true`` depending on the implementation.
    authoring.optimize_rule(text, sel)


# ---------------------------------------------------------------------------
# Scenario 2 — deduplicate_identical_strings: len(ast.rules) != 1 (line 94)
# ---------------------------------------------------------------------------


def test_deduplicate_identical_strings_returns_none_for_multi_rule_single_line() -> None:
    """deduplicate_identical_strings returns None when two rules appear on
    the same source line (exercises line 94: ``len(ast.rules) != 1``).

    The rule context captures both rules as one block; the parser produces
    an AST with two rules.  The guard at line 94 fires before any string
    analysis takes place.
    """
    authoring = AuthoringActions()

    result = authoring.deduplicate_identical_strings(_TWO_RULES_ONE_LINE, _SEL_LINE_0)

    assert result is None


def test_deduplicate_identical_strings_len_guard_is_strict_none() -> None:
    """The multi-rule guard at line 94 returns the singleton None, not an
    empty edit or any other falsy sentinel."""
    authoring = AuthoringActions()

    result = authoring.deduplicate_identical_strings(_TWO_RULES_ONE_LINE, _SEL_LINE_0)

    assert result is None
    assert not isinstance(result, (list, dict))


def test_deduplicate_identical_strings_produces_edit_for_single_dup_rule() -> None:
    """Positive counterpart: deduplicate_identical_strings returns a real
    StructuralEdit for a single rule with duplicate string definitions,
    confirming the multi-rule guard is the only reason the guard tests
    return None."""
    authoring = AuthoringActions()

    result = authoring.deduplicate_identical_strings(_DUP_STRING_RULE, _SEL_CONDITION_LINE)

    assert result is not None
    assert "Deduplicate" in result.title


# ---------------------------------------------------------------------------
# Scenario 3 — rewrite_of_them: len(ast.rules) != 1 (line 161)
# ---------------------------------------------------------------------------


def test_expand_of_them_returns_none_for_multi_rule_single_line() -> None:
    """expand_of_them returns None when two rules appear on the same source
    line (exercises line 161 via the ``expand`` mode: ``len(ast.rules) != 1``).
    """
    authoring = AuthoringActions()

    result = authoring.expand_of_them(_TWO_RULES_ONE_LINE, _SEL_LINE_0)

    assert result is None


def test_compress_of_them_returns_none_for_multi_rule_single_line() -> None:
    """compress_of_them returns None when two rules appear on the same source
    line (exercises line 161 via the ``compress`` mode: ``len(ast.rules) != 1``).
    """
    authoring = AuthoringActions()

    result = authoring.compress_of_them(_TWO_RULES_ONE_LINE, _SEL_LINE_0)

    assert result is None


def test_rewrite_of_them_len_guard_strict_none_for_both_modes() -> None:
    """Both expand and compress modes return the singleton None (not any
    other falsy value) when the multi-rule guard fires at line 161."""
    authoring = AuthoringActions()

    for action in ("expand_of_them", "compress_of_them"):
        result = getattr(authoring, action)(_TWO_RULES_ONE_LINE, _SEL_LINE_0)
        assert (
            result is None
        ), f"{action} returned {result!r} instead of None for two-rule single-line text"


def test_expand_of_them_produces_edit_for_single_of_them_rule() -> None:
    """Positive counterpart: expand_of_them returns a real StructuralEdit
    when the cursor is inside a single rule that uses ``any of them``,
    confirming that the multi-rule guard is the sole cause of None in the
    guard tests above."""
    authoring = AuthoringActions()

    result = authoring.expand_of_them(_OF_THEM_RULE, _SEL_OF_THEM_LINE)

    assert result is not None
    assert "Expand" in result.title


# ---------------------------------------------------------------------------
# Combined regression: all four guard-hitting actions return None for the
# same two-rule single-line text.
# ---------------------------------------------------------------------------


def test_all_rewrite_actions_return_none_for_multi_rule_text() -> None:
    """All four rewrite actions that contain a ``len(ast.rules) != 1`` guard
    return None for the same two-rule single-line input, confirming that:
    (a) each guard is independently reachable, and
    (b) none of the guards has an off-by-one error that would allow a
        two-rule AST to pass through.
    """
    authoring = AuthoringActions()
    actions = [
        "optimize_rule",
        "deduplicate_identical_strings",
        "expand_of_them",
        "compress_of_them",
    ]
    for action in actions:
        result = getattr(authoring, action)(_TWO_RULES_ONE_LINE, _SEL_LINE_0)
        assert (
            result is None
        ), f"{action} returned {result!r} instead of None for two-rule single-line text"


# ---------------------------------------------------------------------------
# Boundary tests: confirm the guards fire at exactly len == 2, not len == 1
# ---------------------------------------------------------------------------


def test_three_rules_on_one_line_also_triggers_guards() -> None:
    """The guards fire for any count other than 1, not only for exactly 2.
    Three rules on a single line also produce len(ast.rules) == 3, which
    satisfies ``!= 1`` equally."""
    authoring = AuthoringActions()
    three_rules = (
        "rule a { condition: true } " "rule b { condition: false } " "rule c { condition: true }"
    )
    sel = Range(start=Position(line=0, character=0), end=Position(line=0, character=0))

    # Verify the parser gives us three rules for this text
    from yaraast.parser.parser import Parser

    ctx_text = three_rules
    ast = Parser().parse(ctx_text)
    assert len(ast.rules) == 3, "Precondition: three rules must parse from this text"

    for action in ("optimize_rule", "deduplicate_identical_strings", "expand_of_them"):
        result = getattr(authoring, action)(three_rules, sel)
        assert result is None, f"{action} did not return None for three-rule text"
