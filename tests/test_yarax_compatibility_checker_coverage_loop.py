# Copyright (c) 2026 Marc Rivero López
# Licensed under GPLv3. See LICENSE file for details.
# This test suite validates real code behavior without mocks or stubs.
"""Regression tests targeting remaining uncovered lines in compatibility_checker.py.

Missing lines from the baseline full-suite run (94.97%):
  220->230  _is_valid_quantifier: comma at end-of-string branch
  285       _check_hex_jump_bound: None value early-return
  381       visit_unary_expression body
  384       visit_parentheses_expression body
  390-391   visit_range_expression body
  402       visit_member_access body
  409       visit_defined_expression body
  412-413   visit_string_operator_expression body
  416-418   visit_for_expression body
  421-423   visit_for_of_expression body
  430-431   visit_in_expression body
  536->533  _get_yarax_features_used: duplicate-feature dedup branch
"""

from __future__ import annotations

from yaraast.ast.base import YaraFile
from yaraast.ast.conditions import ForExpression, ForOfExpression, InExpression
from yaraast.ast.expressions import (
    BooleanLiteral,
    Expression,
    Identifier,
    IntegerLiteral,
    MemberAccess,
    ParenthesesExpression,
    RangeExpression,
    StringLiteral,
    UnaryExpression,
)
from yaraast.ast.operators import DefinedExpression, StringOperatorExpression
from yaraast.ast.rules import Rule
from yaraast.ast.strings import HexJump, RegexString
from yaraast.yarax.compatibility_checker import CompatibilityIssue, YaraXCompatibilityChecker
from yaraast.yarax.feature_flags import YaraXFeatures

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _strict_checker() -> YaraXCompatibilityChecker:
    return YaraXCompatibilityChecker(YaraXFeatures.yarax_strict())


def _file_with_condition(name: str, condition: Expression) -> YaraFile:
    return YaraFile(rules=[Rule(name=name, condition=condition)])


# ---------------------------------------------------------------------------
# Line 220->230: _is_valid_quantifier branch where comma is the final char
#
# The branch fires when pattern[j] == ',' but j + 1 >= len(pattern), so the
# compound condition on line 220 evaluates to False and control falls directly
# to line 230 (return False).  The regex 'x{1,' exercises this path: the '{'
# is at position 1, so _is_valid_quantifier is called with start_pos=1.
# After consuming the digit '1', j reaches position 3 where pattern[3]==','.
# At that point j+1 == 4 == len('x{1,'), so the short-circuit fires.
# ---------------------------------------------------------------------------


def test_is_valid_quantifier_comma_at_end_of_string() -> None:
    """Quantifier helper returns False when a comma appears at the last position."""
    checker = _strict_checker()

    # Direct call: '{1,' with start_pos=0 → digit consumed → j reaches ','
    # at the final position → j+1 >= len → branch 220->230 taken.
    result = checker._is_valid_quantifier("{1,", 0)

    assert result is False


def test_unescaped_brace_detection_with_comma_at_string_end() -> None:
    """visit_regex_string reports unescaped brace for /x{1,/ (comma at end).

    This also exercises the 220->230 branch through _check_unescaped_braces,
    which calls _is_valid_quantifier on the '{' character found in the regex.
    """
    checker = _strict_checker()
    node = RegexString(identifier="$r", regex="x{1,", modifiers=[])

    checker.visit_regex_string(node)

    unescaped = [i for i in checker.issues if i.issue_type == "unescaped_brace"]
    assert len(unescaped) == 1


# ---------------------------------------------------------------------------
# Line 285: _check_hex_jump_bound early-return when value is None
#
# HexJump(None, None) passes None for both bounds.  The first statement inside
# _check_hex_jump_bound is ``if value is None: return``, which is line 285.
# validate_hex_bounds is True under yarax_strict(), so visit_hex_jump is
# entered and _check_hex_jump_bound is called for both bounds.
# ---------------------------------------------------------------------------


def test_hex_jump_none_bounds_produces_no_issues() -> None:
    """An unbounded hex jump (None, None) generates no compatibility issues."""
    checker = _strict_checker()

    # HexJump with both bounds None represents [- -] in YARA syntax.
    checker.visit_hex_jump(HexJump(None, None))

    bound_issues = [i for i in checker.issues if i.issue_type == "hex_jump_invalid_bound"]
    assert bound_issues == []


def test_hex_jump_none_min_and_positive_max_produces_no_issues() -> None:
    """A hex jump with None minimum and a valid maximum is not flagged."""
    checker = _strict_checker()

    checker.visit_hex_jump(HexJump(None, 10))

    bound_issues = [i for i in checker.issues if i.issue_type == "hex_jump_invalid_bound"]
    assert bound_issues == []


# ---------------------------------------------------------------------------
# Line 381: visit_unary_expression
#
# The checker inherits a visit_unary_expression method that delegates to
# _visit_ast_value on the operand.  It is reached only when the rule
# condition is (or contains) a UnaryExpression AST node.
# ---------------------------------------------------------------------------


def test_visit_unary_expression_traverses_operand() -> None:
    """Checker traverses a UnaryExpression operand without raising errors."""
    checker = _strict_checker()
    # 'not true' produces UnaryExpression('not', BooleanLiteral(True))
    yara_file = _file_with_condition("r_unary", UnaryExpression("not", BooleanLiteral(True)))

    issues = checker.check(yara_file)

    assert issues == []


# ---------------------------------------------------------------------------
# Line 384: visit_parentheses_expression
# ---------------------------------------------------------------------------


def test_visit_parentheses_expression_traverses_inner_expression() -> None:
    """Checker traverses a parenthesised condition without raising errors."""
    checker = _strict_checker()
    yara_file = _file_with_condition("r_paren", ParenthesesExpression(BooleanLiteral(True)))

    issues = checker.check(yara_file)

    assert issues == []


# ---------------------------------------------------------------------------
# Lines 390-391: visit_range_expression
#
# RangeExpression appears as the ``range`` attribute of InExpression.  When
# visit_in_expression calls _visit_ast_value(node.range), that triggers
# node.range.accept(checker), which dispatches to visit_range_expression.
# ---------------------------------------------------------------------------


def test_visit_range_expression_traverses_low_and_high() -> None:
    """Checker traverses a RangeExpression's bounds without raising errors."""
    checker = _strict_checker()
    range_node = RangeExpression(low=IntegerLiteral(0), high=IntegerLiteral(100))
    yara_file = _file_with_condition("r_range", InExpression(subject="$a", range=range_node))

    issues = checker.check(yara_file)

    assert issues == []


# ---------------------------------------------------------------------------
# Line 402: visit_member_access
# ---------------------------------------------------------------------------


def test_visit_member_access_traverses_object() -> None:
    """Checker traverses a MemberAccess node without raising errors."""
    checker = _strict_checker()
    node = MemberAccess(object=Identifier(name="pe"), member="number_of_sections")
    yara_file = _file_with_condition("r_member", node)

    issues = checker.check(yara_file)

    assert issues == []


# ---------------------------------------------------------------------------
# Line 409: visit_defined_expression
# ---------------------------------------------------------------------------


def test_visit_defined_expression_traverses_inner_expression() -> None:
    """Checker traverses a DefinedExpression node without raising errors."""
    checker = _strict_checker()
    node = DefinedExpression(expression=Identifier(name="pe"))
    yara_file = _file_with_condition("r_defined", node)

    issues = checker.check(yara_file)

    assert issues == []


# ---------------------------------------------------------------------------
# Lines 412-413: visit_string_operator_expression
# ---------------------------------------------------------------------------


def test_visit_string_operator_expression_traverses_operands() -> None:
    """Checker traverses a StringOperatorExpression node without raising errors."""
    checker = _strict_checker()
    node = StringOperatorExpression(
        left=StringLiteral("hello"),
        operator="contains",
        right=StringLiteral("ell"),
    )
    yara_file = _file_with_condition("r_str_op", node)

    issues = checker.check(yara_file)

    assert issues == []


# ---------------------------------------------------------------------------
# Lines 416-418: visit_for_expression
# ---------------------------------------------------------------------------


def test_visit_for_expression_traverses_quantifier_iterable_and_body() -> None:
    """Checker traverses a ForExpression node without raising errors."""
    checker = _strict_checker()
    node = ForExpression(
        quantifier="any",
        variable="i",
        iterable=RangeExpression(low=IntegerLiteral(0), high=IntegerLiteral(10)),
        body=BooleanLiteral(True),
    )
    yara_file = _file_with_condition("r_for", node)

    issues = checker.check(yara_file)

    assert issues == []


# ---------------------------------------------------------------------------
# Lines 421-423: visit_for_of_expression
#
# ForOfExpression accepts an optional condition argument (third positional
# parameter).  The visitor dispatches _visit_ast_value on all three: quantifier,
# string_set, and condition.
# ---------------------------------------------------------------------------


def test_visit_for_of_expression_traverses_quantifier_set_and_condition() -> None:
    """Checker traverses a ForOfExpression node including optional condition."""
    checker = _strict_checker()
    node = ForOfExpression(
        quantifier="any",
        string_set=["$a"],
        condition=BooleanLiteral(True),
    )
    yara_file = _file_with_condition("r_forof", node)

    issues = checker.check(yara_file)

    assert issues == []


def test_visit_for_of_expression_without_condition_traverses_cleanly() -> None:
    """Checker traverses ForOfExpression with condition=None without errors."""
    checker = _strict_checker()
    node = ForOfExpression(quantifier="all", string_set=["$b"])
    yara_file = _file_with_condition("r_forof_no_cond", node)

    issues = checker.check(yara_file)

    assert issues == []


# ---------------------------------------------------------------------------
# Lines 430-431: visit_in_expression
# ---------------------------------------------------------------------------


def test_visit_in_expression_traverses_subject_and_range() -> None:
    """Checker traverses an InExpression node's subject and range."""
    checker = _strict_checker()
    node = InExpression(
        subject=IntegerLiteral(1),
        range=RangeExpression(low=IntegerLiteral(0), high=IntegerLiteral(100)),
    )
    yara_file = _file_with_condition("r_in", node)

    issues = checker.check(yara_file)

    assert issues == []


# ---------------------------------------------------------------------------
# Line 536->533: _get_yarax_features_used deduplication branch
#
# The method builds a list of feature strings found in issues, skipping
# duplicates.  The branch fires when a feature already appears in the list.
# We inject two issues with identical yarax_feature messages directly so that
# the dedup path (feature already in list → do not append) is exercised.
# ---------------------------------------------------------------------------


def test_get_yarax_features_used_deduplicates_repeated_feature_name() -> None:
    """_get_yarax_features_used returns each feature at most once."""
    checker = _strict_checker()
    # Inject two issues carrying the same YARA-X feature label.
    checker.issues.append(
        CompatibilityIssue("error", None, "yarax_feature", "Using YARA-X feature: with statements")
    )
    checker.issues.append(
        CompatibilityIssue("error", None, "yarax_feature", "Using YARA-X feature: with statements")
    )

    features = checker._get_yarax_features_used()

    assert features == ["with statements"]


def test_get_report_deduplicates_yarax_features_in_report() -> None:
    """get_report() surfaces each YARA-X feature label only once."""
    checker = _strict_checker()
    checker.issues.append(
        CompatibilityIssue("error", None, "yarax_feature", "Using YARA-X feature: with statements")
    )
    checker.issues.append(
        CompatibilityIssue("error", None, "yarax_feature", "Using YARA-X feature: with statements")
    )

    report = checker.get_report()

    assert report["yarax_features_used"].count("with statements") == 1
