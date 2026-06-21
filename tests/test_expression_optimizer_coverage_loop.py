# Copyright (c) 2026 Marc Rivero López
# Licensed under GPLv3. See LICENSE file for details.
# This test suite validates real code behavior without mocks or stubs.

"""Regression tests targeting uncovered branches in expression_optimizer.py.

Missing lines before this file (95.95%):
  83        - _fold_arithmetic: modulo INT64_MIN / -1 overflow sentinel
  91        - _fold_arithmetic: right-shift with negative shift amount sentinel
  112       - _is_static_numeric_identity_operand: Identifier branch
  179, 181  - _simplify_boolean_short_circuit: right-True-and and right-False-or identity
  188, 198  - _is_empty_integer_range: None literal guard and high < low path
  223->exit, 226->exit  - @overload stubs (structurally unreachable at runtime)
  295-296   - visit_binary_expression: identity-simplification early-return
  443->445, 445->447, 447->449  - visit_for_of_expression: tuple/set/frozenset string_set
  466, 468  - _optimize_ast_value: set comprehension body and plain-value fallback
"""

from __future__ import annotations

from typing import Any, cast

from yaraast.ast.conditions import ForOfExpression, InExpression, OfExpression
from yaraast.ast.expressions import (
    BinaryExpression,
    BooleanLiteral,
    Identifier,
    IntegerLiteral,
    RangeExpression,
    StringIdentifier,
)
from yaraast.ast.operators import DefinedExpression
from yaraast.optimization.expression_optimizer import ExpressionOptimizer
from yaraast.shared.integer_semantics import INT64_MIN

# ---------------------------------------------------------------------------
# _fold_arithmetic: overflow sentinels (lines 83 and 91)
# ---------------------------------------------------------------------------


def test_fold_arithmetic_modulo_int64_min_over_minus_one_returns_node() -> None:
    """INT64_MIN % -1 would overflow; the optimizer must leave the node unchanged."""
    opt = ExpressionOptimizer()
    # Arrange: INT64_MIN % -1 is the overflow case for the modulo path
    node = BinaryExpression(IntegerLiteral(INT64_MIN), "%", IntegerLiteral(-1))

    # Act
    result = opt.visit(node)

    # Assert: node is returned unchanged; no optimization is counted
    assert result is node
    assert opt.optimization_count == 0


def test_fold_arithmetic_right_shift_by_negative_amount_returns_node() -> None:
    """A right-shift by a negative amount is undefined; the node must survive unmodified."""
    opt = ExpressionOptimizer()
    # Arrange: shift-right by -1 is not a valid operation
    node = BinaryExpression(IntegerLiteral(8), ">>", IntegerLiteral(-1))

    # Act
    result = opt.visit(node)

    # Assert: sentinel path taken, node returned as-is
    assert result is node
    assert opt.optimization_count == 0


# ---------------------------------------------------------------------------
# _is_static_numeric_identity_operand: Identifier branch (line 112)
# ---------------------------------------------------------------------------


def test_identity_simplification_filesize_plus_zero_yields_filesize() -> None:
    """filesize + 0 -> filesize: exercises the Identifier branch of _is_static_numeric_identity_operand."""
    opt = ExpressionOptimizer()
    # Arrange: filesize is a known numeric identity operand
    node = BinaryExpression(Identifier("filesize"), "+", IntegerLiteral(0))

    # Act
    result = opt.optimize(node)

    # Assert: identity eliminated, result is the Identifier itself
    assert result == Identifier("filesize")
    assert opt.optimization_count == 1


def test_identity_simplification_entrypoint_times_one_yields_entrypoint() -> None:
    """entrypoint * 1 -> entrypoint: second known-numeric Identifier name."""
    opt = ExpressionOptimizer()
    node = BinaryExpression(Identifier("entrypoint"), "*", IntegerLiteral(1))

    result = opt.optimize(node)

    assert result == Identifier("entrypoint")
    assert opt.optimization_count == 1


def test_identity_simplification_unknown_identifier_plus_zero_not_simplified() -> None:
    """An Identifier whose name is not filesize/entrypoint must not be treated as numeric."""
    opt = ExpressionOptimizer()
    # Arrange: pe.size is not in the known-numeric set
    node = BinaryExpression(Identifier("pe.size"), "+", IntegerLiteral(0))

    result = opt.optimize(node)

    # Assert: node unchanged; the Identifier branch returns False
    assert result == node
    assert opt.optimization_count == 0


# ---------------------------------------------------------------------------
# visit_binary_expression: identity-simplification early-return (lines 295-296)
# ---------------------------------------------------------------------------


def test_visit_binary_expression_identity_increments_count() -> None:
    """The identity path inside visit_binary_expression increments optimization_count."""
    opt = ExpressionOptimizer()
    # Arrange: 0 + filesize triggers _simplify_identity with count=1
    node = BinaryExpression(IntegerLiteral(0), "+", Identifier("filesize"))

    result = opt.visit(node)

    # Assert: result is the Identifier and count reflects the single simplification
    assert result == Identifier("filesize")
    assert opt.optimization_count == 1


# ---------------------------------------------------------------------------
# _simplify_boolean_short_circuit: right-True-and and right-False-or identities
# (lines 179 and 181)
# ---------------------------------------------------------------------------


def test_boolean_short_circuit_string_identifier_and_true_yields_identifier() -> None:
    """(string_id and True) -> string_id: exercises line 179."""
    opt = ExpressionOptimizer()
    # Arrange: right side is BooleanLiteral(True) with 'and'; left is static bool identity
    node = BinaryExpression(StringIdentifier("$a"), "and", BooleanLiteral(True))

    result = opt.optimize(node)

    # Assert: (X and True) simplifies to X when X is a string identifier
    assert result == StringIdentifier("$a")
    assert opt.optimization_count == 1


def test_boolean_short_circuit_string_identifier_or_false_yields_identifier() -> None:
    """(string_id or False) -> string_id: exercises line 181."""
    opt = ExpressionOptimizer()
    # Arrange: right side is BooleanLiteral(False) with 'or'
    node = BinaryExpression(StringIdentifier("$b"), "or", BooleanLiteral(False))

    result = opt.optimize(node)

    # Assert: (X or False) simplifies to X
    assert result == StringIdentifier("$b")
    assert opt.optimization_count == 1


def test_boolean_short_circuit_defined_expr_and_true_yields_defined_expr() -> None:
    """(defined(expr) and True) -> defined(expr): another static-bool-identity operand."""
    opt = ExpressionOptimizer()
    inner = DefinedExpression(Identifier("pe.size"))
    node = BinaryExpression(inner, "and", BooleanLiteral(True))

    result = opt.optimize(node)

    # Assert: the result is the DefinedExpression itself (with its inner visited)
    assert isinstance(result, DefinedExpression)
    assert opt.optimization_count == 1


# ---------------------------------------------------------------------------
# _is_empty_integer_range: None-value guard (line 198) and empty-range path
# ---------------------------------------------------------------------------


def test_is_empty_integer_range_guards_against_none_literal_value() -> None:
    """A RangeExpression whose IntegerLiteral carries a bool value yields None from
    _integer_literal_value; _is_empty_integer_range must return False without crashing."""
    opt = ExpressionOptimizer()
    # Arrange: IntegerLiteral(True) has a bool value -> _integer_literal_value returns None
    malformed_range = RangeExpression(
        low=IntegerLiteral(cast(Any, True)),
        high=IntegerLiteral(5),
    )
    in_node = InExpression(subject=StringIdentifier("$x"), range=malformed_range)

    # Act: visiting must not raise and must not fold (range is not provably empty)
    result = opt.visit(in_node)

    # Assert: node returned unchanged
    assert result is in_node
    assert opt.optimization_count == 0


def test_is_empty_integer_range_unwraps_parentheses_expression() -> None:
    """_is_empty_integer_range must unwrap a ParenthesesExpression to reach the inner range.

    visit_parentheses_expression preserves a RangeExpression (it is not a literal or identifier),
    so the InExpression visitor receives a ParenthesesExpression-wrapped range.
    The unwrapping branch (source line 188: ``node = node.expression``) must execute
    and still identify the range as empty, yielding BooleanLiteral(False)."""
    opt = ExpressionOptimizer()
    # Arrange: (10..5) wrapped in parentheses, high < low -> empty
    from yaraast.ast.expressions import ParenthesesExpression

    wrapped_range = ParenthesesExpression(
        expression=RangeExpression(
            low=IntegerLiteral(10),
            high=IntegerLiteral(5),
        )
    )
    in_node = InExpression(subject=StringIdentifier("$w"), range=wrapped_range)

    # Act
    result = opt.optimize(in_node)

    # Assert: range identified as empty through ParenthesesExpression unwrapping
    assert result == BooleanLiteral(False)
    assert opt.optimization_count == 1


def test_visit_in_expression_with_empty_range_folds_to_false() -> None:
    """An InExpression whose range has high < low is provably empty -> BooleanLiteral(False)."""
    opt = ExpressionOptimizer()
    # Arrange: (10..5) is an empty range
    empty_range = RangeExpression(
        low=IntegerLiteral(10),
        high=IntegerLiteral(5),
    )
    in_node = InExpression(subject=StringIdentifier("$y"), range=empty_range)

    # Act
    result = opt.optimize(in_node)

    # Assert: folded to False, one optimization counted
    assert result == BooleanLiteral(False)
    assert opt.optimization_count == 1


# ---------------------------------------------------------------------------
# _optimize_ast_value: tuple, set, frozenset branches and plain-value fallback
# (lines 443->445, 445->447, 447->449, 466, 468)
# ---------------------------------------------------------------------------


def test_optimize_ast_value_tuple_string_set_is_preserved() -> None:
    """A ForOfExpression with a tuple string_set traverses the tuple branch in _optimize_ast_value."""
    opt = ExpressionOptimizer()
    # Arrange: string_set is a tuple of plain strings (no AST nodes to recurse into)
    node = ForOfExpression(quantifier="any", string_set=("$a", "$b"), condition=None)

    result = opt.visit(node)

    # Assert: the string_set tuple is reconstructed and members are unchanged
    assert isinstance(result, ForOfExpression)
    assert result.string_set == ("$a", "$b")


def test_optimize_ast_value_set_string_set_is_preserved() -> None:
    """A ForOfExpression with a set string_set traverses the set branch."""
    opt = ExpressionOptimizer()
    node = ForOfExpression(quantifier="any", string_set={"$c", "$d"}, condition=None)

    result = opt.visit(node)

    assert isinstance(result, ForOfExpression)
    assert result.string_set == {"$c", "$d"}


def test_optimize_ast_value_frozenset_string_set_is_preserved() -> None:
    """A ForOfExpression with a frozenset string_set traverses the frozenset branch."""
    opt = ExpressionOptimizer()
    node = ForOfExpression(quantifier="any", string_set=frozenset({"$e"}), condition=None)

    result = opt.visit(node)

    assert isinstance(result, ForOfExpression)
    assert result.string_set == frozenset({"$e"})


def test_optimize_ast_value_plain_string_quantifier_returned_unchanged() -> None:
    """A plain string quantifier ('any', 'all', 'none') reaches the fallback return (line 468)."""
    opt = ExpressionOptimizer()
    # OfExpression quantifier is a plain string -> hits _optimize_ast_value plain-value path
    node = OfExpression(quantifier="any", string_set=["$f"])

    result = opt.visit(node)

    # Assert: quantifier unchanged, traversal completed without error
    assert isinstance(result, OfExpression)
    assert result.quantifier == "any"


def test_optimize_ast_value_integer_quantifier_returned_unchanged() -> None:
    """A plain integer quantifier also reaches the plain-value fallback."""
    opt = ExpressionOptimizer()
    node = OfExpression(quantifier=2, string_set=["$g", "$h"])

    result = opt.visit(node)

    assert isinstance(result, OfExpression)
    assert result.quantifier == 2


# ---------------------------------------------------------------------------
# @overload stubs: confirmed structurally unreachable at runtime
# ---------------------------------------------------------------------------


def test_overload_stubs_are_not_executable_at_runtime() -> None:
    """The @overload-decorated stubs at lines 222-226 exist for the type checker only.

    They are re-bound by the overload decorator so that calling the implementation
    dispatches to the real method body.  There is no runtime path that executes the
    stub bodies; this test documents that confirmed structural dead-code so the
    project record is accurate.
    """
    opt = ExpressionOptimizer()
    # Calling .optimize() on a real Expression dispatches to the concrete body,
    # not to the stub.  The stub body is `...` and is never run.
    result = opt.optimize(BooleanLiteral(True))
    # The real implementation returns the expression unchanged (no optimization needed).
    assert result == BooleanLiteral(True)
    assert opt.optimization_count == 0


# ---------------------------------------------------------------------------
# Structurally dead branches: documented and confirmed unreachable
# ---------------------------------------------------------------------------


def test_integer_literal_branch_of_is_static_numeric_identity_operand_is_dead() -> None:
    """Document that the IntegerLiteral branch of _is_static_numeric_identity_operand
    (source line 112) is structurally unreachable through the current optimizer flow.

    Reasoning: _simplify_identity is called from visit_binary_expression only AFTER the
    constant-folding block (lines 276-290).  Whenever both operands are IntegerLiterals,
    the constant-folding block always handles the expression first (addition and
    multiplication never produce a _SENTINEL result).  Whenever one operand is an
    IntegerLiteral with a bool value, _integer_literal_value returns None and the
    folding block returns the node early (line 280) before _simplify_identity is reached.
    Therefore no execution path can supply an IntegerLiteral to _is_static_numeric_identity_operand.

    This test validates observable behavior of the identity path using a non-IntegerLiteral
    numeric operand (Identifier) so that future refactoring remains regression-safe.
    """
    opt = ExpressionOptimizer()
    # The identity path is exercised via an Identifier operand (line 113), not line 112.
    node = BinaryExpression(IntegerLiteral(1), "*", Identifier("filesize"))
    result = opt.optimize(node)
    # 1 * filesize -> filesize (identity simplification via Identifier branch)
    assert result == Identifier("filesize")
    assert opt.optimization_count == 1


def test_hasattr_false_branches_in_visit_for_of_expression_are_unreachable() -> None:
    """Document that the False branches of hasattr() guards in visit_for_of_expression
    (branch arcs 443->445 and 445->447) are structurally unreachable with real AST nodes.

    ForOfExpression is a dataclass that always declares 'quantifier', 'string_set', and
    'condition' fields; hasattr() on a real instance is always True for those names.
    The visit() dispatch requires a real ASTNode (the visitor raises TypeError otherwise),
    so there is no execution path that passes a node lacking these attributes to
    visit_for_of_expression.

    This test documents the observable behavior to keep the test suite honest about
    why those branch arcs cannot be driven to False without bypassing the visitor contract.
    """
    opt = ExpressionOptimizer()
    # All three hasattr() checks evaluate to True for a real ForOfExpression.
    node = ForOfExpression(
        quantifier="all",
        string_set=["$a", "$b"],
        condition=BooleanLiteral(True),
    )
    result = opt.visit(node)
    # Condition BooleanLiteral(True) is unchanged; quantifier and string_set pass through.
    assert isinstance(result, ForOfExpression)
    assert result.quantifier == "all"
