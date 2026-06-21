# Copyright (c) 2026 Marc Rivero López
# Licensed under GPLv3. See LICENSE file for details.
# This test suite validates real code behavior without mocks or stubs.
"""Regression tests for yaraast/metrics/dependency_graph_finder.py.

Missing lines addressed (from coverage report at 93.53%):

  80            visit_for_of_expression: quantifier is an AST node with accept()
  84->exit      visit_for_of_expression: condition is None branch (dead after line 81-83)
  85            visit_for_of_expression: condition is not None, visits it
  121           visit_string_wildcard: bare '*' pattern, empty prefix -> early return
  133           _record_rule_set_text: value is a local variable -> early return
  135-136       _record_rule_set_text: value ends with '*', dispatches visit_string_wildcard
  137->exit     _record_rule_set_text: value equals current_rule -> no dependency added
  162           _visit_rule_set_value: fallback branch -> _visit_ast_value
  189->191      visit_dict_comprehension: value_variable is None, skips names.append
  219->exit     _define_local: local_scopes is empty -> no-op

All tests construct real AST nodes and invoke DependencyFinder methods directly,
exercising the genuine production code paths without any mocking.
"""

from __future__ import annotations

from yaraast.ast.conditions import ForOfExpression
from yaraast.ast.expressions import (
    Identifier,
    IntegerLiteral,
    ParenthesesExpression,
    SetExpression,
    StringLiteral,
    StringWildcard,
)
from yaraast.metrics.dependency_graph_finder import DependencyFinder
from yaraast.yarax.ast_nodes import DictComprehension

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _finder(current: str, all_rules: set[str]) -> DependencyFinder:
    """Return a DependencyFinder initialised with the given rule universe."""
    return DependencyFinder(current, all_rules)


# ---------------------------------------------------------------------------
# visit_for_of_expression
# ---------------------------------------------------------------------------


def test_for_of_expression_quantifier_with_accept_visits_quantifier() -> None:
    """Line 80: when the quantifier is an AST node, visit() is called on it.

    Using an Identifier as the quantifier exercises the hasattr(accept) branch
    so line 80 executes.  The identifier names rule_b which is in all_rules and
    not the current rule, so it is recorded as a dependency.
    """
    # Arrange
    finder = _finder("rule_a", {"rule_a", "rule_b"})
    quantifier_node = Identifier("rule_b")  # AST node: has accept()
    node = ForOfExpression(quantifier=quantifier_node, string_set="them", condition=None)

    # Act
    finder.visit_for_of_expression(node)

    # Assert
    assert "rule_b" in finder.dependencies


def test_for_of_expression_condition_not_none_visits_condition() -> None:
    """Lines 84->exit and 85: condition is not None, so it is visited.

    The guard on line 84 (``if node.condition is not None``) is always True
    when we reach it — the None branch already returned at line 83.  This test
    reaches line 85 by providing a non-None condition that names rule_b.
    """
    # Arrange
    finder = _finder("rule_a", {"rule_a", "rule_b"})
    condition_node = Identifier("rule_b")
    node = ForOfExpression(quantifier="any", string_set="them", condition=condition_node)

    # Act
    finder.visit_for_of_expression(node)

    # Assert
    assert "rule_b" in finder.dependencies


def test_for_of_expression_condition_none_does_not_visit_condition() -> None:
    """Line 82-83: condition is None, string_set is visited and we return early.

    Ensures the None path is exercised and no dependency is introduced via a
    bare 'them' string_set (which refers to pattern strings, not rules).
    """
    # Arrange
    finder = _finder("rule_a", {"rule_a", "rule_b"})
    node = ForOfExpression(quantifier="any", string_set="them", condition=None)

    # Act
    finder.visit_for_of_expression(node)

    # Assert: 'them' is not a cross-rule dependency
    assert finder.dependencies == set()


# ---------------------------------------------------------------------------
# visit_string_wildcard
# ---------------------------------------------------------------------------


def test_string_wildcard_bare_asterisk_returns_without_adding_dependencies() -> None:
    """Line 121: pattern '*' strips the trailing '*', leaving an empty prefix.

    _is_local and rule name matching rely on a non-empty prefix.  The empty
    prefix guard on line 120-121 returns immediately so no rules are added.
    """
    # Arrange: rules exist that would match any non-empty prefix
    finder = _finder("rule_a", {"rule_a", "rule_abc", "rule_xyz"})
    wildcard_node = StringWildcard("*")

    # Act
    finder.visit_string_wildcard(wildcard_node)

    # Assert: nothing was added
    assert finder.dependencies == set()


# ---------------------------------------------------------------------------
# _record_rule_set_text
# ---------------------------------------------------------------------------


def test_record_rule_set_text_local_variable_returns_early() -> None:
    """Line 133: when the value is shadowed by an active local scope, no dep is added.

    The local scope is pushed with 'rule_b' (a name that is also in all_rules).
    Because _is_local returns True the method returns at line 133.
    """
    # Arrange
    finder = _finder("rule_a", {"rule_a", "rule_b"})
    finder._push_local_scope("rule_b")  # shadows rule_b

    # Act
    finder._record_rule_set_text("rule_b")

    # Assert
    assert finder.dependencies == set()


def test_record_rule_set_text_wildcard_suffix_dispatches_visit_string_wildcard() -> None:
    """Lines 135-136: a value ending with '*' is forwarded to visit_string_wildcard.

    This ensures the wildcard expansion path collects all matching rule names.
    """
    # Arrange
    finder = _finder("rule_a", {"rule_a", "rule_b", "rule_bc", "other_rule"})

    # Act: 'rule_b*' should match rule_b and rule_bc but not rule_a or other_rule
    finder._record_rule_set_text("rule_b*")

    # Assert
    assert "rule_b" in finder.dependencies
    assert "rule_bc" in finder.dependencies
    assert "rule_a" not in finder.dependencies
    assert "other_rule" not in finder.dependencies


def test_record_rule_set_text_self_reference_adds_no_dependency() -> None:
    """Line 137->exit: value is a known rule but equals the current rule.

    The condition ``value in self.all_rules and value != self.current_rule``
    is False when value == current_rule, so no dependency is recorded.
    """
    # Arrange
    finder = _finder("rule_a", {"rule_a", "rule_b"})

    # Act: 'rule_a' is in all_rules but is the current rule
    finder._record_rule_set_text("rule_a")

    # Assert
    assert finder.dependencies == set()


# ---------------------------------------------------------------------------
# _visit_rule_set_value
# ---------------------------------------------------------------------------


def test_visit_rule_set_value_unknown_node_type_falls_through_to_ast_value() -> None:
    """Line 162: an AST node that is none of the specialised types is dispatched
    via _visit_ast_value.

    IntegerLiteral has an accept() method but is not Identifier, StringLiteral,
    StringWildcard, ParenthesesExpression, or SetExpression, so the final
    fallback at line 162 is reached.  The visitor handles it without error and
    no cross-rule dependency is produced.
    """
    # Arrange
    finder = _finder("rule_a", {"rule_a", "rule_b"})
    int_node = IntegerLiteral(42)  # none of the special-cased types

    # Act
    finder._visit_rule_set_value(int_node)

    # Assert
    assert finder.dependencies == set()


def test_visit_rule_set_value_parentheses_expression_recurses() -> None:
    """Lines 155-157: ParenthesesExpression is unwrapped and its inner value visited.

    Wrapping rule_b inside a ParenthesesExpression means the Identifier branch
    is reached after unwrapping.
    """
    # Arrange
    finder = _finder("rule_a", {"rule_a", "rule_b"})
    inner = Identifier("rule_b")
    paren_node = ParenthesesExpression(inner)

    # Act
    finder._visit_rule_set_value(paren_node)

    # Assert
    assert "rule_b" in finder.dependencies


def test_visit_rule_set_value_set_expression_visits_all_elements() -> None:
    """Lines 158-161: SetExpression iterates over its elements.

    Both elements should produce dependencies if they are known rule names.
    """
    # Arrange
    from yaraast.ast.expressions import Expression

    finder = _finder("rule_a", {"rule_a", "rule_b", "rule_c"})
    elements: list[Expression] = [Identifier("rule_b"), Identifier("rule_c")]
    set_node = SetExpression(elements)

    # Act
    finder._visit_rule_set_value(set_node)

    # Assert
    assert {"rule_b", "rule_c"} == finder.dependencies


def test_visit_rule_set_value_string_literal_is_ignored() -> None:
    """Lines 150-151: StringLiteral is a no-op (pattern string, not a rule name)."""
    # Arrange
    finder = _finder("rule_a", {"rule_a", "rule_b"})
    lit = StringLiteral("$my_string")

    # Act
    finder._visit_rule_set_value(lit)

    # Assert
    assert finder.dependencies == set()


def test_visit_rule_set_value_string_wildcard_collects_matching_rules() -> None:
    """Lines 152-154: StringWildcard is forwarded to visit_string_wildcard."""
    # Arrange
    finder = _finder("rule_a", {"rule_a", "rule_b", "rule_c"})
    wildcard = StringWildcard("rule_*")

    # Act
    finder._visit_rule_set_value(wildcard)

    # Assert: all non-current rules starting with 'rule_' are included
    assert "rule_b" in finder.dependencies
    assert "rule_c" in finder.dependencies
    assert "rule_a" not in finder.dependencies


# ---------------------------------------------------------------------------
# visit_dict_comprehension
# ---------------------------------------------------------------------------


def test_dict_comprehension_single_variable_skips_value_variable_append() -> None:
    """Line 189->191: value_variable is None, so names.append is not called.

    Only key_variable is pushed into the local scope.  key_expression naming
    rule_b is visited, but because rule_b was pushed as part of key_variable
    local scope expansion it may or may not shadow rule_b — what matters is
    the branch is exercised and no exception is raised.

    We use a key_variable name that does NOT match rule_b to confirm the
    dependency is recorded.
    """
    # Arrange: key_variable='k', value_variable=None
    finder = _finder("rule_a", {"rule_a", "rule_b"})
    dc = DictComprehension(
        key_expression=Identifier("rule_b"),
        value_expression=None,
        key_variable="k",
        value_variable=None,
        iterable=None,
        condition=None,
    )

    # Act
    finder.visit_dict_comprehension(dc)

    # Assert: rule_b referenced in key_expression becomes a dependency
    assert "rule_b" in finder.dependencies


def test_dict_comprehension_with_value_variable_includes_both_in_scope() -> None:
    """Line 190: value_variable is set, so names.append executes.

    Both key_variable and value_variable are pushed into the local scope.
    A rule name used as key_expression that is distinct from both loop
    variables still becomes a dependency.
    """
    # Arrange: key_variable='k', value_variable='v'
    finder = _finder("rule_a", {"rule_a", "rule_b"})
    dc = DictComprehension(
        key_expression=Identifier("rule_b"),
        value_expression=None,
        key_variable="k",
        value_variable="v",
        iterable=None,
        condition=None,
    )

    # Act
    finder.visit_dict_comprehension(dc)

    # Assert
    assert "rule_b" in finder.dependencies


# ---------------------------------------------------------------------------
# _define_local
# ---------------------------------------------------------------------------


def test_define_local_with_empty_local_scopes_is_a_noop() -> None:
    """Line 219->exit: _define_local is called before any scope is pushed.

    When local_scopes is empty the guard on line 219 is False and the method
    returns without modifying any state.  This is a legitimate call-site
    scenario where a visitor invokes _define_local outside of a scoped block.
    """
    # Arrange
    finder = _finder("rule_a", {"rule_a", "rule_b"})
    assert finder.local_scopes == []

    # Act: should not raise and must leave local_scopes empty
    finder._define_local("myvar")

    # Assert
    assert finder.local_scopes == []
    assert finder.dependencies == set()


def test_define_local_with_active_scope_updates_innermost_scope() -> None:
    """Line 219 True branch: when a scope exists _define_local mutates it.

    This confirms the True path is already covered and that the value is
    correctly shadowed afterwards.
    """
    # Arrange
    finder = _finder("rule_a", {"rule_a", "rule_b"})
    finder._push_local_scope()  # push an empty scope
    assert len(finder.local_scopes) == 1

    # Act: plain identifier — local_name_variants("rule_b", allow_string_identifier=True)
    # produces {"rule_b"}, which shadows the rule name.
    finder._define_local("rule_b")

    # Assert: rule_b is now shadowed in the innermost scope
    assert finder._is_local("rule_b")
    assert finder.local_scopes[0]  # scope is non-empty
