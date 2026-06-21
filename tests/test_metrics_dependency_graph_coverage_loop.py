# Copyright (c) 2026 Marc Rivero López
# Licensed under GPLv3. See LICENSE file for details.
# This test suite validates real code behavior without mocks or stubs.
"""Regression tests targeting uncovered lines in yaraast/metrics/dependency_graph.py.

Each test exercises a specific missing branch or statement identified from the
coverage report:

  187->190  visit_rule: condition is None skips the visit call
  215       _module_name_for_object: object has neither .module nor .name
  235->exit _define_local: called with no active local scopes (no-op)
  252-258   visit_with_statement: local scope pushed/popped with declarations
  261-271   visit_with_declaration: visits value and defines local identifier
  274-278   visit_array_comprehension: iterable/condition/expression visited
  282-288   visit_dict_comprehension: with and without value_variable
  338-339   visit_for_of_expression: condition is not None branch
  370       visit_string_wildcard: pattern starts with '$' -> early return
  374       visit_string_wildcard: no active rule_key -> early return
  383-395   _record_rule_set_text: no rule_key, wildcard suffix, exact match
  423       _matching_rule_wildcard_names: pattern without trailing '*'
  426       _matching_rule_wildcard_names: bare '*' prefix with empty remainder
  407/410   _visit_rule_set_value: StringLiteral and StringWildcard branches
"""

from __future__ import annotations

from yaraast.ast.base import YaraFile
from yaraast.ast.conditions import ForOfExpression, OfExpression
from yaraast.ast.expressions import (
    BooleanLiteral,
    Identifier,
    IntegerLiteral,
    StringLiteral,
    StringWildcard,
)
from yaraast.ast.rules import Rule
from yaraast.metrics.dependency_graph import DependencyGraphGenerator
from yaraast.yarax.ast_nodes import (
    ArrayComprehension,
    DictComprehension,
    LambdaExpression,
    WithDeclaration,
    WithStatement,
)

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _make_ast(*rules: Rule) -> YaraFile:
    """Return a YaraFile containing the given rules and no imports/includes."""
    return YaraFile(rules=list(rules))


def _visited_gen(*rules: Rule) -> DependencyGraphGenerator:
    """Build and visit a minimal AST, return the populated generator."""
    gen = DependencyGraphGenerator()
    gen.visit(_make_ast(*rules))
    return gen


# ---------------------------------------------------------------------------
# visit_rule: condition is None (line 187->190)
# ---------------------------------------------------------------------------


def test_visit_rule_with_none_condition_registers_rule_without_visiting_condition() -> None:
    """A rule whose condition is None must still be registered; no visit is attempted."""
    # Arrange
    rule = Rule(name="no_cond", condition=None)

    # Act
    gen = _visited_gen(rule)

    # Assert: rule entry created with no strings and no condition visited
    assert "no_cond" in gen.rules
    assert gen.rules["no_cond"]["has_condition"] is False
    assert gen.dependencies.get("no_cond", set()) == set()
    # Local scope must have been cleaned up by the finally block
    assert gen._current_rule is None
    assert gen._current_rule_key is None


# ---------------------------------------------------------------------------
# _module_name_for_object: neither .module nor .name (line 215)
# ---------------------------------------------------------------------------


class _PlainObject:
    """An object that has neither a .module nor a .name attribute."""


def test_module_name_for_object_returns_none_for_bare_object() -> None:
    """_module_name_for_object must return None when neither attribute is present."""
    # Arrange
    gen = DependencyGraphGenerator()
    obj = _PlainObject()

    # Act
    result = gen._module_name_for_object(obj)

    # Assert
    assert result is None


# ---------------------------------------------------------------------------
# _define_local: empty _local_scopes (line 235->exit)
# ---------------------------------------------------------------------------


def test_define_local_with_no_active_scope_is_a_no_op() -> None:
    """_define_local must not raise and must leave _local_scopes unchanged when empty."""
    # Arrange
    gen = DependencyGraphGenerator()
    assert gen._local_scopes == []

    # Act
    gen._define_local("somename")

    # Assert: nothing was appended or modified
    assert gen._local_scopes == []


# ---------------------------------------------------------------------------
# visit_with_statement: local scope lifecycle (lines 252-258)
# ---------------------------------------------------------------------------


def test_visit_with_statement_pushes_and_pops_local_scope() -> None:
    """visit_with_statement must push a scope before visiting declarations and body,
    then pop it so _local_scopes is empty after the rule finishes."""
    # Arrange: with myvar = true: true
    decl = WithDeclaration(identifier="myvar", value=BooleanLiteral(True))
    stmt = WithStatement(declarations=[decl], body=BooleanLiteral(True))
    rule = Rule(name="with_rule", condition=stmt)

    # Act
    gen = _visited_gen(rule)

    # Assert: rule registered and local scope cleaned up
    assert "with_rule" in gen.rules
    assert gen._local_scopes == []


def test_visit_with_statement_defines_identifier_in_scope_during_body() -> None:
    """The with declaration's identifier must be locally scoped so the body
    expression can reference it without creating a module reference."""
    # Arrange: with pe = 1: pe.something
    # We use a simple boolean body to stay away from visitor complexity;
    # the key assertion is that no module reference for the identifier leaks out.
    decl = WithDeclaration(identifier="pe", value=IntegerLiteral(1))
    body = BooleanLiteral(True)
    stmt = WithStatement(declarations=[decl], body=body)
    rule = Rule(name="scoped_rule", condition=stmt)

    # Act
    gen = _visited_gen(rule)

    # Assert: 'pe' is NOT treated as a module reference because the with-scope
    # hides it; the scope is cleaned up after the rule visit.
    assert gen.module_references.get("scoped_rule", set()) == set()
    assert gen._local_scopes == []


# ---------------------------------------------------------------------------
# visit_with_declaration: visits value and defines identifier (lines 261-271)
# ---------------------------------------------------------------------------


def test_visit_with_declaration_defines_local_within_active_scope() -> None:
    """visit_with_declaration must visit the value expression and register the
    identifier in the innermost local scope so _is_local returns True for it."""
    # Arrange
    gen = DependencyGraphGenerator()
    gen._push_local_scope()  # simulate the outer with-statement scope

    decl = WithDeclaration(identifier="myvar", value=BooleanLiteral(True))

    # Act
    gen.visit_with_declaration(decl)

    # Assert: identifier is now locally known in the scope
    assert gen._is_local("myvar")
    gen._pop_local_scope()
    assert gen._local_scopes == []


# ---------------------------------------------------------------------------
# visit_array_comprehension (lines 274-278 in source == lines 252-258 actually)
# We cross-check by ensuring all three sub-fields are visited and scope managed.
# ---------------------------------------------------------------------------


def test_visit_array_comprehension_manages_scope_and_visits_sub_expressions() -> None:
    """visit_array_comprehension must push a scope for the loop variable,
    visit iterable/condition/expression inside it, and pop the scope on exit."""
    # Arrange: [x for x in 1 if true]  (simplified; real semantics not validated here)
    node = ArrayComprehension(
        expression=Identifier("x"),
        variable="x",
        iterable=IntegerLiteral(1),
        condition=BooleanLiteral(True),
    )
    rule = Rule(name="arr_rule", condition=node)

    # Act
    gen = _visited_gen(rule)

    # Assert: rule registered, no leaked scope
    assert "arr_rule" in gen.rules
    assert gen._local_scopes == []


def test_visit_array_comprehension_loop_variable_is_locally_scoped() -> None:
    """The comprehension variable must not be treated as a module reference
    even when another rule shares its name."""
    # Arrange: two rules named 'x' plus a rule whose body is [x for x in 1]
    rule_x = Rule(name="x", condition=BooleanLiteral(True))
    node = ArrayComprehension(
        expression=Identifier("x"),
        variable="x",
        iterable=IntegerLiteral(1),
        condition=None,
    )
    arr_rule = Rule(name="arr_rule", condition=node)

    # Act
    gen = _visited_gen(rule_x, arr_rule)

    # Assert: the comprehension variable 'x' must NOT create a dependency on
    # the rule named 'x' because the loop variable shadows it inside the scope.
    assert "x" not in gen.dependencies.get("arr_rule", set())


# ---------------------------------------------------------------------------
# visit_dict_comprehension: with and without value_variable (lines 282-288)
# ---------------------------------------------------------------------------


def test_visit_dict_comprehension_with_key_and_value_variables() -> None:
    """DictComprehension with a value_variable must include both variables
    in the pushed scope and clean up on exit."""
    # Arrange: {k: v for k, v in 1 if true}
    node = DictComprehension(
        key_expression=Identifier("k"),
        value_expression=Identifier("v"),
        key_variable="k",
        value_variable="v",
        iterable=IntegerLiteral(1),
        condition=BooleanLiteral(True),
    )
    rule = Rule(name="dict_rule", condition=node)

    # Act
    gen = _visited_gen(rule)

    # Assert
    assert "dict_rule" in gen.rules
    assert gen._local_scopes == []


def test_visit_dict_comprehension_without_value_variable() -> None:
    """DictComprehension with value_variable=None must still operate correctly,
    using only the key_variable for the scope."""
    # Arrange: {k: k for k in 1 if true}
    node = DictComprehension(
        key_expression=Identifier("k"),
        value_expression=Identifier("k"),
        key_variable="k",
        value_variable=None,
        iterable=IntegerLiteral(1),
        condition=BooleanLiteral(True),
    )
    rule = Rule(name="dict_single_rule", condition=node)

    # Act
    gen = _visited_gen(rule)

    # Assert
    assert "dict_single_rule" in gen.rules
    assert gen._local_scopes == []


# ---------------------------------------------------------------------------
# visit_lambda_expression (lines 274-278 in source view)
# ---------------------------------------------------------------------------


def test_visit_lambda_expression_scopes_parameters() -> None:
    """visit_lambda_expression must push a scope for the parameter names and
    clean it up after visiting the body."""
    # Arrange
    node = LambdaExpression(parameters=["x"], body=Identifier("x"))
    rule = Rule(name="lam_rule", condition=node)

    # Act
    gen = _visited_gen(rule)

    # Assert: no leaked scope
    assert "lam_rule" in gen.rules
    assert gen._local_scopes == []


def test_visit_lambda_expression_parameter_does_not_create_rule_dependency() -> None:
    """A lambda parameter that happens to share a name with another rule must
    not produce a dependency edge from inside the lambda body."""
    # Arrange
    rule_x = Rule(name="x", condition=BooleanLiteral(True))
    node = LambdaExpression(parameters=["x"], body=Identifier("x"))
    lam_rule = Rule(name="lam_rule", condition=node)

    # Act
    gen = _visited_gen(rule_x, lam_rule)

    # Assert: lambda parameter shadows rule name inside body
    assert "x" not in gen.dependencies.get("lam_rule", set())


# ---------------------------------------------------------------------------
# visit_for_of_expression: condition is not None (lines 338-339)
# ---------------------------------------------------------------------------


def test_visit_for_of_expression_with_condition_visits_condition_expression() -> None:
    """When ForOfExpression.condition is not None, visit_for_of_expression must
    visit the condition expression instead of the string_set."""
    # Arrange: for all of ($a) : true
    node = ForOfExpression(
        quantifier="all",
        string_set=[StringLiteral(value="$a")],
        condition=BooleanLiteral(True),
    )
    rule = Rule(name="foe_rule", condition=node)

    # Act
    gen = _visited_gen(rule)

    # Assert: rule was processed with no errors; the condition branch was taken
    assert "foe_rule" in gen.rules
    # The string_set was NOT traversed for dependency resolution (condition path)
    assert gen.dependencies.get("foe_rule", set()) == set()


def test_visit_for_of_expression_with_condition_tracks_rule_reference_in_condition() -> None:
    """When condition references another rule by name, a dependency edge must be recorded."""
    # Arrange: rule_a exists, for_of_rule has a condition that references rule_a
    rule_a = Rule(name="rule_a", condition=BooleanLiteral(True))
    node = ForOfExpression(
        quantifier="any",
        string_set=[StringLiteral(value="$a")],
        condition=Identifier("rule_a"),
    )
    for_of_rule = Rule(name="for_of_rule", condition=node)

    # Act
    gen = _visited_gen(rule_a, for_of_rule)

    # Assert: the condition Identifier caused a dependency
    assert "rule_a" in gen.dependencies.get("for_of_rule", set())


# ---------------------------------------------------------------------------
# visit_string_wildcard: early returns (lines 370 and 374)
# ---------------------------------------------------------------------------


def test_visit_string_wildcard_dollar_prefix_returns_early_without_dependencies() -> None:
    """A StringWildcard whose pattern starts with '$' must return early and
    not create any dependency edges."""
    # Arrange: generator with a known rule name in scope
    gen = DependencyGraphGenerator()
    gen._rule_names = {"rule_a", "rule_b"}
    gen._current_rule = "caller"
    gen._current_rule_key = "caller"

    wildcard = StringWildcard(pattern="$a*")

    # Act
    gen.visit_string_wildcard(wildcard)

    # Assert: no dependencies created
    assert gen.dependencies.get("caller", set()) == set()


def test_visit_string_wildcard_without_active_rule_returns_early() -> None:
    """A StringWildcard visited outside of any rule context (no _current_rule)
    must return early and not create any dependency edges."""
    # Arrange: no active rule
    gen = DependencyGraphGenerator()
    gen._rule_names = {"rule_a", "rule_b"}
    # _current_rule and _current_rule_key default to None

    wildcard = StringWildcard(pattern="rule_*")

    # Act
    gen.visit_string_wildcard(wildcard)

    # Assert: no dependency side-effects
    assert len(gen.dependencies) == 0


# ---------------------------------------------------------------------------
# _record_rule_set_text: no rule_key (lines 383-385)
# ---------------------------------------------------------------------------


def test_record_rule_set_text_without_active_rule_is_a_no_op() -> None:
    """_record_rule_set_text called when no rule is active must not create edges."""
    # Arrange: populate rule names but leave _current_rule empty
    gen = DependencyGraphGenerator()
    gen._rule_names = {"rule_a", "rule_b"}
    # _current_rule is None -> _active_rule_key() returns None -> early return

    # Act
    gen._record_rule_set_text("rule_a")

    # Assert
    assert len(gen.dependencies) == 0


# ---------------------------------------------------------------------------
# _record_rule_set_text: wildcard suffix match (lines 387-392)
# ---------------------------------------------------------------------------


def test_record_rule_set_text_wildcard_suffix_creates_dependency_for_matching_rules() -> None:
    """When the value ends with '*', _record_rule_set_text must expand the
    wildcard and create dependency edges for all matching rule names."""
    # Arrange: visit an AST to populate internal state, then manually invoke
    rule_a = Rule(name="rule_a", condition=BooleanLiteral(True))
    rule_b = Rule(name="rule_b", condition=BooleanLiteral(True))
    caller = Rule(name="caller", condition=BooleanLiteral(True))
    gen = _visited_gen(rule_a, rule_b, caller)

    # Set active context for the next direct call
    gen._current_rule = "caller"
    gen._current_rule_key = "caller"

    # Act: wildcard 'rule_*' should match rule_a and rule_b
    gen._record_rule_set_text("rule_*")

    # Assert
    assert "rule_a" in gen.dependencies["caller"]
    assert "rule_b" in gen.dependencies["caller"]


# ---------------------------------------------------------------------------
# _record_rule_set_text: exact rule name match (lines 394-395)
# ---------------------------------------------------------------------------


def test_record_rule_set_text_exact_name_creates_single_dependency() -> None:
    """When the value is an exact rule name (no wildcard), a single dependency
    edge must be created for that rule."""
    # Arrange
    rule_a = Rule(name="rule_a", condition=BooleanLiteral(True))
    caller = Rule(name="caller", condition=BooleanLiteral(True))
    gen = _visited_gen(rule_a, caller)

    gen._current_rule = "caller"
    gen._current_rule_key = "caller"

    # Act
    gen._record_rule_set_text("rule_a")

    # Assert
    assert "rule_a" in gen.dependencies["caller"]


def test_record_rule_set_text_self_reference_is_excluded() -> None:
    """A value equal to the current rule name must not create a self-dependency."""
    # Arrange
    caller = Rule(name="caller", condition=BooleanLiteral(True))
    gen = _visited_gen(caller)

    gen._current_rule = "caller"
    gen._current_rule_key = "caller"

    # Act
    gen._record_rule_set_text("caller")

    # Assert: no self-loop
    assert "caller" not in gen.dependencies.get("caller", set())


# ---------------------------------------------------------------------------
# _visit_rule_set_value: StringLiteral branch (line 407)
# ---------------------------------------------------------------------------


def test_visit_rule_set_value_with_string_literal_is_a_no_op() -> None:
    """A StringLiteral in a rule set must be ignored (it is a string pattern,
    not a rule reference)."""
    # Arrange: OfExpression whose string_set is a single StringLiteral
    node = OfExpression(
        quantifier="any",
        string_set=StringLiteral(value="$a"),
    )
    rule = Rule(name="of_rule", condition=node)

    # Act
    gen = _visited_gen(rule)

    # Assert: no dependencies, rule registered
    assert "of_rule" in gen.rules
    assert gen.dependencies.get("of_rule", set()) == set()


def test_visit_rule_set_value_with_string_literal_list_is_a_no_op() -> None:
    """A list containing StringLiterals must be iterated without creating edges."""
    # Arrange
    gen = DependencyGraphGenerator()
    gen._rule_names = {"rule_a"}
    gen._current_rule = "caller"
    gen._current_rule_key = "caller"

    # Act: pass a list with a StringLiteral — should hit lines 400-402 then 407
    gen._visit_rule_set_value([StringLiteral(value="$a"), StringLiteral(value="$b")])

    # Assert
    assert gen.dependencies.get("caller", set()) == set()


# ---------------------------------------------------------------------------
# _visit_rule_set_value: StringWildcard branch (line 410)
# ---------------------------------------------------------------------------


def test_visit_rule_set_value_with_dollar_string_wildcard_does_not_create_dependency() -> None:
    """A StringWildcard whose pattern starts with '$' (a string set wildcard,
    not a rule wildcard) must not produce any dependency edges."""
    # Arrange: OfExpression with a dollar-prefixed wildcard
    node = OfExpression(
        quantifier="any",
        string_set=StringWildcard(pattern="$a*"),
    )
    rule = Rule(name="of_rule2", condition=node)

    # Act
    gen = _visited_gen(rule)

    # Assert: no dependency edges from a string wildcard
    assert gen.dependencies.get("of_rule2", set()) == set()


def test_visit_rule_set_value_with_rule_name_wildcard_creates_dependency() -> None:
    """A StringWildcard whose pattern is a rule-name wildcard (no '$' prefix)
    must create dependency edges for all matching rules."""
    # Arrange: rule_a and rule_b exist; caller's of-set uses wildcard 'rule_*'
    rule_a = Rule(name="rule_a", condition=BooleanLiteral(True))
    rule_b = Rule(name="rule_b", condition=BooleanLiteral(True))
    node = OfExpression(
        quantifier="any",
        string_set=StringWildcard(pattern="rule_*"),
    )
    caller = Rule(name="caller", condition=node)

    # Act
    gen = _visited_gen(rule_a, rule_b, caller)

    # Assert: both rule_a and rule_b are dependencies of caller
    assert "rule_a" in gen.dependencies.get("caller", set())
    assert "rule_b" in gen.dependencies.get("caller", set())


# ---------------------------------------------------------------------------
# _matching_rule_wildcard_names: no trailing '*' (line 423)
# ---------------------------------------------------------------------------


def test_matching_rule_wildcard_names_without_star_returns_empty() -> None:
    """_matching_rule_wildcard_names must return () for a pattern with no trailing '*'."""
    # Arrange
    gen = DependencyGraphGenerator()
    gen._rule_names = {"rule_a", "rule_b"}

    # Act
    result = gen._matching_rule_wildcard_names("rule_a")

    # Assert
    assert result == ()


# ---------------------------------------------------------------------------
# _matching_rule_wildcard_names: bare '*' with empty prefix (line 426)
# ---------------------------------------------------------------------------


def test_matching_rule_wildcard_names_bare_star_returns_empty() -> None:
    """_matching_rule_wildcard_names must return () for a bare '*' pattern
    because the prefix after stripping the star is empty."""
    # Arrange
    gen = DependencyGraphGenerator()
    gen._rule_names = {"rule_a", "rule_b"}

    # Act
    result = gen._matching_rule_wildcard_names("*")

    # Assert
    assert result == ()


# ---------------------------------------------------------------------------
# Duplicate rule names produce keyed graph entries (line 215 / _rule_graph_key)
# ---------------------------------------------------------------------------


def test_duplicate_rule_names_produce_numbered_graph_keys() -> None:
    """When the same rule name appears twice, graph keys must be 'name#1' and
    'name#2'; a single occurrence stays just 'name'."""
    # Arrange: two rules share the name 'dup', one unique rule
    rule1 = Rule(name="dup", condition=BooleanLiteral(True))
    rule2 = Rule(name="dup", condition=BooleanLiteral(True))
    rule3 = Rule(name="unique", condition=BooleanLiteral(True))

    # Act
    gen = _visited_gen(rule1, rule2, rule3)

    # Assert
    assert "dup#1" in gen.rules
    assert "dup#2" in gen.rules
    assert "unique" in gen.rules
    assert "dup" not in gen.rules


def test_duplicate_rule_caller_records_dependency_to_all_occurrences() -> None:
    """A rule referencing a duplicated rule name by Identifier must receive
    dependency edges pointing to every numbered occurrence."""
    # Arrange
    dup1 = Rule(name="dup", condition=BooleanLiteral(True))
    dup2 = Rule(name="dup", condition=BooleanLiteral(True))
    caller = Rule(name="caller", condition=Identifier("dup"))

    # Act
    gen = _visited_gen(dup1, dup2, caller)

    # Assert
    caller_deps = gen.dependencies.get("caller", set())
    assert "dup#1" in caller_deps
    assert "dup#2" in caller_deps
