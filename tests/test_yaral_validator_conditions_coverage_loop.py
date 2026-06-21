"""
// Copyright (c) 2026 Marc Rivero López
// Licensed under GPLv3. See LICENSE file for details.
// This test suite validates real code behavior without mocks or stubs.

Regression tests for yaraast.yaral.validator_conditions targeting every
uncovered branch identified by:

    python -m pytest tests/test_yaral_validator_conditions_more.py
        -p no:xdist --override-ini="addopts="
        --cov=yaraast.yaral.validator_conditions --cov-report=term-missing

Missing lines before this file:
    28-29, 36-39, 42, 45-46, 49-50, 53, 59, 62, 65-66, 69-76, 80, 86

All tests call real production code on real AST-node instances.  No mocks,
no stubs, no placeholder implementations.
"""

from __future__ import annotations

from yaraast.yaral.ast_nodes import (
    ArithmeticExpression,
    BinaryCondition,
    ConditionalExpression,
    ConditionExpression,
    ConditionSection,
    EventCountCondition,
    EventExistsCondition,
    EventVariable,
    JoinCondition,
    NOfCondition,
    NullCheckCondition,
    UDMFieldAccess,
    UDMFieldPath,
    UnaryCondition,
    VariableComparisonCondition,
)
from yaraast.yaral.validator import YaraLValidator

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _make_validator(rule_name: str = "test_rule") -> YaraLValidator:
    """Return a freshly-initialised validator with a current_rule set."""
    v = YaraLValidator()
    v.current_rule = rule_name
    return v


def _udm_field_access(event_name: str, field_parts: list[str]) -> UDMFieldAccess:
    """Build a minimal UDMFieldAccess with an EventVariable attached."""
    event = EventVariable(name=event_name)
    field = UDMFieldPath(parts=field_parts)
    return UDMFieldAccess(event=event, field=field)


# ---------------------------------------------------------------------------
# _validate_condition_section  (lines 28-29)
# ---------------------------------------------------------------------------


def test_validate_condition_section_emits_error_when_expression_is_none() -> None:
    """
    Purpose: cover lines 28-29.

    _validate_condition_section is called when node.expression is None.
    The guard on line 28 evaluates to True, so _add_error is invoked (line 29).
    """
    # Arrange
    validator = _make_validator("rule_empty_cond")
    node = ConditionSection(expression=None)

    # Act
    validator._validate_condition_section(node)

    # Assert - one error is recorded with the expected section name
    assert len(validator.errors) == 1
    err = validator.errors[0]
    assert err.section == "condition"
    assert "empty" in err.message.lower()
    assert validator.warnings == []


def test_validate_condition_section_no_error_when_expression_present() -> None:
    """
    Purpose: guard on line 28 evaluates to False when expression is set.

    _validate_condition_section should NOT emit an error when the node carries
    a real expression object, confirming the non-error branch is intact.
    """
    # Arrange
    validator = _make_validator("rule_has_cond")
    expr = EventExistsCondition(event="$e")
    node = ConditionSection(expression=expr)

    # Act
    validator._validate_condition_section(node)

    # Assert
    assert validator.errors == []


# ---------------------------------------------------------------------------
# visit_yaral_condition_section  (lines 36-39)
# ---------------------------------------------------------------------------


def test_visit_condition_section_with_none_expression_records_error() -> None:
    """
    Purpose: cover lines 36-38 (None branch inside visit_yaral_condition_section).

    When expression is None, visit_yaral_condition_section delegates to
    _validate_condition_section which records the error, then returns early.
    """
    # Arrange
    validator = _make_validator("rule_none_section")
    node = ConditionSection(expression=None)

    # Act
    validator.visit_yaral_condition_section(node)

    # Assert
    assert len(validator.errors) == 1
    assert "empty" in validator.errors[0].message.lower()


def test_visit_condition_section_with_expression_visits_child() -> None:
    """
    Purpose: cover line 39 — self.visit(node.expression) — the non-None branch.

    An EventExistsCondition is used as the expression; visiting it populates
    used_events, confirming the child-visit path executed.
    """
    # Arrange
    validator = _make_validator("rule_visits_expr")
    expr = EventExistsCondition(event="$auth")
    node = ConditionSection(expression=expr)

    # Act
    validator.visit_yaral_condition_section(node)

    # Assert — child was visited, event name was registered
    assert "auth" in validator.used_events
    assert validator.errors == []


# ---------------------------------------------------------------------------
# visit_yaral_condition_expression  (line 42)
# ---------------------------------------------------------------------------


def test_visit_condition_expression_is_no_op() -> None:
    """
    Purpose: cover line 42 — the bare `return` in visit_yaral_condition_expression.

    ConditionExpression is the base class; calling its visitor method produces
    no errors, no warnings, and no state changes.
    """
    # Arrange
    validator = _make_validator("rule_base_expr")
    node = ConditionExpression()

    # Act
    validator.visit_yaral_condition_expression(node)

    # Assert
    assert validator.errors == []
    assert validator.warnings == []
    assert validator.used_events == set()


# ---------------------------------------------------------------------------
# visit_yaral_binary_condition  (lines 45-46)
# ---------------------------------------------------------------------------


def test_visit_binary_condition_visits_both_children() -> None:
    """
    Purpose: cover lines 45-46 — visit(node.left) and visit(node.right).

    A BinaryCondition wrapping two EventExistsConditions is used; both child
    events must appear in used_events after the call.
    """
    # Arrange
    validator = _make_validator("rule_binary")
    left = EventExistsCondition(event="$src")
    right = EventExistsCondition(event="$dst")
    node = BinaryCondition(operator="and", left=left, right=right)

    # Act
    validator.visit_yaral_binary_condition(node)

    # Assert — both children visited
    assert "src" in validator.used_events
    assert "dst" in validator.used_events
    assert validator.errors == []


def test_visit_binary_condition_or_operator() -> None:
    """
    Purpose: confirm binary visitor works for OR operator as well.

    Exercises the same lines 45-46 with a different operator to confirm
    operator-agnosticism in the mixin.
    """
    # Arrange
    validator = _make_validator("rule_binary_or")
    left = EventExistsCondition(event="$login")
    right = EventExistsCondition(event="$logout")
    node = BinaryCondition(operator="or", left=left, right=right)

    # Act
    validator.visit_yaral_binary_condition(node)

    # Assert
    assert "login" in validator.used_events
    assert "logout" in validator.used_events


# ---------------------------------------------------------------------------
# visit_yaral_unary_condition  (lines 49-50)
# ---------------------------------------------------------------------------


def test_visit_unary_condition_visits_operand_when_present() -> None:
    """
    Purpose: cover lines 49-50 — the `if operand is not None` branch.

    A NOT wrapping an EventExistsCondition; the child event appears in
    used_events, confirming visit(node.operand) was reached.
    """
    # Arrange
    validator = _make_validator("rule_unary_not")
    operand = EventExistsCondition(event="$proc")
    node = UnaryCondition(operator="not", operand=operand)

    # Act
    validator.visit_yaral_unary_condition(node)

    # Assert
    assert "proc" in validator.used_events
    assert validator.errors == []


def test_visit_unary_condition_skips_when_operand_is_none() -> None:
    """
    Purpose: confirm the else-branch (operand is None) skips the visit call.

    No events should be added when operand is None.
    """
    # Arrange
    validator = _make_validator("rule_unary_none")
    node = UnaryCondition(operator="not", operand=None)

    # Act
    validator.visit_yaral_unary_condition(node)

    # Assert
    assert validator.used_events == set()
    assert validator.errors == []


# ---------------------------------------------------------------------------
# visit_yaral_event_count_condition  (line 53)
# ---------------------------------------------------------------------------


def test_visit_event_count_condition_registers_event() -> None:
    """
    Purpose: cover line 53 — used_events.add(node.event.lstrip('$')).

    An EventCountCondition using a dollar-prefixed event name must result in
    the bare name (without '$') being registered in used_events.
    """
    # Arrange
    validator = _make_validator("rule_event_count")
    node = EventCountCondition(event="$http", operator=">", count=5)

    # Act
    validator.visit_yaral_event_count_condition(node)

    # Assert
    assert "http" in validator.used_events
    assert validator.errors == []


def test_visit_event_count_condition_strips_dollar_prefix() -> None:
    """
    Purpose: confirm lstrip('$') works on a name already without the prefix.

    EventCountCondition.event may be stored without '$' in some parsers;
    verify no double-stripping or KeyError occurs.
    """
    # Arrange
    validator = _make_validator("rule_event_count_no_dollar")
    node = EventCountCondition(event="net", operator=">=", count=1)

    # Act
    validator.visit_yaral_event_count_condition(node)

    # Assert
    assert "net" in validator.used_events


# ---------------------------------------------------------------------------
# visit_yaral_variable_comparison_condition  (line 59)
# ---------------------------------------------------------------------------


def test_visit_variable_comparison_condition_is_no_op() -> None:
    """
    Purpose: cover line 59 — the bare `return` in visit_yaral_variable_comparison_condition.

    VariableComparisonCondition validation does not mutate used_events or emit
    diagnostics; the method only needs to execute without error.
    """
    # Arrange
    validator = _make_validator("rule_var_cmp")
    node = VariableComparisonCondition(variable="$count", operator=">", value=3)

    # Act
    validator.visit_yaral_variable_comparison_condition(node)

    # Assert
    assert validator.used_events == set()
    assert validator.errors == []


# ---------------------------------------------------------------------------
# visit_yaral_join_condition  (line 62)
# ---------------------------------------------------------------------------


def test_visit_join_condition_is_no_op() -> None:
    """
    Purpose: cover line 62 — the bare `return` in visit_yaral_join_condition.

    JoinCondition visitor is intentionally a no-op; no state changes expected.
    """
    # Arrange
    validator = _make_validator("rule_join")
    node = JoinCondition(left_event="$e1", right_event="$e2", join_type="inner")

    # Act
    validator.visit_yaral_join_condition(node)

    # Assert
    assert validator.used_events == set()
    assert validator.errors == []


# ---------------------------------------------------------------------------
# visit_yaral_n_of_condition  (lines 65-66)
# ---------------------------------------------------------------------------


def test_visit_n_of_condition_registers_all_events() -> None:
    """
    Purpose: cover lines 65-66 — the for-loop body in visit_yaral_n_of_condition.

    All event names in the NOfCondition.events list must appear in used_events
    after the visit, stripped of their '$' prefix.
    """
    # Arrange
    validator = _make_validator("rule_n_of")
    node = NOfCondition(count=2, events=["$e1", "$e2", "$e3"])

    # Act
    validator.visit_yaral_n_of_condition(node)

    # Assert
    assert "e1" in validator.used_events
    assert "e2" in validator.used_events
    assert "e3" in validator.used_events
    assert validator.errors == []


def test_visit_n_of_condition_empty_events_list() -> None:
    """
    Purpose: confirm the for-loop executes zero times with an empty events list.

    The loop body (line 66) must not execute, leaving used_events empty.
    """
    # Arrange
    validator = _make_validator("rule_n_of_empty")
    node = NOfCondition(count=0, events=[])

    # Act
    validator.visit_yaral_n_of_condition(node)

    # Assert
    assert validator.used_events == set()


def test_visit_n_of_condition_strips_dollar_prefix() -> None:
    """
    Purpose: verify lstrip('$') applies correctly per event in the list.

    Mix dollar-prefixed and bare names; both styles must be stored without '$'.
    """
    # Arrange
    validator = _make_validator("rule_n_of_mixed")
    node = NOfCondition(count=1, events=["$login", "network"])

    # Act
    validator.visit_yaral_n_of_condition(node)

    # Assert
    assert "login" in validator.used_events
    assert "network" in validator.used_events


# ---------------------------------------------------------------------------
# visit_yaral_null_check_condition  (lines 69-76)
# ---------------------------------------------------------------------------


def test_visit_null_check_condition_with_udm_field_access_registers_event() -> None:
    """
    Purpose: cover lines 70-73 — the UDMFieldAccess branch of visit_yaral_null_check_condition.

    When field is a UDMFieldAccess that carries an event attribute, the visitor
    must extract the event name and call self.visit(field) to continue traversal.
    """
    # Arrange
    validator = _make_validator("rule_null_udm")
    field = _udm_field_access("$proc", ["principal", "process", "pid"])
    node = NullCheckCondition(field=field, negated=False)

    # Act
    validator.visit_yaral_null_check_condition(node)

    # Assert — event name stripped of '$' must be registered
    assert "proc" in validator.used_events
    assert validator.errors == []


def test_visit_null_check_condition_negated_with_udm_field_access() -> None:
    """
    Purpose: confirm the UDMFieldAccess branch (lines 70-73) is reached for negated checks.

    'is not null' checks carry negated=True but follow the same code path.
    """
    # Arrange
    validator = _make_validator("rule_null_negated")
    field = _udm_field_access("$net", ["target", "ip"])
    node = NullCheckCondition(field=field, negated=True)

    # Act
    validator.visit_yaral_null_check_condition(node)

    # Assert
    assert "net" in validator.used_events


def test_visit_null_check_condition_with_dollar_string_registers_event() -> None:
    """
    Purpose: cover lines 74-76 — the string-with-dollar branch.

    When field is a plain string starting with '$', the visitor extracts the
    event name from the portion before the first '.' and adds it to used_events.
    """
    # Arrange
    validator = _make_validator("rule_null_string")
    node = NullCheckCondition(field="$http.target.url", negated=False)

    # Act
    validator.visit_yaral_null_check_condition(node)

    # Assert — 'http' is extracted and stripped of '$'
    assert "http" in validator.used_events
    assert validator.errors == []


def test_visit_null_check_condition_with_non_dollar_string_skips_event() -> None:
    """
    Purpose: confirm the string branch guard `field.startswith('$')` on line 74
    causes no event registration when the string does not begin with '$'.

    The elif on line 74 is False; used_events must remain empty.
    """
    # Arrange
    validator = _make_validator("rule_null_plain_string")
    node = NullCheckCondition(field="principal.hostname", negated=False)

    # Act
    validator.visit_yaral_null_check_condition(node)

    # Assert
    assert validator.used_events == set()
    assert validator.errors == []


# ---------------------------------------------------------------------------
# visit_yaral_conditional_expression  (line 80)
# ---------------------------------------------------------------------------


def test_visit_conditional_expression_with_visitable_condition_visits_it() -> None:
    """
    Purpose: cover line 80 — self.visit(node.condition) — the branch where
    node.condition has an 'accept' method.

    An EventExistsCondition is used as the condition; visiting it registers
    the event name, confirming the visit call on line 80 was reached.
    """
    # Arrange
    validator = _make_validator("rule_cond_expr_visit")
    cond = EventExistsCondition(event="$auth")
    node = ConditionalExpression(condition=cond, true_value=1, false_value=0)

    # Act
    validator.visit_yaral_conditional_expression(node)

    # Assert
    assert "auth" in validator.used_events
    assert validator.errors == []


def test_visit_conditional_expression_with_scalar_condition_skips_visit() -> None:
    """
    Purpose: confirm the guard `hasattr(node.condition, 'accept')` on line 79
    prevents a visit call when condition is a plain scalar (no accept method).
    """
    # Arrange
    validator = _make_validator("rule_cond_expr_scalar")
    node = ConditionalExpression(condition=True, true_value=1, false_value=0)

    # Act
    validator.visit_yaral_conditional_expression(node)

    # Assert — no visit occurred, used_events unchanged
    assert validator.used_events == set()
    assert validator.errors == []


# ---------------------------------------------------------------------------
# visit_yaral_arithmetic_expression  (line 86)
# ---------------------------------------------------------------------------


def test_visit_arithmetic_expression_visits_both_visitable_children() -> None:
    """
    Purpose: cover line 86 — self.visit(node.right) — when right has 'accept'.

    Both left and right are EventExistsConditions (visitable); both events
    must appear in used_events, confirming lines 83-86 all executed.
    """
    # Arrange
    validator = _make_validator("rule_arith_both")
    left = EventExistsCondition(event="$a")
    right = EventExistsCondition(event="$b")
    node = ArithmeticExpression(operator="+", left=left, right=right)

    # Act
    validator.visit_yaral_arithmetic_expression(node)

    # Assert
    assert "a" in validator.used_events
    assert "b" in validator.used_events
    assert validator.errors == []


def test_visit_arithmetic_expression_only_right_is_visitable() -> None:
    """
    Purpose: cover line 86 specifically when left is a scalar and right is visitable.

    The guard on line 83 is False (left=int, no accept); the guard on line 85
    is True (right has accept).  Only the right event must be registered.
    """
    # Arrange
    validator = _make_validator("rule_arith_right_only")
    right = EventExistsCondition(event="$c")
    node = ArithmeticExpression(operator="*", left=10, right=right)

    # Act
    validator.visit_yaral_arithmetic_expression(node)

    # Assert — only right event registered
    assert "c" in validator.used_events
    assert validator.used_events == {"c"}
    assert validator.errors == []


def test_visit_arithmetic_expression_neither_child_is_visitable() -> None:
    """
    Purpose: confirm both guards false → used_events unchanged.

    When both children are plain scalars, neither visit is invoked and
    used_events stays empty.
    """
    # Arrange
    validator = _make_validator("rule_arith_scalars")
    node = ArithmeticExpression(operator="/", left=100, right=4)

    # Act
    validator.visit_yaral_arithmetic_expression(node)

    # Assert
    assert validator.used_events == set()
    assert validator.errors == []


# ---------------------------------------------------------------------------
# Integration: section visitor dispatches through real visitor chain
# ---------------------------------------------------------------------------


def test_condition_section_visitor_dispatches_nested_binary_condition() -> None:
    """
    Purpose: end-to-end traversal through visit_yaral_condition_section.

    A ConditionSection whose expression is a BinaryCondition(AND) nesting two
    EventExistsConditions exercises all relevant visitor methods in sequence
    via the real visitor dispatch chain.
    """
    # Arrange
    validator = _make_validator("rule_e2e_binary")
    left = EventExistsCondition(event="$src")
    right = EventExistsCondition(event="$dst")
    binary = BinaryCondition(operator="and", left=left, right=right)
    section = ConditionSection(expression=binary)

    # Act — visit_yaral_condition_section → visit(binary) → visit_yaral_binary_condition
    validator.visit_yaral_condition_section(section)

    # Assert
    assert "src" in validator.used_events
    assert "dst" in validator.used_events
    assert validator.errors == []


def test_condition_section_visitor_dispatches_n_of_condition() -> None:
    """
    Purpose: confirm NOfCondition is reachable through visit_yaral_condition_section.

    NOfCondition.accept dispatches to visit_yaral_n_of_condition when the
    visitor implements that method.
    """
    # Arrange
    validator = _make_validator("rule_e2e_n_of")
    n_of = NOfCondition(count=2, events=["$auth", "$proc", "$net"])
    section = ConditionSection(expression=n_of)

    # Act
    validator.visit_yaral_condition_section(section)

    # Assert
    assert "auth" in validator.used_events
    assert "proc" in validator.used_events
    assert "net" in validator.used_events
    assert validator.errors == []


def test_condition_section_visitor_dispatches_null_check_udm() -> None:
    """
    Purpose: confirm NullCheckCondition with UDMFieldAccess reachable through
    visit_yaral_condition_section.
    """
    # Arrange
    validator = _make_validator("rule_e2e_null_udm")
    field = _udm_field_access("$e1", ["principal", "hostname"])
    null_check = NullCheckCondition(field=field, negated=False)
    section = ConditionSection(expression=null_check)

    # Act
    validator.visit_yaral_condition_section(section)

    # Assert
    assert "e1" in validator.used_events
    assert validator.errors == []
