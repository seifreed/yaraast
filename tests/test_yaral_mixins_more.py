"""Additional real coverage for YARA-L optimizer and validator mixins."""

from __future__ import annotations

from dataclasses import dataclass

import pytest

from yaraast.ast.expressions import BooleanLiteral
from yaraast.yaral.ast_nodes import (
    AggregationFunction,
    ArithmeticExpression,
    BinaryCondition,
    ConditionalExpression,
    ConditionSection,
    EventAssignment,
    EventCountCondition,
    EventExistsCondition,
    EventVariable,
    JoinCondition,
    MatchSection,
    MatchVariable,
    OptionsSection,
    OutcomeAssignment,
    OutcomeExpression,
    OutcomeSection,
    TimeWindow,
    UDMFieldPath,
    UnaryCondition,
    YaraLFile,
    YaraLRule,
)
from yaraast.yaral.optimizer import YaraLOptimizer
from yaraast.yaral.validator import ValidationError, YaraLValidator
from yaraast.yaral.visitor_base import YaraLVisitor


@dataclass
class OutcomeVariablesContainer:
    variables: dict[str, object]


def test_yaral_visitor_base_declares_yaral_node_handlers() -> None:
    visitor = YaraLVisitor[object]()

    with pytest.raises(NotImplementedError, match="YaraLFile"):
        visitor.visit(YaraLFile(rules=[]))

    with pytest.raises(NotImplementedError, match="YaraLRule"):
        visitor.visit(YaraLRule(name="r"))


def _assignment(
    field_parts: list[str],
    operator: str,
    value: str | int | EventVariable | UDMFieldPath,
) -> EventAssignment:
    return EventAssignment(
        event_var=EventVariable(name="$e"),
        field_path=UDMFieldPath(parts=field_parts),
        operator=operator,
        value=value,
    )


def test_yaral_optimizer_conditions_helpers_and_outcomes() -> None:
    opt = YaraLOptimizer()

    assert opt._optimize_condition_section(None) is None
    empty_condition = ConditionSection(expression=None)
    assert opt._optimize_condition_section(empty_condition) == empty_condition

    double_not = UnaryCondition(
        operator="not",
        operand=UnaryCondition(operator="not", operand=EventExistsCondition(event="e")),
    )
    simplified = opt._optimize_condition_expression(double_not)
    assert isinstance(simplified, EventExistsCondition)

    passthrough = opt._optimize_binary_condition(
        BinaryCondition(
            operator="xor",
            left=EventExistsCondition(event="l"),
            right=EventExistsCondition(event="r"),
        )
    )
    assert isinstance(passthrough, BinaryCondition)
    assert passthrough.operator == "xor"
    optimized_or = opt._optimize_binary_condition(
        BinaryCondition(
            operator="or",
            left=EventExistsCondition(event="same"),
            right=EventExistsCondition(event="same"),
        )
    )
    assert isinstance(optimized_or, EventExistsCondition)
    assert optimized_or.event == "same"

    left = EventExistsCondition(event="left")
    right = EventExistsCondition(event="right")
    assert opt._optimize_and_condition(left, BooleanLiteral(value=True)) == left
    assert opt._optimize_and_condition(BooleanLiteral(value=True), right) == right
    false_cond = opt._optimize_and_condition(left, BooleanLiteral(value=False))
    assert isinstance(false_cond, UnaryCondition)
    assert opt._optimize_and_condition(left, left) == left
    assert opt._optimize_and_condition(left, right).operator == "and"

    assert opt._optimize_or_condition(left, BooleanLiteral(value=False)) == left
    assert opt._optimize_or_condition(BooleanLiteral(value=False), right) == right
    true_cond = opt._optimize_or_condition(left, BooleanLiteral(value=True))
    assert isinstance(true_cond, EventExistsCondition)
    assert opt._optimize_or_condition(left, left) == left
    assert opt._optimize_or_condition(left, right).operator == "or"

    true_condition = opt._create_true_condition()
    assert isinstance(true_condition, EventExistsCondition)
    assert true_condition.event == "true"
    assert isinstance(opt._create_false_condition(), UnaryCondition)

    assert (
        opt._field_path_to_string(UDMFieldPath(parts=["metadata", "event_timestamp"]))
        == "metadata.event_timestamp"
    )
    assert (
        opt._field_path_to_string(
            UDMFieldPath(parts=["metadata", '["event_type"]', "[0]", "value"])
        )
        == 'metadata["event_type"][0].value'
    )
    assert opt._field_path_to_string("principal.ip") == "principal.ip"
    assert opt._should_index_field(_assignment(["metadata", "event_type"], "=", "LOGIN"))
    assert opt._should_index_field(_assignment(["metadata", "event_timestamp"], ">", 1))
    assert opt._should_index_field(_assignment(["principal", "ip"], "contains", "1.2.3.4"))
    assert opt._should_index_field(_assignment(["principal", "ip", "[0]"], "contains", "1.2.3.4"))
    assert not opt._should_index_field(_assignment(["metadata", "description"], "contains", "x"))

    assert opt._are_contradictory(_assignment(["a"], "=", 1), _assignment(["a"], "!=", 1))
    assert opt._are_contradictory(_assignment(["a"], "!=", 1), _assignment(["a"], "=", 1))
    assert opt._are_contradictory(_assignment(["a"], ">", 10), _assignment(["a"], "<", 10))
    assert not opt._are_contradictory(_assignment(["a"], ">", 5), _assignment(["a"], "<", 10))
    assert not opt._are_contradictory(_assignment(["a"], "=", 1), _assignment(["a"], "=", 2))

    assert opt._are_redundant(_assignment(["a"], "=", 1), _assignment(["a"], "=", 1))
    assert opt._are_redundant(_assignment(["a"], ">=", 10), _assignment(["a"], ">", 5))
    assert not opt._are_redundant(_assignment(["a"], ">=", 1), _assignment(["a"], ">", 5))
    assert not opt._are_redundant(_assignment(["a"], "=", 1), _assignment(["a"], "!=", 1))

    assert opt._is_more_restrictive(_assignment(["a"], "=", 1), _assignment(["a"], ">", 1))
    assert opt._is_more_restrictive(_assignment(["a"], ">", 10), _assignment(["a"], ">=", 5))
    assert not opt._is_more_restrictive(_assignment(["a"], ">", 1), _assignment(["a"], ">=", 5))
    assert not opt._is_more_restrictive(_assignment(["a"], "<", 1), _assignment(["a"], "<", 5))

    assert opt._is_outcome_var_used("risk_score")
    assert not opt._is_outcome_var_used("$custom")
    assert opt._is_always_true(BooleanLiteral(value=True))
    assert not opt._is_always_true(EventExistsCondition(event="e"))
    assert opt._is_always_false(BooleanLiteral(value=False))
    assert not opt._is_always_false(EventExistsCondition(event="e"))
    assert opt._are_equal_conditions(left, EventExistsCondition(event="left"))

    assert opt._optimize_match_section(None) is None
    match = MatchSection(
        variables=[
            MatchVariable(variable="e", time_window=TimeWindow(3600, "s")),
            MatchVariable(variable="m", time_window=TimeWindow(1440, "m")),
        ]
    )
    optimized_match = opt._optimize_match_section(match)
    assert optimized_match is not None
    assert optimized_match.variables[0].time_window.unit == "h"
    assert optimized_match.variables[1].time_window.unit == "d"
    legacy_var = MatchVariable(variable="legacy", time_window=TimeWindow(duration=1, unit="m"))
    optimized_legacy_match = opt._optimize_match_section(MatchSection(variables=[legacy_var]))
    assert optimized_legacy_match is not None
    assert optimized_legacy_match.variables[0].variable == "legacy"
    opaque_window = object()
    assert opt._optimize_time_window(opaque_window) is opaque_window

    assert opt._optimize_outcome_section(None) is None
    outcome = OutcomeSection(
        assignments=[OutcomeAssignment(variable="$x", expression=OutcomeExpression())]
    )
    assert opt._optimize_outcome_section(outcome) is outcome
    assert opt._optimize_outcome_section(type("EmptyLegacyOutcome", (), {})()).assignments == []

    legacy = OutcomeVariablesContainer(
        variables={"risk_score": 10, "severity": "high", "$drop": 1},
    )
    optimized_legacy = opt._optimize_outcome_section(legacy)
    assert [assignment.variable for assignment in optimized_legacy.assignments] == [
        "risk_score",
        "severity",
    ]

    assert opt._optimize_options(None) is None
    options = OptionsSection(options={"timeout": "1m"})
    optimized_options = opt._optimize_options(options)
    assert optimized_options.options["timeout"] == "1m"
    assert optimized_options.options["max_events"] == 10000
    complete_options = OptionsSection(options={"timeout": "1m", "max_events": 5})
    assert opt._optimize_options(complete_options).options == {"timeout": "1m", "max_events": 5}
    opaque_options = object()
    assert opt._optimize_options(opaque_options) is opaque_options


def test_yaral_validator_condition_and_outcome_mixins() -> None:
    class FalsyEventExistsCondition(EventExistsCondition):
        def __bool__(self) -> bool:
            return False

    validator = YaraLValidator()
    validator.current_rule = "r1"

    validator._validate_condition_section(ConditionSection(expression=None))
    assert any("Condition section cannot be empty" in err.message for err in validator.errors)

    validator.errors.clear()
    validator._validate_condition_section(
        ConditionSection(expression=FalsyEventExistsCondition(event="present"))
    )
    assert not any("Condition section cannot be empty" in err.message for err in validator.errors)

    validator.errors.clear()
    validator.warnings.clear()
    validator.used_events.clear()
    validator.defined_outcome_vars.clear()

    validator.visit_yaral_condition_section(
        ConditionSection(expression=EventExistsCondition(event="e1"))
    )
    assert "e1" in validator.used_events

    validator.visit_yaral_condition_expression(EventExistsCondition(event="ignored"))
    validator.visit_yaral_binary_condition(
        BinaryCondition(
            operator="and",
            left=EventCountCondition(event="e2", operator=">", count=1),
            right=EventExistsCondition(event="e3"),
        )
    )
    validator.visit_yaral_unary_condition(
        UnaryCondition(operator="not", operand=EventExistsCondition(event="e4"))
    )
    from yaraast.yaral.ast_nodes import VariableComparisonCondition

    validator.visit_yaral_variable_comparison_condition(
        VariableComparisonCondition(variable="$x", operator=">", value=1)
    )
    validator.visit_yaral_join_condition(JoinCondition(left_event="e1", right_event="e2"))
    assert {"e2", "e3", "e4"}.issubset(validator.used_events)

    validator.visit_yaral_conditional_expression(
        ConditionalExpression(
            condition=EventExistsCondition(event="e5"),
            true_value=1,
            false_value=0,
        )
    )
    validator.visit_yaral_arithmetic_expression(
        ArithmeticExpression(
            operator="+",
            left=EventExistsCondition(event="e6"),
            right=EventExistsCondition(event="e7"),
        )
    )


def test_yaral_optimizer_validator_and_rule_file_edge_paths() -> None:
    opt = YaraLOptimizer()
    section = ConditionSection(expression=EventExistsCondition(event="edge"))
    optimized = opt.visit_yaral_condition_section(section)
    assert isinstance(optimized, ConditionSection)
    assert isinstance(optimized.expression, EventExistsCondition)
    assert optimized.expression.event == "edge"

    issue = ValidationError(
        severity="warning",
        rule_name="demo",
        section="meta",
        message="missing field",
    )
    assert str(issue) == "[WARNING] demo/meta: missing field"

    validator = YaraLValidator()
    validator.visit_yaral_file(YaraLFile())
    assert any("Empty YARA-L file" in warning.message for warning in validator.warnings)

    outcome_section = OutcomeSection(
        assignments=[
            OutcomeAssignment(variable="dup", expression=OutcomeExpression()),
            OutcomeAssignment(variable="dup", expression=OutcomeExpression()),
            OutcomeAssignment(variable="risk_score", expression=OutcomeExpression()),
            OutcomeAssignment(variable="$ok", expression=OutcomeExpression()),
        ]
    )
    validator._validate_outcome_section(outcome_section)
    assert "dup" in validator.defined_outcome_vars
    assert any("Duplicate outcome variable" in err.message for err in validator.errors)
    assert any("must start with $" in err.message for err in validator.errors)

    validator._validate_outcome_section(
        OutcomeSection(
            assignments=[
                OutcomeAssignment(variable="name_without_dollar", expression=OutcomeExpression())
            ]
        )
    )
    assert "name_without_dollar" in validator.defined_outcome_vars

    validator.errors.clear()
    validator.warnings.clear()
    validator.defined_outcome_vars.clear()
    validator.visit_yaral_outcome_section(
        OutcomeSection(
            assignments=[
                OutcomeAssignment(
                    variable="$score",
                    expression=AggregationFunction(function="count", arguments=["$e"]),
                )
            ]
        )
    )
    assert "$score" in validator.defined_outcome_vars

    validator.visit_yaral_outcome_expression(OutcomeExpression())
    validator.visit_yaral_aggregation_function(
        AggregationFunction(function="weird_sum", arguments=["$e"])
    )
    assert any("Unknown aggregation function" in warn.message for warn in validator.warnings)

    validator.warnings.clear()
    validator.visit_yaral_aggregation_function(
        AggregationFunction(function="earliest", arguments=["$e"])
    )
    validator.visit_yaral_aggregation_function(
        AggregationFunction(function="latest", arguments=["$e"])
    )
    assert validator.warnings == []
