"""Additional real coverage for the YARA-L generator."""

from __future__ import annotations

from yaraast.yaral.ast_nodes import (
    AggregationFunction,
    BinaryCondition,
    ConditionalExpression,
    ConditionExpression,
    ConditionSection,
    EventAssignment,
    EventExistsCondition,
    EventsSection,
    EventStatement,
    EventVariable,
    FunctionCall,
    JoinCondition,
    MatchSection,
    MatchVariable,
    MetaEntry,
    MetaSection,
    OptionsSection,
    OutcomeAssignment,
    OutcomeExpression,
    OutcomeSection,
    RegexPattern,
    TimeWindow,
    UDMFieldAccess,
    UDMFieldPath,
    UnaryCondition,
    VariableComparisonCondition,
    YaraLFile,
    YaraLRule,
)
from yaraast.yaral.generator import YaraLGenerator


def test_generator_handles_empty_sections_and_sparse_rule() -> None:
    generator = YaraLGenerator()

    assert generator.visit_meta_section(MetaSection(entries=[])) == ""
    assert generator.visit_events_section(EventsSection(statements=[])) == ""
    assert generator.visit_event_statement(EventStatement()) == ""

    code = generator.generate(
        YaraLFile(
            rules=[
                YaraLRule(
                    name="sparse",
                    meta=MetaSection(entries=[]),
                    events=EventsSection(statements=[]),
                    condition=ConditionSection(expression=ConditionExpression()),
                    outcome=OutcomeSection(assignments=[]),
                    options=OptionsSection(options={}),
                )
            ]
        )
    )

    assert "rule sparse {" in code
    assert "condition:" in code
    assert "outcome:" in code
    assert "options:" in code
    assert "meta:" not in code
    assert "events:" not in code
    assert "match:" not in code

    minimal_code = generator.generate(YaraLFile(rules=[YaraLRule(name="minimal")]))
    assert minimal_code == "rule minimal {\n}"


def test_generator_covers_base_conditions_outcomes_and_wrappers() -> None:
    generator = YaraLGenerator()

    event_var = EventVariable(name="$evt")
    field_path = UDMFieldPath(parts=["principal", "hostname"])
    udm_access = UDMFieldAccess(event=event_var, field=field_path)

    assert (
        generator.visit_binary_condition(
            BinaryCondition(
                operator="=",
                left=EventExistsCondition(event="$left"),
                right=EventExistsCondition(event="$right"),
            )
        )
        == "$left = $right"
    )
    assert generator.visit_unary_condition(UnaryCondition(operator="not", operand=None)) == "not "
    assert generator.visit_event_exists_condition(EventExistsCondition(event="$evt")) == "$evt"
    assert (
        generator.visit_conditional_expression(
            ConditionalExpression(condition="ok", true_value=1, false_value="bad")
        )
        == 'if("ok", 1, "bad")'
    )
    assert (
        generator.visit_variable_comparison_condition(
            VariableComparisonCondition(variable="$count", operator=">=", value=7)
        )
        == "$count >= 7"
    )
    assert generator.visit_join_condition(
        JoinCondition(left_event="$a", right_event="$b", join_type="left")
    ) == ("join $a left $b")
    assert generator.visit_condition_expression(ConditionExpression()) == ""
    assert generator.visit_outcome_expression(OutcomeExpression()) == ""
    assert generator.visit_yaral_condition_expression(ConditionExpression()) == ""
    assert generator.visit_yaral_outcome_expression(OutcomeExpression()) == ""
    assert (
        generator.visit_yaral_unary_condition(UnaryCondition(operator="not", operand=None))
        == "not "
    )
    assert (
        generator.visit_yaral_variable_comparison_condition(
            VariableComparisonCondition(variable="count", operator="<", value=3)
        )
        == "count < 3"
    )
    assert (
        generator.visit_yaral_join_condition(
            JoinCondition(left_event="$left", right_event="$right", join_type="inner")
        )
        == "join $left inner $right"
    )
    assert (
        generator.visit_yaral_conditional_expression(
            ConditionalExpression(
                condition=RegexPattern("a.*"), true_value=udm_access, false_value=False
            )
        )
        == "if(/a.*/, $evt.principal.hostname, false)"
    )


def test_generator_renders_prefixed_methods_and_non_default_values() -> None:
    generator = YaraLGenerator()

    event_assignment = EventAssignment(
        event_var=EventVariable(name="$e"),
        field_path=UDMFieldPath(parts=["metadata", "event_type"]),
        operator="=",
        value=RegexPattern(pattern="AUTH.*", flags=["i"]),
        modifiers=["nocase"],
    )
    match_section = MatchSection(
        variables=[MatchVariable(variable="$e", time_window=TimeWindow(10, "m"))],
    )
    outcome_section = OutcomeSection(
        assignments=[
            OutcomeAssignment(
                variable="$agg", expression=AggregationFunction(function="count", arguments=[])
            ),
            OutcomeAssignment(
                variable="$fn",
                expression=FunctionCall(function="concat", arguments=[1, "x"]),
            ),
        ]
    )
    options = OptionsSection(options={"threshold": 5, "enabled": False})
    rule = YaraLRule(
        name="prefixed",
        meta=MetaSection(
            entries=[MetaEntry(key="score", value=10), MetaEntry(key="enabled", value=False)]
        ),
        events=EventsSection(statements=[event_assignment]),
        match=match_section,
        condition=ConditionSection(expression=EventExistsCondition(event="$e")),
        outcome=outcome_section,
        options=options,
    )

    code = generator.generate(YaraLFile(rules=[rule]))

    assert "score = 10" in code
    assert "enabled = false" in code
    assert "$e.metadata.event_type = /AUTH.*/i nocase" in code
    assert "$e over 10m" in code
    assert "$agg = count()" in code
    assert '$fn = concat(1, "x")' in code

    assert (
        generator.visit_event_assignment(event_assignment)
        == "metadata.event_type = /AUTH.*/i nocase"
    )
    assert generator.visit_yaral_event_statement(EventStatement()) == ""
    assert (
        generator.visit_yaral_event_assignment(event_assignment)
        == "$e.metadata.event_type = /AUTH.*/i nocase"
    )
