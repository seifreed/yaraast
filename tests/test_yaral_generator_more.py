"""Additional coverage for YARA-L generator output."""

from __future__ import annotations

from yaraast.yaral.ast_nodes import (
    ArithmeticExpression,
    BinaryCondition,
    CIDRExpression,
    ConditionSection,
    EventAssignment,
    EventExistsCondition,
    EventsSection,
    EventVariable,
    FunctionCall,
    MatchSection,
    MatchVariable,
    MetaEntry,
    MetaSection,
    OptionsSection,
    OutcomeAssignment,
    OutcomeSection,
    ReferenceList,
    RegexPattern,
    TimeWindow,
    UDMFieldAccess,
    UDMFieldPath,
    YaraLFile,
    YaraLRule,
)
from yaraast.yaral.generator import YaraLGenerator


def test_yaral_generator_renders_regex_reference_and_functions() -> None:
    event_var = EventVariable(name="$e")
    field_path = UDMFieldPath(parts=["metadata", "event_type"])
    events = EventsSection(
        statements=[
            EventAssignment(
                event_var=event_var,
                field_path=field_path,
                operator="=~",
                value=RegexPattern(pattern="AUTH.*", flags=["i"]),
            ),
            EventAssignment(
                event_var=event_var,
                field_path=UDMFieldPath(parts=["metadata", "product_name"]),
                operator="=",
                value=ReferenceList(name="products"),
            ),
        ]
    )

    condition = ConditionSection(
        expression=BinaryCondition(
            operator="and",
            left=EventExistsCondition(event="e"),
            right=EventExistsCondition(event="e"),
        )
    )

    outcome = OutcomeSection(
        assignments=[
            OutcomeAssignment(
                variable="$cidr",
                expression=CIDRExpression(
                    field=UDMFieldAccess(
                        event=event_var,
                        field=UDMFieldPath(parts=["principal", "ip"]),
                    ),
                    cidr="10.0.0.0/8",
                ),
            ),
            OutcomeAssignment(
                variable="$calc",
                expression=ArithmeticExpression(operator="+", left=1, right=2),
            ),
            OutcomeAssignment(
                variable="$func",
                expression=FunctionCall(function="string_concat", arguments=["a", "b"]),
            ),
        ]
    )

    match = MatchSection(
        variables=[MatchVariable(variable="user", time_window=TimeWindow(5, "m", "every"))],
    )

    meta = MetaSection(
        entries=[MetaEntry(key="author", value="unit"), MetaEntry(key="enabled", value=True)]
    )
    options = OptionsSection(options={"case_sensitive": False})

    rule = YaraLRule(
        name="gen_extra",
        meta=meta,
        events=events,
        match=match,
        condition=condition,
        outcome=outcome,
        options=options,
    )
    yaral_file = YaraLFile(rules=[rule])

    generated = YaraLGenerator().generate(yaral_file)
    assert "rule gen_extra" in generated
    assert "$e.metadata.event_type =~ /AUTH.*/i" in generated
    assert "$e.metadata.product_name = %products" in generated
    assert "over every 5m" in generated
    assert "$cidr = $e.principal.ip in 10.0.0.0/8" in generated
    assert "$calc = 1 + 2" in generated
    assert '$func = string_concat("a", "b")' in generated
