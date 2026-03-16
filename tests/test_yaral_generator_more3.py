"""More tests for YARA-L generator (no mocks)."""

from __future__ import annotations

from yaraast.yaral.ast_nodes import (
    AggregationFunction,
    BinaryCondition,
    ConditionSection,
    EventAssignment,
    EventCountCondition,
    EventExistsCondition,
    EventsSection,
    EventVariable,
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
    UDMFieldPath,
    YaraLFile,
    YaraLRule,
)
from yaraast.yaral.generator import YaraLGenerator


def test_yaral_generator_full_sections() -> None:
    rule = YaraLRule(
        name="rule1",
        meta=MetaSection(entries=[MetaEntry(key="author", value="me")]),
        events=EventsSection(
            statements=[
                EventAssignment(
                    event_var=EventVariable(name="$e"),
                    field_path=UDMFieldPath(parts=["metadata", "event_type"]),
                    operator="=",
                    value="LOGIN",
                ),
                EventAssignment(
                    event_var=EventVariable(name="$e"),
                    field_path=UDMFieldPath(parts=["target", "ip"]),
                    operator="in",
                    value=ReferenceList(name="bad_ips"),
                ),
                EventAssignment(
                    event_var=EventVariable(name="$e"),
                    field_path=UDMFieldPath(parts=["target", "hostname"]),
                    operator="regex",
                    value=RegexPattern(pattern="evil.*"),
                    modifiers=["nocase"],
                ),
            ],
        ),
        match=MatchSection(
            variables=[MatchVariable(variable="e", time_window=TimeWindow(5, "m", "every"))],
        ),
        condition=ConditionSection(
            expression=BinaryCondition(
                operator="and",
                left=EventCountCondition(event="e", operator=">", count=2),
                right=EventExistsCondition(event="e"),
            ),
        ),
        outcome=OutcomeSection(
            assignments=[
                OutcomeAssignment(
                    variable="$count",
                    expression=AggregationFunction(
                        function="count",
                        arguments=[
                            UDMFieldPath(parts=["target", "ip"]),
                        ],
                    ),
                ),
            ],
        ),
        options=OptionsSection(options={"case_sensitive": False}),
    )

    code = YaraLGenerator().generate(YaraLFile(rules=[rule]))
    assert "meta:" in code
    assert "events:" in code
    assert "match:" in code
    assert "condition:" in code
    assert "outcome:" in code
    assert "options:" in code
    assert '$e.metadata.event_type = "LOGIN"' in code
    assert "$e.target.ip in %bad_ips" in code
    assert "/evil.*/" in code
