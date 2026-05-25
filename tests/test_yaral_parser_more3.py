"""More tests for YARA-L parser (no mocks)."""

from __future__ import annotations

from textwrap import dedent

from yaraast.yaral.ast_nodes import (
    AggregationFunction,
    ConditionalExpression,
    EventAssignment,
    EventStatement,
    FunctionCall,
    ReferenceList,
    RegexPattern,
    UDMFieldAccess,
)
from yaraast.yaral.generator import YaraLGenerator
from yaraast.yaral.parser import YaraLParser


def test_parser_events_match_outcome_options() -> None:
    code = dedent(
        """
        rule suspicious_login {
            meta:
                author = "unit"
            events:
                $e.metadata.event_type = "LOGIN"
                $e.target.ip in %bad_ips%
                $e.target.hostname regex /evil.*/
                re.regex($e.target.hostname, /evil.*/) nocase
            match:
                $e over every 5m
            condition:
                #e > 2 and $e
            outcome:
                $count = count($e.target.ip)
            options:
                case_sensitive = false
        }
        """,
    )

    ast = YaraLParser(code).parse()
    rule = ast.rules[0]
    assert rule.events and rule.match and rule.condition and rule.outcome and rule.options

    statements = rule.events.statements
    assert len(statements) >= 4
    assert isinstance(statements[0], EventAssignment)
    assert isinstance(statements[1], EventAssignment)
    assert isinstance(statements[2], EventAssignment)
    assert isinstance(statements[1].value, ReferenceList)
    assert isinstance(statements[2].value, RegexPattern)

    match_var = rule.match.variables[0]
    assert match_var.time_window.modifier == "every"
    assert match_var.time_window.unit == "m"


def test_parser_event_assignment_value_can_be_udm_field_access() -> None:
    code = dedent(
        """
        rule field_join {
            events:
                $e1.principal.ip = $e2.principal.ip
                $e1.metadata.event_type = "LOGIN"
            condition:
                $e1 and $e2
        }
        """,
    )

    ast = YaraLParser(code).parse()
    events = ast.rules[0].events
    assert events is not None
    statements = events.statements

    assert len(statements) == 2
    assert isinstance(statements[0], EventAssignment)
    assert isinstance(statements[0].value, UDMFieldAccess)
    assert statements[0].value.event.name == "$e2"
    assert statements[0].value.field.path == "principal.ip"


def test_parser_complex_event_patterns_preserve_generated_text() -> None:
    code = dedent(
        """
        rule complex_patterns {
            events:
                all
                any
                e1 followed by e2
            condition:
                $e
        }
        """,
    )

    ast = YaraLParser(code).parse()
    events = ast.rules[0].events
    assert events is not None
    assert len(events.statements) == 3
    assert all(isinstance(statement, EventStatement) for statement in events.statements)
    assert [statement.text for statement in events.statements] == [
        "all",
        "any",
        "e1 followed by e2",
    ]

    generated = YaraLGenerator().generate(ast)
    assert "all\n    any\n    e1 followed by e2" in generated


def test_parser_outcome_bare_udm_references_preserve_generated_text() -> None:
    code = dedent(
        """
        rule outcome_bare_udm {
            events:
                $e.metadata.event_type = "LOGIN"
            condition:
                $e
            outcome:
                $field = metadata.event_type
                $count = count(metadata.event_type)
        }
        """,
    )

    ast = YaraLParser(code).parse()
    outcome = ast.rules[0].outcome
    assert outcome is not None
    assert len(outcome.assignments) == 2
    direct_field = outcome.assignments[0].expression
    assert isinstance(direct_field, UDMFieldAccess)
    assert direct_field.event is None
    aggregation = outcome.assignments[1].expression
    assert isinstance(aggregation, AggregationFunction)
    assert isinstance(aggregation.arguments[0], UDMFieldAccess)

    generated = YaraLGenerator().generate(ast)
    assert "$field = metadata.event_type" in generated
    assert "$count = count(metadata.event_type)" in generated
    assert '"metadata.event_type"' not in generated


def test_parser_outcome_function_calls_preserve_generated_text() -> None:
    code = dedent(
        """
        rule outcome_functions {
            events:
                $e.field = "value"
            condition:
                $e
            outcome:
                $len = strings.length($e.field)
                $upper = strings.to_upper($e.field)
                $result = if(strings.length($e.field) > 10, "LONG", "SHORT")
        }
        """,
    )

    ast = YaraLParser(code).parse()
    outcome = ast.rules[0].outcome
    assert outcome is not None
    assert isinstance(outcome.assignments[0].expression, FunctionCall)
    assert isinstance(outcome.assignments[1].expression, FunctionCall)
    assert isinstance(outcome.assignments[2].expression, ConditionalExpression)

    generated = YaraLGenerator().generate(ast)
    assert "$len = strings.length($e.field)" in generated
    assert "$upper = strings.to_upper($e.field)" in generated
    assert '$result = if(strings.length($e.field) > 10, "LONG", "SHORT")' in generated
    assert "UDMFieldAccess" not in generated


def test_parser_normalizes_regex_token_delimiters_for_generation() -> None:
    code = dedent(
        r"""
        rule regex_roundtrip {
            events:
                $e.target.hostname regex /evil.*/ nocase
            outcome:
                $match = if($e.target.hostname = /evil.*/i, "YES", "NO")
            condition:
                $e
        }
        """,
    )

    ast = YaraLParser(code).parse()
    event_value = ast.rules[0].events
    assert event_value is not None
    statement = event_value.statements[0]
    assert isinstance(statement, EventAssignment)
    assert isinstance(statement.value, RegexPattern)
    assert statement.value.pattern == "evil.*"
    assert statement.value.flags == []

    generated = YaraLGenerator().generate(ast)
    assert "$e.target.hostname regex /evil.*/ nocase" in generated
    assert '$match = if($e.target.hostname = /evil.*/i, "YES", "NO")' in generated
    assert "//evil" not in generated


def test_parser_match_multiple_variables_lines() -> None:
    code = dedent(
        """
        rule multiple_match {
            events:
                $e.metadata.event_type = "LOGIN"
            match:
                $a over 5m
                $b over 10m
            condition:
                $e
        }
        """,
    )

    ast = YaraLParser(code).parse()
    rule = ast.rules[0]
    assert rule.match is not None
    assert len(rule.match.variables) == 2
