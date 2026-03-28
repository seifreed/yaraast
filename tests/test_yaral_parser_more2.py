"""Real tests for YARA-L parser (no mocks)."""

from __future__ import annotations

from textwrap import dedent

from yaraast.yaral.parser import YaraLParser


def test_parser_event_assignment_and_match() -> None:
    code = dedent(
        """
        rule login_attempts {
            meta:
                author = "unit"
            events:
                $e.metadata.event_type = "LOGIN" nocase
            match:
                $e over 5m
            condition:
                $e
        }
        """,
    )

    ast = YaraLParser(code).parse()
    assert len(ast.rules) == 1
    rule = ast.rules[0]
    assert rule.events
    assert rule.match
    assert rule.condition


def test_parser_condition_count_and_compare() -> None:
    code = dedent(
        """
        rule counts {
            events:
                $e.metadata.event_type = "LOGIN"
            condition:
                #e > 5 and $e
        }
        """,
    )

    ast = YaraLParser(code).parse()
    assert ast.rules[0].condition is not None


def test_parser_accepts_comma_separated_match_vars() -> None:
    code = dedent(
        """
        rule legacy_match {
            events:
                $e.metadata.event_type = "LOGIN"
            match:
                $var1, $var2 over 5m
            condition:
                $e
        }
        """,
    )

    ast = YaraLParser(code).parse()
    assert ast.rules[0].match is not None
    variables = ast.rules[0].match.variables
    assert len(variables) == 2
    assert variables[0].variable == "var1"
    assert variables[1].variable == "var2"
    assert variables[0].time_window.duration == 5
    assert variables[0].time_window.unit == "m"
    assert variables[1].time_window.duration == 5
    assert variables[1].time_window.unit == "m"
