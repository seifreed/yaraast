"""Additional tests for Enhanced YARA-L parser paths."""

from __future__ import annotations

from textwrap import dedent

from yaraast.yaral.ast_nodes import ReferenceList, RegexPattern
from yaraast.yaral.enhanced_parser import EnhancedYaraLParser


def test_enhanced_parser_parses_events_conditions_outcome_options() -> None:
    yaral_code = """
    rule enhanced_extras {
        meta:
            author = "sec"
            enabled = false
            threshold = 3

        events:
            $e.metadata.event_type matches /LOGIN/i and $e.principal.user = "alice"
            $e.security_result.action = true
            $e.metadata.product_name = %products%

        condition:
            not ($e and #e > 1) or src.ip in %suspicious_ips%

        outcome:
            $count = count(metadata.event_type)
            if #e > 0 then "high" else "low"

        options:
            case_sensitive = false
            max_events = 10
            output_format = json
    }
    """

    parser = EnhancedYaraLParser(dedent(yaral_code))
    ast = parser.parse()

    assert parser.errors == []
    assert len(ast.rules) == 1
    rule = ast.rules[0]
    assert rule.name == "enhanced_extras"
    assert rule.meta is not None
    assert rule.events is not None
    assert rule.condition is not None
    assert rule.outcome is not None
    assert rule.options is not None
    assert rule.options.options["case_sensitive"] is False
    assert rule.options.options["max_events"] == 10
    assert rule.options.options["output_format"] == "json"


def test_enhanced_parser_parses_reference_and_regex_values() -> None:
    yaral_code = """
    rule enhanced_refs {
        events:
            $e.metadata.event_type matches /AUTH.*/im
            $e.metadata.product_name = %products%

        condition:
            principal.ip in %watchlist%
    }
    """

    parser = EnhancedYaraLParser(dedent(yaral_code))
    ast = parser.parse()

    assert parser.errors == []
    rule = ast.rules[0]
    events = rule.events
    assert events is not None
    assert any(
        isinstance(stmt.value, RegexPattern) for stmt in events.statements if hasattr(stmt, "value")
    )
    assert any(
        isinstance(stmt.value, ReferenceList)
        for stmt in events.statements
        if hasattr(stmt, "value")
    )


def test_enhanced_parser_error_recovery_keeps_parsing() -> None:
    yaral_code = """
    rule bad_rule {
        events:
            $e.metadata.event_type = "LOGIN"
        condition:
            #e >
    }

    rule good_rule {
        events:
            $e.metadata.event_type = "OK"
        condition:
            #e > 0
    }
    """

    parser = EnhancedYaraLParser(dedent(yaral_code))
    ast = parser.parse()

    assert parser.errors
    assert any(rule.name == "good_rule" for rule in ast.rules)
