"""Extra tests for enhanced YARA-L parser (no mocks)."""

from __future__ import annotations

from textwrap import dedent

from yaraast.yaral.ast_nodes import ReferenceList, RegexPattern
from yaraast.yaral.enhanced_parser import EnhancedYaraLParser


def test_enhanced_parser_parses_not_matches_and_in() -> None:
    code = dedent(
        """
        rule enhanced_more {
            events:
                $e.metadata.event_type not matches /AUTH.*/i
                $e.principal.ip in %suspicious_ips%
            condition:
                not $e
        }
        """,
    )
    parser = EnhancedYaraLParser(code)
    ast = parser.parse()

    assert parser.errors == []
    rule = ast.rules[0]
    assert rule.events is not None
    # Ensure regex/reference list parsed
    assert any(isinstance(stmt.value, RegexPattern) for stmt in rule.events.statements)
    assert any(isinstance(stmt.value, ReferenceList) for stmt in rule.events.statements)


def test_enhanced_parser_outcome_conditional_and_aggregation() -> None:
    code = dedent(
        """
        rule outcome_rule {
            events:
                $e.metadata.event_type = "LOGIN"
            condition:
                $e
            outcome:
                if #e > 0 then "high" else "low"
                $count = count(metadata.event_type)
        }
        """,
    )
    parser = EnhancedYaraLParser(code)
    ast = parser.parse()

    assert parser.errors == []
    rule = ast.rules[0]
    assert rule.outcome is not None
    assert len(rule.outcome.assignments) == 2
