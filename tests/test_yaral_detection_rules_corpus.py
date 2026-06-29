"""Regression coverage for real detection-rules YARA-L syntax."""

from __future__ import annotations

from textwrap import dedent

from yaraast.yaral.enhanced_parser import EnhancedYaraLParser
from yaraast.yaral.generator import YaraLGenerator


def _parse_without_recovery_errors(source: str) -> str:
    parser = EnhancedYaraLParser(dedent(source))
    ast = parser.parse()
    assert parser.errors == []
    return YaraLGenerator().generate(ast)


def test_yaral_accepts_reference_list_without_closing_percent_and_field() -> None:
    generated = _parse_without_recovery_errors("""
        rule reference_list_field {
          events:
            $role in %sap_sensitive_roles.role
          condition:
            $role
        }
        """)

    assert "$role in %sap_sensitive_roles.role" in generated


def test_yaral_accepts_literal_left_comparison_inside_if_expression() -> None:
    generated = _parse_without_recovery_errors("""
        rule literal_left_if {
          events:
            $login.metadata.event_timestamp.seconds = $timestamp
          outcome:
            $risk_score = max(
              if (01 = timestamp.get_day_of_week($timestamp, "UTC"), 10)
            )
          condition:
            $login
        }
        """)

    assert 'if(1 = timestamp.get_day_of_week($timestamp, "UTC"), 10)' in generated
