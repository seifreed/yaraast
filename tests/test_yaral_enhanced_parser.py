"""Tests for Enhanced YARA-L parser."""

from __future__ import annotations

from yaraast.yaral.enhanced_parser import EnhancedYaraLParser


def test_enhanced_parser_full_rule() -> None:
    yaral_code = """
    rule enhanced_rule {
        meta:
            author = "team"

        events:
            $e.metadata.event_type = "LOGIN" and $e.principal.hostname = "host1"

        condition:
            #e > 1 and $e

        outcome:
            $e = count(metadata.event_type)
            if #e > 1 then "high" else "low"

        options:
            case_insensitive = true
    }
    """

    parser = EnhancedYaraLParser(yaral_code)
    ast = parser.parse()

    assert parser.errors == []
    assert len(ast.rules) == 1
    rule = ast.rules[0]
    assert rule.name == "enhanced_rule"
    assert rule.events is not None
    assert rule.condition is not None
    assert rule.outcome is not None
    assert rule.options is not None
    assert "case_insensitive" in rule.options.options
