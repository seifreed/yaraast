"""Real tests for YARA-L validator (no mocks)."""

from __future__ import annotations

from textwrap import dedent

from yaraast.yaral.parser import YaraLParser
from yaraast.yaral.validator import YaraLValidator


def test_validator_detects_missing_sections() -> None:
    code = dedent(
        """
        rule missing_sections {
        }
        """,
    )
    ast = YaraLParser(code).parse()
    errors, _warnings = YaraLValidator().validate(ast)
    assert any("events section" in e.message for e in errors)
    assert any("condition section" in e.message for e in errors)


def test_validator_warns_on_unknown_udm() -> None:
    code = dedent(
        """
        rule udm_test {
            events:
                $e.unknown.field = "x"
            condition:
                $e
        }
        """,
    )
    ast = YaraLParser(code).parse()
    _errors, warnings = YaraLValidator().validate(ast)
    assert any("Unknown UDM namespace" in w.message for w in warnings)
