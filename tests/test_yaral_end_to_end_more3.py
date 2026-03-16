"""End-to-end YARA-L tests (no mocks)."""

from __future__ import annotations

from textwrap import dedent

from yaraast.yaral.generator import YaraLGenerator
from yaraast.yaral.optimizer import YaraLOptimizer
from yaraast.yaral.parser import YaraLParser
from yaraast.yaral.validator import YaraLValidator


def test_yaral_parse_validate_optimize_generate() -> None:
    code = dedent(
        """
        rule login_burst {
            events:
                $e.metadata.event_type = "LOGIN"
            match:
                $e over 10m
            condition:
                #e > 3 and $e
            outcome:
                $count = count($e.target.ip)
        }
        """,
    )

    parser = YaraLParser(code)
    ast = parser.parse()

    errors, warnings = YaraLValidator().validate(ast)
    assert not errors
    assert warnings is not None

    optimized, _stats = YaraLOptimizer().optimize(ast)
    generated = YaraLGenerator().generate(optimized)

    assert "rule login_burst" in generated
    assert "events:" in generated and "condition:" in generated
