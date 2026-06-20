"""Coverage for OptimizationAnalyzer suggestion paths and YARA-X visitors.

Drives the analyzer over rules that trigger optimization suggestions and over
YARA-X constructs (for / for-of / with / comprehensions / lambda) so the
per-node-type visitor methods and scope handling run.
"""

from __future__ import annotations

import pytest

from yaraast.analysis.optimization import OptimizationAnalyzer
from yaraast.ast.base import YaraFile
from yaraast.ast.expressions import BinaryExpression, Identifier, IntegerLiteral
from yaraast.ast.rules import Rule
from yaraast.parser.source import parse_yara_source
from yaraast.yarax.ast_nodes import WithDeclaration, WithStatement
from yaraast.yarax.parser import YaraXParser


def test_many_strings_any_of_them_yields_suggestions() -> None:
    strings = "\n".join(f'    $s{i} = "string_value_{i}"' for i in range(12))
    source = f"rule big {{\n  strings:\n{strings}\n  condition:\n    any of them\n}}"

    report = OptimizationAnalyzer().analyze(parse_yara_source(source))

    assert report.suggestions
    assert report.high_impact_count >= 0
    assert all(isinstance(suggestion.format(), str) for suggestion in report.suggestions)


@pytest.mark.parametrize(
    "condition",
    [
        "for any i in (1..3) : ( i > 0 )",
        "for all of them : ( $ )",
        "for any of ($s*) : ( $ )",
    ],
)
def test_analyze_standard_for_expressions(condition: str) -> None:
    source = f'rule r {{\n  strings:\n    $s0 = "a"\n  condition:\n    {condition}\n}}'
    report = OptimizationAnalyzer().analyze(parse_yara_source(source))
    assert report is not None


@pytest.mark.parametrize(
    "condition",
    [
        "[x for x in (1, 2, 3) if x > 0]",
        "{k: v for k, v in pairs}",
        "lambda x: x + 1",
    ],
)
def test_analyze_yarax_expressions(condition: str) -> None:
    expr = YaraXParser(condition).parse_expression()
    report = OptimizationAnalyzer().analyze(YaraFile(rules=[Rule(name="yx", condition=expr)]))
    assert report is not None


def test_analyze_with_statement_scopes_declarations() -> None:
    declaration = WithDeclaration(identifier="a", value=IntegerLiteral(value=1))
    body = BinaryExpression(left=Identifier(name="a"), operator=">", right=IntegerLiteral(value=0))
    statement = WithStatement(declarations=[declaration], body=body)

    report = OptimizationAnalyzer().analyze(YaraFile(rules=[Rule(name="w", condition=statement)]))
    assert report is not None
