"""Additional tests for complexity metrics (no mocks)."""

from __future__ import annotations

from collections.abc import Iterator
from typing import Any, cast

from yaraast.ast.base import YaraFile
from yaraast.ast.conditions import ForOfExpression, OfExpression
from yaraast.ast.expressions import BinaryExpression, BooleanLiteral
from yaraast.ast.rules import Rule
from yaraast.metrics.complexity import ComplexityAnalyzer
from yaraast.parser import Parser
from yaraast.parser.source import parse_yara_source
from yaraast.yarax.ast_nodes import ArrayComprehension, DictComprehension, PatternMatch


def _rule_complexity(rule: Rule) -> int:
    complexity = 1
    if rule.strings:
        complexity += len(rule.strings)
        for string in rule.strings:
            if string.__class__.__name__ == "RegexString":
                complexity += 2
            elif string.__class__.__name__ == "HexString":
                complexity += 1
    if rule.condition is not None:
        complexity += 1
    if any(str(m) == "private" for m in rule.modifiers):
        complexity += 1
    if any(str(m) == "global" for m in rule.modifiers):
        complexity += 1
    return complexity


def _cyclomatic_complexity(expr: object) -> int:
    complexity = 1
    op = expr.operator if hasattr(expr, "operator") else None
    if op in ("and", "or"):
        complexity += 1
    if isinstance(expr, ForOfExpression | ArrayComprehension | DictComprehension):
        complexity += 1
    if isinstance(expr, PatternMatch):
        complexity += max(1, len(expr.cases) + (1 if expr.default is not None else 0))

    for child in _iter_cyclomatic_children(expr):
        complexity += _cyclomatic_complexity(child) - 1
    return complexity


def _iter_cyclomatic_children(expr: object) -> Iterator[object]:
    child_attrs = (
        "left",
        "right",
        "operand",
        "expression",
        "body",
        "quantifier",
        "iterable",
        "condition",
        "string_set",
        "declarations",
        "value",
        "cases",
        "default",
        "pattern",
        "result",
        "elements",
        "items",
        "key",
        "key_expression",
        "value_expression",
        "tuple_expr",
        "index",
        "target",
        "start",
        "stop",
        "step",
        "arguments",
    )
    for attr in child_attrs:
        value = getattr(expr, attr, None)
        if hasattr(value, "accept"):
            yield value
        elif isinstance(value, list | tuple | set | frozenset):
            for item in value:
                if hasattr(item, "accept"):
                    yield item


def _build_complexity_report(ast: YaraFile) -> dict[str, Any]:
    analyzer = ComplexityAnalyzer()
    metrics = analyzer.analyze(ast)
    rules_data: list[dict[str, Any]] = []
    total_complexities: list[int] = []
    for rule in ast.rules:
        complexity = _rule_complexity(rule)
        total_complexities.append(complexity)
        metric_key = analyzer._metric_key_for_rule(rule)
        cyclomatic = metrics.cyclomatic_complexity.get(metric_key, 1)
        cognitive = metrics.cyclomatic_complexity.get(metric_key, 1)
        rules_data.append(
            {
                "name": rule.name,
                "total_complexity": complexity,
                "cyclomatic_complexity": cyclomatic,
                "cognitive_complexity": cognitive,
                "strings": len(rule.strings) if rule.strings else 0,
                "modifiers": len(rule.modifiers),
            },
        )
    return {
        "rules": rules_data,
        "summary": {
            "total_rules": len(ast.rules),
            "avg_complexity": sum(total_complexities) / max(1, len(total_complexities)),
            "max_complexity": max(total_complexities, default=0),
            "quality_score": metrics.get_quality_score(),
            "quality_grade": metrics.get_complexity_grade(),
        },
        "metrics": metrics.to_dict(),
    }


class _HashableDecision:
    operator = "and"

    def accept(self, visitor: object) -> object:
        return visitor

    def __hash__(self) -> int:
        return id(self)


def test_complexity_analyzer_basic_counts() -> None:
    code = """
import "pe"
rule r1 {
  strings:
    $a = "x"
  condition:
    $a
}
""".lstrip()
    ast = Parser().parse(code)
    analyzer = ComplexityAnalyzer()
    metrics = analyzer.analyze(ast)

    assert metrics.total_rules == 1
    assert metrics.total_imports == 1
    assert metrics.rules_with_strings == 1


def test_complexity_analyzer_accepts_raw_string_sets() -> None:
    ast = YaraFile(
        rules=[
            Rule(name="for_raw", condition=ForOfExpression("all", "them", condition=None)),
            Rule(name="of_raw", condition=OfExpression("any", ["$a", "$b"])),
            Rule(name="for_list", condition=ForOfExpression("any", ["$a"], BooleanLiteral(True))),
            Rule(
                name="of_nested",
                condition=OfExpression(
                    "any",
                    [BinaryExpression(BooleanLiteral(True), "and", BooleanLiteral(False))],
                ),
            ),
        ],
    )

    metrics = ComplexityAnalyzer().analyze(ast)

    assert metrics.for_of_expressions == 2
    assert metrics.of_expressions == 2
    assert metrics.total_binary_ops == 1


def test_complexity_expression_helpers() -> None:
    code = "rule r1 { condition: (1 + 2 == 3) and true }"
    ast = Parser().parse(code)
    expr = ast.rules[0].condition
    assert expr is not None

    assert _cyclomatic_complexity(expr) >= 1


def test_cyclomatic_complexity_traverses_non_list_child_containers() -> None:
    decision = BinaryExpression(BooleanLiteral(True), "and", BooleanLiteral(False))
    hashable_decision = _HashableDecision()
    hashable_container = cast(Any, frozenset((hashable_decision,)))

    assert _cyclomatic_complexity(OfExpression("any", [decision])) == 2
    assert _cyclomatic_complexity(OfExpression("any", (decision,))) == 2
    assert _cyclomatic_complexity(OfExpression("any", hashable_container)) == 2


def test_generate_complexity_report_from_parsed_source() -> None:
    ast = parse_yara_source("rule r1 { condition: true }")
    report = _build_complexity_report(ast)

    assert report["summary"]["total_rules"] == 1
    assert report["rules"][0]["name"] == "r1"
