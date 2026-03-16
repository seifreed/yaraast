"""AST-focused report generation for complexity analysis."""

from __future__ import annotations

from typing import Any

from yaraast.ast.base import YaraFile
from yaraast.metrics.complexity import ComplexityAnalyzer
from yaraast.metrics.complexity_helpers import (
    calculate_cognitive_complexity,
    calculate_rule_complexity,
)


def generate_complexity_report(ast: YaraFile) -> dict[str, Any]:
    """Generate a comprehensive complexity report for a YARA file."""
    analyzer = ComplexityAnalyzer()
    metrics = analyzer.analyze(ast)

    rules_data = []
    for rule in ast.rules:
        complexity = calculate_rule_complexity(rule)
        cyclomatic = metrics.cyclomatic_complexity.get(rule.name, 1)
        cognitive = calculate_cognitive_complexity(rule.condition) if rule.condition else 0

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
            "avg_complexity": sum(r["total_complexity"] for r in rules_data)
            / max(1, len(rules_data)),
            "max_complexity": max(
                (r["total_complexity"] for r in rules_data),
                default=0,
            ),
            "quality_score": metrics.get_quality_score(),
            "quality_grade": metrics.get_complexity_grade(),
        },
        "metrics": metrics.to_dict(),
    }
