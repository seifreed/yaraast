"""Optimization services for CLI (logic without IO)."""

from __future__ import annotations

from dataclasses import dataclass

from yaraast.codegen.generator import CodeGenerator
from yaraast.parser.error_tolerant_parser import ErrorTolerantParser
from yaraast.performance.optimizer import PerformanceOptimizer
from yaraast.performance.string_analyzer import analyze_rule_performance


@dataclass
class OptimizationAnalysis:
    total_issues: int
    critical_issues: int


def parse_yara_with_tolerance(content: str):
    parser = ErrorTolerantParser()
    return parser.parse_with_errors(content)


def analyze_performance(ast) -> OptimizationAnalysis:
    total_issues = 0
    critical = 0
    for rule in ast.rules:
        issues = analyze_rule_performance(rule)
        total_issues += len(issues)
        critical += sum(1 for i in issues if i.severity == "critical")
    return OptimizationAnalysis(total_issues=total_issues, critical_issues=critical)


def optimize_ast(ast):
    optimizer = PerformanceOptimizer()
    optimized_ast = optimizer.optimize(ast)
    return optimized_ast, ["Performance optimizations applied"]


def generate_code(ast) -> str:
    generator = CodeGenerator()
    return generator.generate(ast)


def calculate_improvement(
    before: OptimizationAnalysis, after: OptimizationAnalysis
) -> float | None:
    if before.total_issues <= 0:
        return None
    if before.total_issues <= after.total_issues:
        return None
    return ((before.total_issues - after.total_issues) / before.total_issues) * 100
