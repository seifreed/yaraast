"""Optimization services for CLI (logic without IO)."""

from __future__ import annotations

from dataclasses import dataclass

from yaraast.dialects import YaraDialect, detect_dialect
from yaraast.errors import ParseError
from yaraast.parser.error_tolerant_parser import ErrorTolerantParser
from yaraast.parser.source import parse_yara_source
from yaraast.performance.optimizer import PerformanceOptimizer
from yaraast.performance.string_performance_checks import analyze_rule_performance
from yaraast.yarax.generator import YaraXGenerator


@dataclass
class OptimizationAnalysis:
    total_issues: int
    critical_issues: int


def parse_yara_with_tolerance(content: str):
    dialect = detect_dialect(content)
    if dialect == YaraDialect.YARA_L:
        msg = "YARA-L input is not supported by optimize; use YARA-L tooling instead"
        raise ParseError(msg)
    if dialect == YaraDialect.YARA_X:
        return parse_yara_source(content), [], []
    result = ErrorTolerantParser().parse(content)
    return result.ast, [], result.errors


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
    generator = YaraXGenerator()
    return generator.generate(ast)


def calculate_improvement(
    before: OptimizationAnalysis, after: OptimizationAnalysis
) -> float | None:
    if before.total_issues <= 0:
        return None
    if before.total_issues <= after.total_issues:
        return None
    return ((before.total_issues - after.total_issues) / before.total_issues) * 100
