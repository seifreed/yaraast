"""Service wrappers around metrics subsystem workflows."""

from __future__ import annotations

from typing import Any

from yaraast.ast.base import YaraFile
from yaraast.metrics import workflows as _workflows
from yaraast.metrics.workflows import DependencyGraphGenerator, MetricsReportData

__all__ = [
    "DependencyGraphGenerator",
    "MetricsReportData",
    "analyze_complexity",
    "determine_graph_output_path",
    "determine_pattern_output_path",
    "generate_dependency_graph_with_generator",
    "generate_pattern_diagram_with_generator",
]


def analyze_complexity(ast: YaraFile) -> Any:
    return _workflows.analyze_complexity(ast)


def determine_graph_output_path(yara_file: str, output: object, graph_type: str, fmt: str) -> str:
    return _workflows.determine_graph_output_path(yara_file, output, graph_type, fmt)


def generate_dependency_graph_with_generator(
    generator: Any,
    ast: YaraFile,
    graph_type: str,
    output_path: str,
    fmt: str,
    engine: str,
) -> tuple[str, Any]:
    return _workflows.generate_dependency_graph_with_generator(
        generator, ast, graph_type, output_path, fmt, engine
    )


def determine_pattern_output_path(
    yara_file: str, output: object, pattern_type: str, fmt: str
) -> str:
    return _workflows.determine_pattern_output_path(yara_file, output, pattern_type, fmt)


def generate_pattern_diagram_with_generator(
    generator: Any,
    ast: YaraFile,
    pattern_type: str,
    output_path: str,
    fmt: str,
) -> str:
    return _workflows.generate_pattern_diagram_with_generator(
        generator, ast, pattern_type, output_path, fmt
    )
