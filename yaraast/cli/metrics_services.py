"""Service wrappers around metrics subsystem workflows."""

from __future__ import annotations

from collections.abc import Sequence
from typing import Any

from yaraast.ast.base import YaraFile
from yaraast.cli.utils import parse_yara_file as _parse_yara_file
from yaraast.metrics import workflows as _workflows

try:
    from yaraast.metrics import DependencyGraphGenerator
except ModuleNotFoundError:
    DependencyGraphGenerator = None  # type: ignore[assignment]

MetricsReportData = _workflows.MetricsReportData
_DEFAULT_FACTORY = object()


__all__ = [
    "MetricsReportData",
    "analyze_complexity",
    "build_complexity_payload",
    "build_report",
    "determine_graph_output_path",
    "determine_pattern_output_path",
    "generate_dependency_graph",
    "generate_dependency_graph_with_generator",
    "generate_dependency_graphs",
    "generate_html_tree",
    "generate_html_tree_file",
    "generate_pattern_diagram",
    "generate_pattern_diagram_with_generator",
    "generate_pattern_diagrams",
    "is_graphviz_error",
    "parse_yara_file",
]


def analyze_complexity(ast: YaraFile) -> Any:
    return _workflows.analyze_complexity(ast)


def is_graphviz_error(error: Exception) -> bool:
    return _workflows.is_graphviz_error(error)


def build_complexity_payload(metrics: Any) -> dict[str, Any]:
    return _workflows.build_complexity_payload(metrics)


def generate_dependency_graphs(
    ast: YaraFile,
    output_dir: str,
    base_name: str,
    image_format: str,
    generator_factory: Any = _DEFAULT_FACTORY,
) -> Sequence[str]:
    factory = (
        DependencyGraphGenerator if generator_factory is _DEFAULT_FACTORY else generator_factory
    )
    return _workflows.generate_dependency_graphs(ast, output_dir, base_name, image_format, factory)


def generate_html_tree(
    ast: YaraFile,
    output_dir: str,
    base_name: str,
    interactive: bool = True,
    generator_factory: Any = None,
) -> str:
    if generator_factory is None:
        return _workflows.generate_html_tree(ast, output_dir, base_name, interactive)
    return _workflows.generate_html_tree(ast, output_dir, base_name, interactive, generator_factory)


def generate_pattern_diagrams(
    ast: YaraFile,
    output_dir: str,
    base_name: str,
    image_format: str,
    generator_factory: Any = None,
) -> Sequence[str]:
    if generator_factory is None:
        return _workflows.generate_pattern_diagrams(ast, output_dir, base_name, image_format)
    return _workflows.generate_pattern_diagrams(
        ast, output_dir, base_name, image_format, generator_factory
    )


def build_report(
    ast: YaraFile, output_dir: str, base_name: str, image_format: str
) -> MetricsReportData:
    metrics = analyze_complexity(ast)
    payload = build_complexity_payload(metrics)

    generated_files = []
    try:
        generated_files.extend(generate_dependency_graphs(ast, output_dir, base_name, image_format))
    except Exception as exc:
        if not is_graphviz_error(exc):
            raise
    generated_files.append(generate_html_tree(ast, output_dir, base_name, interactive=True))
    try:
        generated_files.extend(generate_pattern_diagrams(ast, output_dir, base_name, image_format))
    except Exception as exc:
        if not is_graphviz_error(exc):
            raise

    return MetricsReportData(
        base_name=base_name,
        complexity_metrics=metrics,
        complexity_payload=payload,
        generated_files=generated_files,
    )


def determine_graph_output_path(
    yara_file: str, output: str | None, graph_type: str, fmt: str
) -> str:
    return _workflows.determine_graph_output_path(yara_file, output, graph_type, fmt)


def generate_dependency_graph(
    ast: YaraFile,
    graph_type: str,
    output_path: str,
    fmt: str,
    engine: str,
) -> str:
    if DependencyGraphGenerator is None:
        msg = "Graph visualization requires the 'graphviz' Python package."
        raise RuntimeError(msg)
    return _workflows.generate_dependency_graph(ast, graph_type, output_path, fmt, engine)


def generate_dependency_graph_with_generator(
    generator: Any,
    ast: YaraFile,
    graph_type: str,
    output_path: str,
    fmt: str,
    engine: str,
) -> str:
    return _workflows.generate_dependency_graph_with_generator(
        generator, ast, graph_type, output_path, fmt, engine
    )


def determine_pattern_output_path(
    yara_file: str, output: str | None, pattern_type: str, fmt: str
) -> str:
    return _workflows.determine_pattern_output_path(yara_file, output, pattern_type, fmt)


def generate_pattern_diagram(ast: YaraFile, pattern_type: str, output_path: str, fmt: str) -> str:
    return _workflows.generate_pattern_diagram(ast, pattern_type, output_path, fmt)


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


def generate_html_tree_file(
    ast: YaraFile,
    output_path: str,
    title: str,
    interactive: bool,
    include_metadata: bool,
) -> str:
    return _workflows.generate_html_tree_file(
        ast, output_path, title, interactive, include_metadata
    )


def parse_yara_file(yara_file: str) -> YaraFile:
    """Parse a YARA file into an AST."""
    return _parse_yara_file(yara_file)
