"""Operational workflows for the metrics subsystem."""

from __future__ import annotations

from collections.abc import Callable
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from yaraast.ast.base import YaraFile
from yaraast.metrics.capabilities import get_capability
from yaraast.metrics.complexity import ComplexityAnalyzer
from yaraast.metrics.complexity_model import ComplexityMetrics
from yaraast.metrics.dependency_graph_helpers import require_output_path
from yaraast.metrics.graphviz_errors import is_graphviz_error
from yaraast.metrics.html_tree import HtmlTreeGenerator
from yaraast.metrics.string_diagrams import StringDiagramGenerator

__all__ = ["DependencyGraphGenerator"]

try:
    from yaraast.metrics.dependency_graph import DependencyGraphGenerator
except ModuleNotFoundError as exc:
    if exc.name != "graphviz":
        raise
    DependencyGraphGenerator = None


@dataclass
class MetricsReportData:
    base_name: str
    complexity_metrics: ComplexityMetrics
    generated_files: list[str]


def analyze_complexity(ast: YaraFile) -> ComplexityMetrics:
    return ComplexityAnalyzer().analyze(ast)


def build_complexity_payload(metrics: ComplexityMetrics) -> dict[str, Any]:
    capability = get_capability("complexity")
    result = metrics.to_dict()
    result["quality_score"] = metrics.get_quality_score()
    result["quality_grade"] = metrics.get_complexity_grade()
    result["heuristic"] = True
    result["analysis_kind"] = "heuristic"
    if capability is not None:
        result["capability"] = capability["name"]
        result["capability_outputs"] = list(capability["outputs"])
    return result


def _require_non_empty_text(value: object, name: str) -> str:
    if not isinstance(value, str):
        msg = f"{name} must be a string"
        raise TypeError(msg)
    if not value.strip():
        msg = f"{name} must not be empty"
        raise ValueError(msg)
    return value


def generate_dependency_graphs(
    ast: YaraFile,
    output_dir: Path,
    base_name: str,
    image_format: str,
    generator_factory: Callable[[], Any] | None = DependencyGraphGenerator,
) -> list[str]:
    if generator_factory is None:
        msg = "Graph visualization requires the 'graphviz' Python package."
        raise RuntimeError(msg)
    generator = (
        generator_factory()
        if generator_factory is not DependencyGraphGenerator
        else DependencyGraphGenerator()
    )
    generated = []

    deps_path = output_dir / f"{base_name}_dependencies.{image_format}"
    generator.generate_graph(ast, str(deps_path), image_format)
    generated.append(deps_path.name)

    rules_path = output_dir / f"{base_name}_rules.{image_format}"
    generator.generate_rule_graph(ast, str(rules_path), image_format)
    generated.append(rules_path.name)

    complexity_path = output_dir / f"{base_name}_complexity_graph.{image_format}"
    metrics = analyze_complexity(ast)
    generator.generate_complexity_graph(
        ast, metrics.cyclomatic_complexity, str(complexity_path), image_format
    )
    generated.append(complexity_path.name)
    return generated


def generate_html_tree(
    ast: YaraFile,
    output_dir: Path,
    base_name: str,
    interactive: bool = True,
    generator_factory: Callable[[], Any] = HtmlTreeGenerator,
) -> str:
    generator = (
        generator_factory() if generator_factory is not HtmlTreeGenerator else HtmlTreeGenerator()
    )
    output_path = output_dir / f"{base_name}_tree.html"
    if interactive:
        generator.generate_interactive_html(ast, str(output_path))
    else:
        generator.generate_html(ast, str(output_path))
    return output_path.name


def generate_pattern_diagrams(
    ast: YaraFile,
    output_dir: Path,
    base_name: str,
    image_format: str,
    generator_factory: Callable[[], Any] = StringDiagramGenerator,
) -> list[str]:
    generator = (
        generator_factory()
        if generator_factory is not StringDiagramGenerator
        else StringDiagramGenerator()
    )
    generated = []

    flow_path = output_dir / f"{base_name}_pattern_flow.{image_format}"
    generator.generate_pattern_flow_diagram(ast, str(flow_path), image_format)
    generated.append(flow_path.name)

    complexity_path = output_dir / f"{base_name}_pattern_complexity.{image_format}"
    generator.generate_pattern_complexity_diagram(ast, str(complexity_path), image_format)
    generated.append(complexity_path.name)

    hex_path = output_dir / f"{base_name}_hex_patterns.{image_format}"
    generator.generate_hex_pattern_diagram(ast, str(hex_path), image_format)
    generated.append(hex_path.name)
    return generated


def build_report(
    ast: YaraFile, output_dir: Path, base_name: str, image_format: str
) -> MetricsReportData:
    metrics = analyze_complexity(ast)

    generated_files = []
    try:
        generated_files.extend(generate_dependency_graphs(ast, output_dir, base_name, image_format))
    except Exception as exc:  # suppress missing graphviz, re-raise others
        if not is_graphviz_error(exc):
            raise
    generated_files.append(generate_html_tree(ast, output_dir, base_name, interactive=True))
    try:
        generated_files.extend(generate_pattern_diagrams(ast, output_dir, base_name, image_format))
    except Exception as exc:  # suppress missing graphviz, re-raise others
        if not is_graphviz_error(exc):
            raise

    return MetricsReportData(
        base_name=base_name,
        complexity_metrics=metrics,
        generated_files=generated_files,
    )


def determine_graph_output_path(yara_file: str, output: object, graph_type: str, fmt: str) -> str:
    yara_file = _require_non_empty_text(yara_file, "yara_file")
    graph_type = _require_non_empty_text(graph_type, "graph_type")
    fmt = _require_non_empty_text(fmt, "output format")
    if output is not None:
        return str(require_output_path(output))
    base_name = Path(yara_file).stem
    return f"{base_name}_graph_{graph_type}.{fmt}"


def determine_pattern_output_path(
    yara_file: str, output: object, pattern_type: str, fmt: str
) -> str:
    yara_file = _require_non_empty_text(yara_file, "yara_file")
    pattern_type = _require_non_empty_text(pattern_type, "pattern_type")
    fmt = _require_non_empty_text(fmt, "output format")
    if output is not None:
        return str(require_output_path(output))
    base_name = Path(yara_file).stem
    return f"{base_name}_patterns_{pattern_type}.{fmt}"
