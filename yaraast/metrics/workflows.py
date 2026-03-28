"""Operational workflows for the metrics subsystem."""

from __future__ import annotations

from collections.abc import Callable
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from yaraast.ast.base import YaraFile
from yaraast.errors import ValidationError
from yaraast.metrics.capabilities import get_capability
from yaraast.metrics.complexity_model import ComplexityMetrics
from yaraast.metrics.facade import METRICS
from yaraast.metrics.html_tree import HtmlTreeGenerator
from yaraast.metrics.string_diagrams import StringDiagramGenerator

try:
    from yaraast.metrics.dependency_graph import DependencyGraphGenerator
except ModuleNotFoundError:
    DependencyGraphGenerator = None  # type: ignore[assignment]


@dataclass
class MetricsReportData:
    base_name: str
    complexity_metrics: ComplexityMetrics
    complexity_payload: dict[str, Any]
    generated_files: list[str]


def analyze_complexity(ast: YaraFile) -> ComplexityMetrics:
    analyzer = METRICS.new_complexity_analyzer()
    return analyzer.analyze(ast)


def is_graphviz_error(error: Exception) -> bool:
    """Check if error is caused by missing graphviz installation."""
    # Check exception type first (more reliable than string matching)
    error_type = type(error).__name__
    if error_type in ("ExecutableNotFound", "CalledProcessError"):
        return True
    error_str = str(error)
    graphviz_indicators = [
        "dot",
        "graphviz",
        "ExecutableNotFound",
        "No such file or directory",
    ]
    return any(indicator.lower() in error_str.lower() for indicator in graphviz_indicators)


def build_complexity_payload(metrics: ComplexityMetrics) -> dict[str, Any]:
    capability = get_capability("complexity")
    result = metrics.to_dict()
    result["quality_score"] = metrics.get_quality_score()
    result["quality_grade"] = metrics.get_complexity_grade()
    result["heuristic"] = True
    result["analysis_kind"] = "heuristic"
    if capability is not None:
        result["capability"] = capability.name
        result["capability_outputs"] = list(capability.outputs)
    return result


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
        else METRICS.new_dependency_graph_generator()
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
        generator_factory()
        if generator_factory is not HtmlTreeGenerator
        else METRICS.new_html_tree_generator()
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
        else METRICS.new_string_diagram_generator()
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
    payload = build_complexity_payload(metrics)

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
        complexity_payload=payload,
        generated_files=generated_files,
    )


def determine_graph_output_path(
    yara_file: str, output: str | None, graph_type: str, fmt: str
) -> str:
    if output:
        return output
    base_name = Path(yara_file).stem
    return f"{base_name}_graph_{graph_type}.{fmt}"


def generate_dependency_graph(
    ast: YaraFile, graph_type: str, output_path: str, fmt: str, engine: str
) -> str:
    if DependencyGraphGenerator is None:
        msg = "Graph visualization requires the 'graphviz' Python package."
        raise RuntimeError(msg)
    generator = METRICS.new_dependency_graph_generator()
    return generate_dependency_graph_with_generator(
        generator, ast, graph_type, output_path, fmt, engine
    )


def generate_dependency_graph_with_generator(
    generator: Any,
    ast: YaraFile,
    graph_type: str,
    output_path: str,
    fmt: str,
    engine: str,
) -> tuple[str, Any]:
    if graph_type == "full":
        return generator.generate_graph(ast, output_path, fmt, engine), generator
    if graph_type == "rules":
        return generator.generate_rule_graph(ast, output_path, fmt), generator
    if graph_type == "modules":
        return generator.generate_module_graph(ast, output_path, fmt), generator
    if graph_type == "complexity":
        metrics = analyze_complexity(ast)
        return (
            generator.generate_complexity_graph(
                ast, metrics.cyclomatic_complexity, output_path, fmt
            ),
            generator,
        )
    raise ValidationError(f"Unknown graph type: {graph_type}")


def determine_pattern_output_path(
    yara_file: str, output: str | None, pattern_type: str, fmt: str
) -> str:
    if output:
        return output
    base_name = Path(yara_file).stem
    return f"{base_name}_patterns_{pattern_type}.{fmt}"


def generate_pattern_diagram(ast: YaraFile, pattern_type: str, output_path: str, fmt: str) -> str:
    generator = METRICS.new_string_diagram_generator()
    return generate_pattern_diagram_with_generator(generator, ast, pattern_type, output_path, fmt)


def generate_pattern_diagram_with_generator(
    generator: Any,
    ast: YaraFile,
    pattern_type: str,
    output_path: str,
    fmt: str,
) -> str:
    if pattern_type == "flow":
        return generator.generate_pattern_flow_diagram(ast, output_path, fmt)
    if pattern_type == "complexity":
        return generator.generate_pattern_complexity_diagram(ast, output_path, fmt)
    if pattern_type == "similarity":
        return generator.generate_pattern_similarity_diagram(ast, output_path, fmt)
    if pattern_type == "hex":
        return generator.generate_hex_pattern_diagram(ast, output_path, fmt)
    raise ValidationError(f"Unknown pattern type: {pattern_type}")


def generate_html_tree_file(
    ast: YaraFile,
    output_path: str,
    title: str,
    interactive: bool,
    include_metadata: bool,
) -> str:
    generator = HtmlTreeGenerator(include_metadata=include_metadata)
    if interactive:
        generator.generate_interactive_html(ast, output_path, title)
    else:
        generator.generate_html(ast, output_path, title)
    return output_path
