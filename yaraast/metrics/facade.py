"""Operational facade for the metrics subsystem."""

from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path
from typing import Any

from yaraast.metrics.capabilities import CAPABILITIES, MetricsCapability, get_capability
from yaraast.metrics.complexity import ComplexityAnalyzer
from yaraast.metrics.dependency_graph import DependencyGraphGenerator
from yaraast.metrics.html_tree import HtmlTreeGenerator
from yaraast.metrics.string_diagrams import StringDiagramGenerator


@dataclass(frozen=True)
class MetricsSubsystem:
    """Provide a single conceptual entry point for metrics capabilities."""

    complexity_analyzer: type[ComplexityAnalyzer] = ComplexityAnalyzer
    dependency_graph_generator: type[DependencyGraphGenerator] = DependencyGraphGenerator
    html_tree_generator: type[HtmlTreeGenerator] = HtmlTreeGenerator
    string_diagram_generator: type[StringDiagramGenerator] = StringDiagramGenerator

    def new_complexity_analyzer(self) -> ComplexityAnalyzer:
        return self.complexity_analyzer()

    def new_dependency_graph_generator(self) -> DependencyGraphGenerator:
        return self.dependency_graph_generator()

    def new_html_tree_generator(self) -> HtmlTreeGenerator:
        return self.html_tree_generator()

    def new_string_diagram_generator(self) -> StringDiagramGenerator:
        return self.string_diagram_generator()

    def list_capabilities(self) -> tuple[MetricsCapability, ...]:
        return CAPABILITIES

    def get_capability(self, name: str) -> MetricsCapability | None:
        return get_capability(name)

    def analyze_complexity(self, ast: Any) -> Any:
        from yaraast.metrics.workflows import analyze_complexity

        return analyze_complexity(ast)

    def build_report(self, ast: Any, output_dir: Path, base_name: str, image_format: str) -> Any:
        from yaraast.metrics.workflows import build_report

        return build_report(ast, output_dir, base_name, image_format)


METRICS = MetricsSubsystem()
