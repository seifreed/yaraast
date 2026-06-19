"""String pattern diagrams for YARA AST analysis."""

from __future__ import annotations

from collections import defaultdict
from typing import Any

from yaraast.metrics._visitor_base import MetricsVisitorBase

from .string_diagrams_analysis import StringDiagramAnalysisMixin
from .string_diagrams_labels import StringDiagramLabelsMixin
from .string_diagrams_stats import StringDiagramStatsMixin


class StringDiagramGenerator(
    StringDiagramLabelsMixin,
    StringDiagramStatsMixin,
    StringDiagramAnalysisMixin,
    MetricsVisitorBase,
):
    """Generates string pattern analysis diagrams."""

    def __init__(self) -> None:
        super().__init__(default=None)
        self.string_patterns: dict[str, dict[str, Any]] = {}
        self.pattern_relationships: dict[str, set[str]] = defaultdict(set)
        self.pattern_stats: dict[str, Any] = {}
        self._current_rule: str | None = None

    def generate_pattern_flow_diagram(
        self,
        ast,
        output_path: str | None = None,
        format: str = "svg",
    ) -> str:
        from yaraast.metrics.string_diagrams_graph_builders import generate_pattern_flow_diagram

        return generate_pattern_flow_diagram(self, ast, output_path, format)

    def generate_pattern_complexity_diagram(
        self,
        ast,
        output_path: str | None = None,
        format: str = "svg",
    ) -> str:
        from yaraast.metrics.string_diagrams_graph_builders import (
            generate_pattern_complexity_diagram,
        )

        return generate_pattern_complexity_diagram(self, ast, output_path, format)

    def generate_pattern_similarity_diagram(
        self,
        ast,
        output_path: str | None = None,
        format: str = "svg",
    ) -> str:
        from yaraast.metrics.string_diagrams_graph_builders import (
            generate_pattern_similarity_diagram,
        )

        return generate_pattern_similarity_diagram(self, ast, output_path, format)

    def generate_hex_pattern_diagram(
        self,
        ast,
        output_path: str | None = None,
        format: str = "svg",
    ) -> str:
        from yaraast.metrics.string_diagrams_graph_builders import generate_hex_pattern_diagram

        return generate_hex_pattern_diagram(self, ast, output_path, format)


__all__ = [
    "StringDiagramGenerator",
]
