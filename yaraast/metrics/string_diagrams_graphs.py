"""Graph generation helpers for string pattern diagrams."""

from __future__ import annotations

from typing import TYPE_CHECKING, Any

from yaraast.metrics.string_diagrams_graph_builders import (
    add_pattern_relationships as builder_add_pattern_relationships,
)
from yaraast.metrics.string_diagrams_graph_builders import (
    generate_hex_pattern_diagram as builder_generate_hex_pattern_diagram,
)
from yaraast.metrics.string_diagrams_graph_builders import (
    generate_pattern_complexity_diagram as builder_generate_pattern_complexity_diagram,
)
from yaraast.metrics.string_diagrams_graph_builders import (
    generate_pattern_flow_diagram as builder_generate_pattern_flow_diagram,
)
from yaraast.metrics.string_diagrams_graph_builders import (
    generate_pattern_similarity_diagram as builder_generate_pattern_similarity_diagram,
)
from yaraast.metrics.string_diagrams_graph_builders import (
    render_or_write_dot as builder_render_or_write_dot,
)

if TYPE_CHECKING:
    from yaraast.ast.base import YaraFile


class StringDiagramGraphsMixin:
    """Mixin providing string diagram helpers."""

    @staticmethod
    def _render_or_write_dot(dot, output_path: str, format: str) -> str:
        return builder_render_or_write_dot(dot, output_path, format)

    def generate_pattern_flow_diagram(
        self,
        ast: YaraFile,
        output_path: str | None = None,
        format: str = "svg",
    ) -> str:
        return builder_generate_pattern_flow_diagram(self, ast, output_path, format)

    def generate_pattern_complexity_diagram(
        self,
        ast: YaraFile,
        output_path: str | None = None,
        format: str = "svg",
    ) -> str:
        return builder_generate_pattern_complexity_diagram(self, ast, output_path, format)

    def generate_pattern_similarity_diagram(
        self,
        ast: YaraFile,
        output_path: str | None = None,
        format: str = "svg",
    ) -> str:
        return builder_generate_pattern_similarity_diagram(self, ast, output_path, format)

    def generate_hex_pattern_diagram(
        self,
        ast: YaraFile,
        output_path: str | None = None,
        format: str = "svg",
    ) -> str:
        return builder_generate_hex_pattern_diagram(self, ast, output_path, format)

    def _add_pattern_relationships(self, dot: Any) -> None:
        builder_add_pattern_relationships(self, dot)
