"""Graph generation helpers for string pattern diagrams."""

from __future__ import annotations

from os import PathLike
from typing import TYPE_CHECKING, Any

if TYPE_CHECKING:
    from yaraast.ast.base import YaraFile


def _graph_builders() -> Any:
    from yaraast.metrics import string_diagrams_graph_builders

    return string_diagrams_graph_builders


class StringDiagramGraphsMixin:
    """Mixin providing string diagram helpers."""

    @staticmethod
    def _render_or_write_dot(dot, output_path: str | PathLike[str], format: str) -> str:
        return _graph_builders().render_or_write_dot(dot, output_path, format)

    def generate_pattern_flow_diagram(
        self,
        ast: YaraFile,
        output_path: str | None = None,
        format: str = "svg",
    ) -> str:
        return _graph_builders().generate_pattern_flow_diagram(self, ast, output_path, format)

    def generate_pattern_complexity_diagram(
        self,
        ast: YaraFile,
        output_path: str | None = None,
        format: str = "svg",
    ) -> str:
        return _graph_builders().generate_pattern_complexity_diagram(self, ast, output_path, format)

    def generate_pattern_similarity_diagram(
        self,
        ast: YaraFile,
        output_path: str | None = None,
        format: str = "svg",
    ) -> str:
        return _graph_builders().generate_pattern_similarity_diagram(self, ast, output_path, format)

    def generate_hex_pattern_diagram(
        self,
        ast: YaraFile,
        output_path: str | None = None,
        format: str = "svg",
    ) -> str:
        return _graph_builders().generate_hex_pattern_diagram(self, ast, output_path, format)

    def _add_pattern_relationships(self, dot: Any) -> None:
        _graph_builders().add_pattern_relationships(self, dot)
