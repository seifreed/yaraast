"""String pattern diagrams for YARA AST analysis."""

from __future__ import annotations

from collections import defaultdict
from typing import TYPE_CHECKING, Any

from yaraast.metrics._visitor_base import MetricsVisitorBase

from .string_diagrams_analysis import StringDiagramAnalysisMixin
from .string_diagrams_graphs import StringDiagramGraphsMixin
from .string_diagrams_labels import StringDiagramLabelsMixin
from .string_diagrams_render import StringDiagramRenderMixin
from .string_diagrams_stats import StringDiagramStatsMixin

if TYPE_CHECKING:
    pass


class StringDiagramGenerator(
    StringDiagramLabelsMixin,
    StringDiagramStatsMixin,
    StringDiagramAnalysisMixin,
    StringDiagramGraphsMixin,
    StringDiagramRenderMixin,
    MetricsVisitorBase,
):
    """Generates string pattern analysis diagrams."""

    def __init__(self) -> None:
        super().__init__(default=None)
        self.string_patterns: dict[str, dict[str, Any]] = {}
        self.pattern_relationships: dict[str, set[str]] = defaultdict(set)
        self.pattern_stats: dict[str, Any] = {}
        self._current_rule: str | None = None


from .string_diagrams_helpers import (
    analyze_string_patterns,
    create_hex_diagram,
    create_regex_diagram,
    generate_pattern_report,
    generate_string_diagram,
)

__all__ = [
    "StringDiagramGenerator",
    "analyze_string_patterns",
    "create_hex_diagram",
    "create_regex_diagram",
    "generate_pattern_report",
    "generate_string_diagram",
]
