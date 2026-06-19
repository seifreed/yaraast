"""Metrics subsystem facade for YARA AST analysis and visualization."""

from __future__ import annotations

from yaraast.metrics.complexity import ComplexityAnalyzer
from yaraast.metrics.html_tree import HtmlTreeGenerator
from yaraast.metrics.string_diagrams import StringDiagramGenerator

try:
    from yaraast.metrics.dependency_graph import DependencyGraphGenerator
except ModuleNotFoundError as exc:
    if exc.name != "graphviz":
        raise
    DependencyGraphGenerator = None

__all__ = [
    "ComplexityAnalyzer",
    "DependencyGraphGenerator",
    "HtmlTreeGenerator",
    "StringDiagramGenerator",
]
