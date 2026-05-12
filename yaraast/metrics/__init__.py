"""Metrics subsystem facade for YARA AST analysis and visualization."""

from typing import Any

from yaraast.metrics.capabilities import CAPABILITIES, MetricsCapability
from yaraast.metrics.complexity import ComplexityAnalyzer
from yaraast.metrics.facade import METRICS, MetricsSubsystem
from yaraast.metrics.html_tree import HtmlTreeGenerator
from yaraast.metrics.string_diagrams import StringDiagramGenerator
from yaraast.metrics.workflows import MetricsReportData

DependencyGraphGenerator: Any

try:
    from yaraast.metrics.dependency_graph import DependencyGraphGenerator
except ImportError:
    DependencyGraphGenerator = None

__all__ = [
    "CAPABILITIES",
    "METRICS",
    "ComplexityAnalyzer",
    "DependencyGraphGenerator",
    "HtmlTreeGenerator",
    "MetricsCapability",
    "MetricsReportData",
    "MetricsSubsystem",
    "StringDiagramGenerator",
]
