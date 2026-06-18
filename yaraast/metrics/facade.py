"""Operational facade for the metrics subsystem."""

from __future__ import annotations

try:
    from yaraast.metrics.dependency_graph import DependencyGraphGenerator
except ModuleNotFoundError as exc:
    if exc.name != "graphviz":
        raise
    DependencyGraphGenerator = None
