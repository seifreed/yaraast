"""Capability model for the metrics subsystem."""

from __future__ import annotations

from dataclasses import dataclass


@dataclass(frozen=True)
class MetricsCapability:
    name: str
    entrypoint: str
    outputs: tuple[str, ...]
    heuristic: bool
    description: str


CAPABILITIES: tuple[MetricsCapability, ...] = (
    MetricsCapability(
        name="complexity",
        entrypoint="ComplexityAnalyzer",
        outputs=("metrics", "quality_score", "quality_grade"),
        heuristic=True,
        description="Heuristic AST complexity scoring and rule-level quality signals.",
    ),
    MetricsCapability(
        name="dependency_graph",
        entrypoint="DependencyGraphGenerator",
        outputs=("graphviz_graphs", "rule_graphs", "module_graphs"),
        heuristic=True,
        description="Dependency and complexity graphs derived from AST structure.",
    ),
    MetricsCapability(
        name="html_tree",
        entrypoint="HtmlTreeGenerator",
        outputs=("interactive_html", "static_html"),
        heuristic=False,
        description="Structural HTML visualization of the parsed AST.",
    ),
    MetricsCapability(
        name="string_diagrams",
        entrypoint="StringDiagramGenerator",
        outputs=("flow_diagrams", "complexity_diagrams", "hex_diagrams", "similarity_diagrams"),
        heuristic=True,
        description="Pattern-oriented diagrams and summaries for YARA strings.",
    ),
)


def get_capability(name: str) -> MetricsCapability | None:
    for capability in CAPABILITIES:
        if capability.name == name:
            return capability
    return None
