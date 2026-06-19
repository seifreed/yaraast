"""Capability lookup for the metrics subsystem."""

from __future__ import annotations

from typing import Any

from yaraast.ast.base import require_string

_CAPABILITIES: dict[str, dict[str, Any]] = {
    "complexity": {
        "name": "complexity",
        "outputs": ("metrics", "quality_score", "quality_grade"),
    },
    "dependency_graph": {
        "name": "dependency_graph",
        "outputs": ("graphviz_graphs", "rule_graphs", "module_graphs"),
    },
    "html_tree": {
        "name": "html_tree",
        "outputs": ("interactive_html", "static_html"),
    },
    "string_diagrams": {
        "name": "string_diagrams",
        "outputs": ("flow_diagrams", "complexity_diagrams", "hex_diagrams", "similarity_diagrams"),
    },
}


def get_capability(name: str) -> dict[str, Any] | None:
    name = require_string(name, "Metrics capability name")
    if not name.strip():
        msg = "Metrics capability name cannot be empty"
        raise ValueError(msg)
    return _CAPABILITIES.get(name)
