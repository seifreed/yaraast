"""Additional real coverage for dependency_graph_render helpers."""

from __future__ import annotations

from yaraast.metrics.dependency_graph_render import (
    complexity_node_color,
    complexity_node_label,
    module_label,
    rule_cluster_label,
    rule_graph_label,
    rule_node_color,
    strings_summary_label,
)


def test_dependency_graph_render_remaining_paths() -> None:
    assert rule_node_color({"string_count": 0}) == "lightcoral"
    assert rule_node_color({"string_count": 2}) == "lightgreen"

    assert (
        rule_cluster_label("r", {"modifiers": ["private"], "tags": ["tag1", "tag2"]})
        == "r\\n[private]\\n:tag1, tag2"
    )
    assert rule_graph_label("r", {"tags": ["x"], "string_count": 3}) == "r\\nTags: x\\nStrings: 3"
    assert module_label("pe") == "Module: pe"
    assert strings_summary_label(5) == "Strings\\n(5)"

    assert complexity_node_color(1) == "lightgreen"
    assert complexity_node_color(8) == "yellow"
    assert complexity_node_color(11) == "lightcoral"
    assert complexity_node_label("r", 11, {"string_count": 2}) == "r\\nComplexity: 11\\nStrings: 2"
