"""GraphViz helpers for dependency graph rendering."""

from __future__ import annotations

from collections.abc import Iterable

import graphviz


def create_graph(comment: str, rankdir: str, *, engine: str | None = None) -> graphviz.Digraph:
    """Create a graphviz digraph with standard attributes."""
    dot = graphviz.Digraph(comment=comment, engine=engine)
    dot.attr(rankdir=rankdir, bgcolor="white", fontname="Arial")
    return dot


def apply_rule_graph_style(dot: graphviz.Digraph) -> None:
    """Apply default styling for rule-only graphs."""
    _set_node_attrs(dot, shape="box", style="rounded,filled", fillcolor="lightblue")


def apply_module_graph_styles(dot: graphviz.Digraph) -> None:
    """Apply default styling for module graphs."""
    _set_node_attrs(dot, shape="box", style="rounded,filled", fillcolor="lightcyan")


def apply_rule_node_style(dot: graphviz.Digraph) -> None:
    """Apply default styling for rule nodes."""
    _set_node_attrs(dot, shape="ellipse", fillcolor="lightblue")


def set_cluster_style(cluster, label: str, fillcolor: str) -> None:
    """Set common cluster attributes."""
    cluster.attr(label=label, style="filled", fillcolor=fillcolor)


def set_node_style(cluster, shape: str, fillcolor: str) -> None:
    """Set node styling for a cluster."""
    _set_node_attrs(cluster, shape=shape, fillcolor=fillcolor)


def _set_node_attrs(target, *, shape: str, fillcolor: str, style: str | None = None) -> None:
    """Apply node attributes to a graphviz graph or subgraph."""
    attrs = {"shape": shape, "fillcolor": fillcolor}
    if style:
        attrs["style"] = style
    target.attr("node", **attrs)


def add_import_cluster(dot: graphviz.Digraph, imports: Iterable[str]) -> None:
    """Add import nodes cluster."""
    imports = list(imports)
    if not imports:
        return
    with _cluster(dot, "cluster_imports", "Imports", "lightcyan", "box", "lightblue") as cluster:
        add_prefixed_nodes(cluster, "import_", imports, quote_labels=True)


def add_include_cluster(dot: graphviz.Digraph, includes: Iterable[str]) -> None:
    """Add include nodes cluster."""
    includes = list(includes)
    if not includes:
        return
    with _cluster(dot, "cluster_includes", "Includes", "lightyellow", "note", "yellow") as cluster:
        add_prefixed_nodes(cluster, "include_", includes, quote_labels=True)


def add_rules_cluster(
    dot: graphviz.Digraph,
    rules: dict[str, dict],
    label_fn,
    color_fn,
) -> None:
    """Add rule nodes cluster."""
    if not rules:
        return
    with _cluster(dot, "cluster_rules", "Rules", "lightgray", "ellipse", "white") as cluster:
        add_cluster_nodes(cluster, rules, label_fn, color_fn)


def add_rule_graph_nodes(
    dot: graphviz.Digraph,
    rules: dict[str, dict],
    label_fn,
    color_fn,
) -> None:
    """Add rule nodes for rule-only graphs."""
    for rule_name, rule_info in rules.items():
        add_node(dot, rule_name, label_fn(rule_name, rule_info), fillcolor=color_fn(rule_info))


def add_rule_string_edges(
    dot: graphviz.Digraph,
    string_references: dict[str, set[str]],
) -> None:
    """Add edges to string nodes for rule-only graphs."""
    for rule_name, strings in string_references.items():
        for string_id in strings:
            add_node(dot, string_id, string_id, shape="ellipse", fillcolor="lightyellow")
            add_edge(dot, rule_name, string_id, label="uses")


def add_string_reference_edges(
    dot: graphviz.Digraph,
    string_references: dict[str, set[str]],
) -> None:
    """Add conceptual string reference edges for full graphs."""
    for rule_name, strings in string_references.items():
        if strings:
            strings_node = f"{rule_name}_strings"
            add_node(
                dot,
                strings_node,
                strings_summary_label(len(strings)),
                shape="box",
                style="filled",
                fillcolor="lightyellow",
            )
            add_edge(dot, rule_name, strings_node, label="defines", color="green")


def add_module_nodes(dot: graphviz.Digraph, imports: Iterable[str]) -> None:
    """Add module nodes."""
    apply_module_graph_styles(dot)
    for module in imports:
        add_node(dot, f"mod_{module}", module_label(module), fillcolor="lightcyan")


def add_module_rule_nodes(dot: graphviz.Digraph, rules: Iterable[str]) -> None:
    """Add rule nodes for module graphs."""
    apply_rule_node_style(dot)
    for rule_name in rules:
        add_node(dot, rule_name, rule_name)


def add_module_edges(
    dot: graphviz.Digraph,
    module_references: dict[str, set[str]],
    imports: set[str],
) -> None:
    """Add module dependency edges."""
    for rule_name, modules in module_references.items():
        for module in modules:
            if module in imports:
                add_edge(dot, f"mod_{module}", rule_name, label="imported by")


def add_edge(
    dot: graphviz.Digraph,
    from_node: str,
    to_node: str,
    *,
    label: str | None = None,
    style: str | None = None,
    color: str | None = None,
) -> None:
    """Add a graph edge with optional styling."""
    attrs: dict[str, str] = {}
    if label:
        attrs["label"] = label
    if style:
        attrs["style"] = style
    if color:
        attrs["color"] = color
    dot.edge(from_node, to_node, **attrs)


def add_node(
    target,
    node_id: str,
    label: str,
    *,
    shape: str | None = None,
    fillcolor: str | None = None,
    style: str | None = None,
) -> None:
    """Add a node with optional styling."""
    attrs: dict[str, str] = {}
    if shape:
        attrs["shape"] = shape
    if fillcolor:
        attrs["fillcolor"] = fillcolor
    if style:
        attrs["style"] = style
    target.node(node_id, label, **attrs)


def add_complexity_nodes(
    dot: graphviz.Digraph,
    rules: dict[str, dict],
    complexity_metrics: dict[str, int],
    label_fn,
    color_fn,
) -> None:
    """Add nodes for complexity graph."""
    for rule_name, rule_info in rules.items():
        complexity = complexity_metrics.get(rule_name, 1)
        add_node(
            dot,
            rule_name,
            label_fn(rule_name, complexity, rule_info),
            style="filled",
            fillcolor=color_fn(complexity),
            shape="box",
        )


def add_complexity_legend(dot: graphviz.Digraph) -> None:
    """Add legend for complexity graph."""
    with _legend_cluster(dot, "Complexity Legend") as legend:
        add_node(legend, "low", "Low (≤5)", fillcolor="lightgreen", shape="box")
        add_node(legend, "med", "Medium (6-10)", fillcolor="yellow", shape="box")
        add_node(legend, "high", "High (>10)", fillcolor="lightcoral", shape="box")


from contextlib import contextmanager

from yaraast.metrics.dependency_graph_render import module_label, strings_summary_label


@contextmanager
def _legend_cluster(dot: graphviz.Digraph, label: str):
    """Context manager for a legend cluster with default styling."""
    with dot.subgraph(name="cluster_legend") as legend:
        set_cluster_style(legend, label, "white")
        yield legend


@contextmanager
def _cluster(
    dot: graphviz.Digraph,
    name: str,
    label: str,
    fillcolor: str,
    node_shape: str,
    node_fill: str,
):
    """Context manager for a styled cluster."""
    with dot.subgraph(name=name) as cluster:
        set_cluster_style(cluster, label, fillcolor)
        set_node_style(cluster, node_shape, node_fill)
        yield cluster


def add_cluster_nodes(cluster, rules: dict[str, dict], label_fn, color_fn) -> None:
    """Add labeled nodes with fillcolor to a cluster."""
    for rule_name, rule_info in rules.items():
        cluster.node(
            rule_name,
            label_fn(rule_name, rule_info),
            fillcolor=color_fn(rule_info),
        )


def add_prefixed_nodes(
    cluster,
    prefix: str,
    items: Iterable[str],
    *,
    quote_labels: bool = False,
) -> None:
    """Add nodes with a fixed prefix and optional quoted labels."""
    for item in items:
        label = _quote_label(item) if quote_labels else item
        cluster.node(f"{prefix}{item}", label)


def _quote_label(label: str) -> str:
    """Quote a label for display."""
    return f'"{label}"'
