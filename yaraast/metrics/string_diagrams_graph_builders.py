"""Graph-family builders for string diagram generation."""

from __future__ import annotations

from collections import defaultdict
from pathlib import Path

import graphviz

from yaraast.metrics.string_diagrams_graphviz import (
    create_complexity_graph,
    create_hex_graph,
    create_pattern_flow_graph,
    create_similarity_graph,
)


def render_or_write_dot(dot: graphviz.Digraph, output_path: str, format: str) -> str:
    """Render graph output, with DOT/text fallback when executables are unavailable."""
    output_path_obj = Path(output_path)
    if format == "dot":
        output_path_obj.write_text(dot.source, encoding="utf-8")
        return str(output_path_obj)

    output_file = str(output_path_obj.with_suffix(""))
    try:
        dot.render(output_file, format=format, cleanup=True)
        return f"{output_file}.{format}"
    except Exception:
        fallback_path = f"{output_file}.{format}"
        Path(fallback_path).write_text(dot.source, encoding="utf-8")
        return fallback_path


def generate_pattern_flow_diagram(
    generator, ast, output_path: str | None = None, format: str = "svg"
) -> str:
    """Generate string pattern flow diagram."""
    generator._analyze_patterns(ast)
    dot = create_pattern_flow_graph()

    with dot.subgraph(name="cluster_plain") as plain_cluster:
        plain_cluster.attr(
            label="Plain String Patterns", style="filled", fillcolor="lightblue", color="blue"
        )
        plain_cluster.attr("node", shape="box", style="rounded,filled", fillcolor="lightcyan")
        for pattern_id, pattern_info in generator.string_patterns.items():
            if pattern_info["type"] == "plain":
                plain_cluster.node(pattern_id, generator._create_pattern_label(pattern_info))

    with dot.subgraph(name="cluster_hex") as hex_cluster:
        hex_cluster.attr(
            label="Hex Patterns", style="filled", fillcolor="lightyellow", color="orange"
        )
        hex_cluster.attr("node", shape="hexagon", style="filled", fillcolor="yellow")
        for pattern_id, pattern_info in generator.string_patterns.items():
            if pattern_info["type"] == "hex":
                hex_cluster.node(pattern_id, generator._create_hex_pattern_label(pattern_info))

    with dot.subgraph(name="cluster_regex") as regex_cluster:
        regex_cluster.attr(
            label="Regex Patterns", style="filled", fillcolor="lightgreen", color="green"
        )
        regex_cluster.attr("node", shape="ellipse", style="filled", fillcolor="lightgreen")
        for pattern_id, pattern_info in generator.string_patterns.items():
            if pattern_info["type"] == "regex":
                regex_cluster.node(pattern_id, generator._create_regex_pattern_label(pattern_info))

    add_pattern_relationships(generator, dot)
    if output_path:
        return render_or_write_dot(dot, output_path, format)
    return dot.source


def generate_pattern_complexity_diagram(
    generator, ast, output_path: str | None = None, format: str = "svg"
) -> str:
    """Generate pattern complexity visualization."""
    generator._analyze_patterns(ast)
    dot = create_complexity_graph()

    for pattern_id, pattern_info in generator.string_patterns.items():
        complexity = generator._calculate_pattern_complexity(pattern_info)
        color = "lightgreen" if complexity <= 3 else "yellow" if complexity <= 6 else "lightcoral"
        size = min(2.0, 0.5 + (pattern_info.get("length", 0) / 50))
        label = f"{pattern_info['identifier']}\\nComplexity: {complexity}"
        if pattern_info["type"] == "hex":
            label += f"\\nTokens: {pattern_info.get('tokens', 0)}"
        dot.node(
            pattern_id,
            label,
            style="filled",
            fillcolor=color,
            width=str(size),
            height=str(size),
            shape=generator._get_pattern_shape(pattern_info["type"]),
        )

    with dot.subgraph(name="cluster_legend") as legend:
        legend.attr(label="Complexity Legend", style="filled", fillcolor="white")
        legend.node("low_c", "Low (≤3)", fillcolor="lightgreen", shape="circle")
        legend.node("med_c", "Medium (4-6)", fillcolor="yellow", shape="circle")
        legend.node("high_c", "High (>6)", fillcolor="lightcoral", shape="circle")

    if output_path:
        return render_or_write_dot(dot, output_path, format)
    return f"// Layout engine: neato\n{dot.source}"


def generate_pattern_similarity_diagram(
    generator, ast, output_path: str | None = None, format: str = "svg"
) -> str:
    """Generate pattern similarity clustering diagram."""
    generator._analyze_patterns(ast)
    dot = create_similarity_graph()
    similarity_groups = generator._find_similar_patterns()
    colors = [
        "lightblue",
        "lightgreen",
        "lightyellow",
        "lightcoral",
        "lightpink",
        "lightgray",
        "lightcyan",
        "wheat",
    ]

    for i, (group_type, patterns) in enumerate(similarity_groups.items()):
        color = colors[i % len(colors)]
        with dot.subgraph(name=f"cluster_{i}") as cluster:
            cluster.attr(
                label=f"{group_type} Patterns", style="filled", fillcolor=color, alpha="0.5"
            )
            for pattern_id in patterns:
                pattern_info = generator.string_patterns[pattern_id]
                cluster.node(
                    pattern_id,
                    generator._create_short_label(pattern_info),
                    style="filled",
                    fillcolor="white",
                )

            pattern_list = list(patterns)
            for j in range(len(pattern_list)):
                for k in range(j + 1, len(pattern_list)):
                    similarity = generator._calculate_similarity(
                        generator.string_patterns[pattern_list[j]],
                        generator.string_patterns[pattern_list[k]],
                    )
                    if similarity > 0.5:
                        dot.edge(
                            pattern_list[j],
                            pattern_list[k],
                            label=f"{similarity:.2f}",
                            style="dashed",
                            color="gray",
                        )

    if output_path:
        return render_or_write_dot(dot, output_path, format)
    return f"// Layout engine: fdp\n{dot.source}"


def generate_hex_pattern_diagram(
    generator, ast, output_path: str | None = None, format: str = "svg"
) -> str:
    """Generate detailed hex pattern analysis diagram."""
    generator._analyze_patterns(ast)
    dot = create_hex_graph()
    hex_patterns = {
        pid: info for pid, info in generator.string_patterns.items() if info["type"] == "hex"
    }

    if not hex_patterns:
        dot.node(
            "no_hex", "No Hex Patterns Found", shape="box", style="filled", fillcolor="lightgray"
        )
        if output_path:
            return render_or_write_dot(dot, output_path, format)
        return dot.source

    for pattern_id, pattern_info in hex_patterns.items():
        tokens = pattern_info.get("token_analysis", {})
        main_label = f"{pattern_info['identifier']}\\nRule: {pattern_info['rule']}"
        dot.node(pattern_id, main_label, shape="box", style="filled", fillcolor="lightblue")

        if tokens:
            token_id = f"{pattern_id}_tokens"
            dot.node(
                token_id,
                generator._create_hex_token_label(tokens),
                shape="record",
                style="filled",
                fillcolor="lightyellow",
            )
            dot.edge(pattern_id, token_id, label="tokens")

            complexity_id = f"{pattern_id}_complexity"
            dot.node(
                complexity_id,
                generator._create_hex_complexity_label(pattern_info, tokens),
                shape="note",
                style="filled",
                fillcolor="lightgreen",
            )
            dot.edge(pattern_id, complexity_id, label="metrics")

    if output_path:
        return render_or_write_dot(dot, output_path, format)
    return dot.source


def add_pattern_relationships(generator, dot: graphviz.Digraph) -> None:
    """Add relationships between patterns."""
    rule_patterns = defaultdict(list)
    for pattern_id, pattern_info in generator.string_patterns.items():
        rule_patterns[pattern_info["rule"]].append(pattern_id)

    for rule_name, patterns in rule_patterns.items():
        if len(patterns) > 1:
            rule_id = f"rule_{rule_name}"
            dot.node(
                rule_id,
                f"Rule: {rule_name}",
                shape="diamond",
                style="filled",
                fillcolor="lightgray",
            )
            for pattern_id in patterns:
                dot.edge(rule_id, pattern_id, style="dotted", color="gray")
