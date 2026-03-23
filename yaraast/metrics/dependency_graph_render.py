"""Render helpers for dependency graph generation."""

from __future__ import annotations


def _escape_dot(text: str) -> str:
    """Escape text for safe use in DOT graph labels."""
    return text.replace("\\", "\\\\").replace('"', '\\"').replace("<", "\\<").replace(">", "\\>")


def rule_node_color(rule_info: dict) -> str:
    """Choose rule node color based on string usage."""
    return "lightgreen" if rule_info.get("string_count", 0) > 0 else "lightcoral"


def rule_cluster_label(rule_name: str, rule_info: dict) -> str:
    """Build a label for rule nodes in the full graph."""
    label = _escape_dot(rule_name)
    modifiers = rule_info.get("modifiers")
    if modifiers:
        label += f"\\n[{', '.join(_escape_dot(str(m)) for m in modifiers)}]"
    tags = rule_info.get("tags")
    if tags:
        label += f"\\n:{', '.join(_escape_dot(t) for t in tags)}"
    return label


def rule_graph_label(rule_name: str, rule_info: dict) -> str:
    """Build a label for rule nodes in the rule-only graph."""
    label = f"{_escape_dot(rule_name)}\\n"
    tags = rule_info.get("tags")
    if tags:
        label += f"Tags: {', '.join(_escape_dot(t) for t in tags)}\\n"
    label += f"Strings: {rule_info.get('string_count', 0)}"
    return label


def module_label(module: str) -> str:
    """Build label for module nodes."""
    return f"Module: {_escape_dot(module)}"


def strings_summary_label(count: int) -> str:
    """Build label for strings summary nodes."""
    return f"Strings\\n({count})"


def complexity_node_color(complexity: int) -> str:
    """Choose node color based on complexity threshold."""
    if complexity <= 5:
        return "lightgreen"
    if complexity <= 10:
        return "yellow"
    return "lightcoral"


def complexity_node_label(rule_name: str, complexity: int, rule_info: dict) -> str:
    """Build label for complexity graph nodes."""
    return (
        f"{_escape_dot(rule_name)}\\nComplexity: {complexity}\\n"
        f"Strings: {rule_info.get('string_count', 0)}"
    )
