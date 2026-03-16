"""Helpers for dependency graph generation."""

from __future__ import annotations

from pathlib import Path
from typing import Any


def reset_graph_state(generator) -> None:
    generator.dependencies.clear()
    generator.imports.clear()
    generator.includes.clear()
    generator.rules.clear()
    generator.string_references.clear()
    generator.module_references.clear()


def render_graph(dot, output_path: str | None, format: str) -> str:
    if output_path:
        output_path_obj = Path(output_path)
        if format == "dot":
            output_path_obj.write_text(dot.source, encoding="utf-8")
            return str(output_path_obj)

        output_file = str(output_path_obj.with_suffix(""))
        try:
            dot.render(output_file, format=format, cleanup=True)
        except Exception:
            # Fallback for environments without Graphviz executables.
            fallback_path = f"{output_file}.{format}"
            Path(fallback_path).write_text(dot.source, encoding="utf-8")
            return fallback_path
        return f"{output_file}.{format}"
    return dot.source


def rule_info(rule) -> dict[str, Any]:
    return {
        "modifiers": rule.modifiers,
        "tags": [tag.name for tag in rule.tags],
        "string_count": len(rule.strings),
        "has_meta": bool(rule.meta),
        "has_condition": rule.condition is not None,
    }
