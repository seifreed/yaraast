"""Helpers for dependency graph generation."""

from __future__ import annotations

from os import PathLike, fspath
from pathlib import Path
from typing import Any

from yaraast.metrics.graphviz_errors import is_graphviz_error


def reset_graph_state(generator) -> None:
    generator.dependencies.clear()
    generator.imports.clear()
    generator.includes.clear()
    generator.rules.clear()
    generator.string_references.clear()
    generator.module_references.clear()
    generator._current_rule = None
    generator._current_rule_key = None
    generator._local_scopes.clear()
    generator._rule_names.clear()
    generator._rule_graph_keys.clear()
    generator._rule_graph_keys_by_name.clear()


def require_graph_format(format: object) -> str:
    """Validate a Graphviz output format name."""
    if not isinstance(format, str):
        msg = "graph format must be a string"
        raise TypeError(msg)
    if not format:
        msg = "graph format must not be empty"
        raise ValueError(msg)
    return format


def require_output_path(output_path: object, name: str = "output_path") -> Path:
    """Validate a metrics output file path."""
    if isinstance(output_path, bool) or not isinstance(output_path, str | PathLike):
        msg = f"{name} must be a file path"
        raise TypeError(msg)
    raw_path = fspath(output_path)
    if not isinstance(raw_path, str):
        msg = f"{name} must be a file path"
        raise TypeError(msg)
    if not raw_path:
        msg = f"{name} must not be empty"
        raise ValueError(msg)
    path = Path(raw_path)
    if path.exists() and path.is_dir():
        msg = f"{name} must not be a directory"
        raise ValueError(msg)
    return path


def render_graph(dot, output_path: str | PathLike[str] | None, format: str) -> str:
    format = require_graph_format(format)
    if output_path is not None:
        output_path_obj = require_output_path(output_path)
        if format == "dot":
            output_path_obj.write_text(dot.source, encoding="utf-8")
            return str(output_path_obj)

        output_file = str(output_path_obj.with_suffix(""))
        try:
            dot.render(output_file, format=format, cleanup=True)
        except Exception as exc:
            if not is_graphviz_error(exc):
                raise
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
