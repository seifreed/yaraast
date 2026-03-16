"""Helpers for YAML serializer output shaping."""

from __future__ import annotations

from pathlib import Path
from typing import Any

import yaml

from yaraast.serialization.serializer_helpers import write_text


def dump_yaml(data: Any, *, flow_style: bool, width: int = 120) -> str:
    """Render YAML with consistent formatting defaults."""
    return yaml.dump(
        data,
        default_flow_style=flow_style,
        allow_unicode=True,
        sort_keys=False,
        indent=2,
        width=width,
    )


def serialize_yaml(
    data: Any, output_path: str | Path | None, *, flow_style: bool, width: int = 120
) -> str:
    """Dump YAML and optionally write it to disk."""
    yaml_str = dump_yaml(data, flow_style=flow_style, width=width)
    if output_path:
        write_text(output_path, yaml_str)
    return yaml_str


def enrich_yaml_metadata(
    result: dict[str, Any], *, include_metadata: bool, flow_style: bool
) -> dict[str, Any]:
    """Add YAML-specific metadata while preserving JsonSerializer metadata layout."""
    if include_metadata:
        result["metadata"]["format"] = "yaraast-yaml"
        result["metadata"]["serializer"] = "YamlSerializer"
        result["metadata"]["yaml_features"] = {
            "flow_style": flow_style,
            "human_readable": True,
            "preserves_order": True,
        }
    return result
