"""Helpers for YAML serializer output shaping."""

from __future__ import annotations

from pathlib import Path
from typing import Any

import yaml

from yaraast.config import YAML_DEFAULT_WIDTH
from yaraast.serialization.serializer_helpers import (
    require_bool_option,
    require_positive_int_option,
    write_text,
)


def dump_yaml(data: Any, *, flow_style: object, width: object = YAML_DEFAULT_WIDTH) -> str:
    """Render YAML with consistent formatting defaults."""
    flow_style = require_bool_option(flow_style, "flow_style")
    width = require_positive_int_option(width, "width")
    return yaml.safe_dump(
        data,
        default_flow_style=flow_style,
        allow_unicode=True,
        sort_keys=False,
        indent=2,
        width=width,
    )


def serialize_yaml(
    data: Any,
    output_path: str | Path | None,
    *,
    flow_style: object,
    width: object = YAML_DEFAULT_WIDTH,
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
