"""Helpers for pipeline-oriented YAML roundtrip serialization."""

from __future__ import annotations

from datetime import datetime
from pathlib import Path
from typing import Any

import yaml


def build_pipeline_metadata(
    include_pipeline_metadata: bool, pipeline_info: dict[str, Any] | None
) -> dict[str, Any] | None:
    if not include_pipeline_metadata:
        return None
    metadata = {
        "generated_at": datetime.now().isoformat(),
        "format": "yaraast-pipeline-yaml",
        "version": "1.0.0",
        "features": {
            "rule_validation": True,
            "dependency_tracking": True,
            "change_detection": True,
            "automated_testing": True,
        },
    }
    if pipeline_info:
        metadata.update(pipeline_info)
    return metadata


def build_pipeline_statistics(ast) -> dict[str, Any]:
    return {
        "total_rules": len(ast.rules),
        "imports": [imp.module for imp in ast.imports],
        "rule_tags": collect_all_tags(ast),
        "string_patterns": count_string_types(ast),
    }


def build_rules_manifest(ast) -> dict[str, Any]:
    manifest = {
        "manifest_version": "1.0",
        "generated_at": datetime.now().isoformat(),
        "rules": [],
    }
    for rule in ast.rules:
        manifest["rules"].append(
            {
                "name": rule.name,
                "modifiers": rule.modifiers,
                "tags": [tag.name for tag in rule.tags],
                "meta": dict(rule.meta) if isinstance(rule.meta, dict) else {},
                "string_count": len(rule.strings),
                "has_condition": rule.condition is not None,
            }
        )
    manifest["summary"] = {
        "total_rules": len(ast.rules),
        "private_rules": len(
            [r for r in ast.rules if any(str(m) == "private" for m in r.modifiers)]
        ),
        "global_rules": len([r for r in ast.rules if any(str(m) == "global" for m in r.modifiers)]),
        "tagged_rules": len([r for r in ast.rules if r.tags]),
        "imports": [imp.module for imp in ast.imports],
        "includes": [inc.path for inc in ast.includes],
    }
    return manifest


def collect_all_tags(ast) -> list[str]:
    tags = set()
    for rule in ast.rules:
        for tag in rule.tags:
            tags.add(tag.name)
    return sorted(tags)


def count_string_types(ast) -> dict[str, int]:
    counts = {"plain": 0, "hex": 0, "regex": 0}
    for rule in ast.rules:
        for string_def in rule.strings:
            if hasattr(string_def, "value"):
                counts["plain"] += 1
            elif hasattr(string_def, "tokens"):
                counts["hex"] += 1
            elif hasattr(string_def, "regex"):
                counts["regex"] += 1
    return counts


def dump_pipeline_yaml(
    data: Any, output_path: str | Path | None, *, width: int = 100, explicit_markers: bool = False
) -> str:
    yaml_str = yaml.dump(
        data,
        default_flow_style=False,
        allow_unicode=True,
        sort_keys=False,
        indent=2,
        width=width,
        explicit_start=explicit_markers,
        explicit_end=explicit_markers,
    )
    if output_path:
        with Path(output_path).open("w", encoding="utf-8") as handle:
            handle.write(yaml_str)
    return yaml_str
