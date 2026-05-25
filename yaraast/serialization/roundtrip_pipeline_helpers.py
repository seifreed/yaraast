"""Helpers for pipeline-oriented YAML roundtrip serialization."""

from __future__ import annotations

from datetime import datetime
from pathlib import Path
from typing import Any

import yaml

from yaraast.ast.meta import Meta
from yaraast.ast.modifiers import MetaEntry, RuleModifier
from yaraast.ast.rules import Import, Include, Rule, Tag
from yaraast.ast.strings import StringDefinition
from yaraast.errors import SerializationError


def _expected_type_names(expected_type: type[Any] | tuple[type[Any], ...]) -> str:
    expected_types = expected_type if isinstance(expected_type, tuple) else (expected_type,)
    return " or ".join(item_type.__name__ for item_type in expected_types)


def _validated_node_collection(
    values: Any,
    context: str,
    expected_type: type[Any] | tuple[type[Any], ...],
) -> list[Any]:
    if not isinstance(values, list | tuple):
        msg = f"{context} must be a list of {_expected_type_names(expected_type)} nodes"
        raise SerializationError(msg)

    for value in values:
        if not isinstance(value, expected_type):
            msg = f"{context} item must be a {_expected_type_names(expected_type)} node"
            raise SerializationError(msg)
    return list(values)


def _validated_rule_modifiers(values: Any) -> list[Any]:
    if not isinstance(values, list | tuple):
        msg = "Rule modifiers must be a list of rule modifiers"
        raise SerializationError(msg)

    for value in values:
        if isinstance(value, (RuleModifier, str)):
            continue
        msg = "Rule modifiers item must be a string or RuleModifier"
        raise SerializationError(msg)
    return list(values)


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
    imports = _validated_node_collection(ast.imports, "YaraFile imports", Import)
    rules = _validated_node_collection(ast.rules, "YaraFile rules", Rule)
    return {
        "total_rules": len(rules),
        "imports": [imp.module for imp in imports],
        "rule_tags": collect_all_tags(ast),
        "string_patterns": count_string_types(ast),
    }


def build_rules_manifest(ast) -> dict[str, Any]:
    imports = _validated_node_collection(ast.imports, "YaraFile imports", Import)
    includes = _validated_node_collection(ast.includes, "YaraFile includes", Include)
    rules = _validated_node_collection(ast.rules, "YaraFile rules", Rule)
    manifest = {
        "manifest_version": "1.0",
        "generated_at": datetime.now().isoformat(),
        "rules": [],
    }
    private_rules = 0
    global_rules = 0
    tagged_rules = 0

    for rule in rules:
        modifiers = _validated_rule_modifiers(rule.modifiers)
        tags = _validated_node_collection(rule.tags, "Rule tags", Tag)
        meta = _validated_node_collection(rule.meta, "Rule meta", (Meta, MetaEntry))
        strings = _validated_node_collection(rule.strings, "Rule strings", StringDefinition)
        if any(str(modifier) == "private" for modifier in modifiers):
            private_rules += 1
        if any(str(modifier) == "global" for modifier in modifiers):
            global_rules += 1
        if tags:
            tagged_rules += 1

        rule_manifest = {
            "name": rule.name,
            "modifiers": [str(modifier) for modifier in modifiers],
            "tags": [tag.name for tag in tags],
            "meta": _build_rule_meta(meta),
            "string_count": len(strings),
            "has_condition": rule.condition is not None,
        }
        meta_scopes = _build_rule_meta_scopes(meta)
        if meta_scopes:
            rule_manifest["meta_scopes"] = meta_scopes
        manifest["rules"].append(rule_manifest)
    manifest["summary"] = {
        "total_rules": len(rules),
        "private_rules": private_rules,
        "global_rules": global_rules,
        "tagged_rules": tagged_rules,
        "imports": [imp.module for imp in imports],
        "includes": [inc.path for inc in includes],
    }
    return manifest


def _build_rule_meta(meta) -> dict[str, Any]:
    if not meta:
        return {}
    return {entry.key: entry.value for entry in meta}


def _build_rule_meta_scopes(meta) -> dict[str, str]:
    scopes = {}
    for entry in meta:
        scope = getattr(entry, "scope", None)
        if scope is not None:
            scopes[entry.key] = getattr(scope, "value", str(scope))
    return scopes


def collect_all_tags(ast) -> list[str]:
    rules = _validated_node_collection(ast.rules, "YaraFile rules", Rule)
    tags = set()
    for rule in rules:
        rule_tags = _validated_node_collection(rule.tags, "Rule tags", Tag)
        for tag in rule_tags:
            tags.add(tag.name)
    return sorted(tags)


def count_string_types(ast) -> dict[str, int]:
    rules = _validated_node_collection(ast.rules, "YaraFile rules", Rule)
    counts = {"plain": 0, "hex": 0, "regex": 0}
    for rule in rules:
        strings = _validated_node_collection(rule.strings, "Rule strings", StringDefinition)
        for string_def in strings:
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
    yaml_str = yaml.safe_dump(
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
