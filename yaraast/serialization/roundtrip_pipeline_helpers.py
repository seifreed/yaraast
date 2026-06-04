"""Helpers for pipeline-oriented YAML roundtrip serialization."""

from __future__ import annotations

from datetime import datetime
import math
from pathlib import Path
from typing import Any

import yaml

from yaraast.ast.meta import Meta
from yaraast.ast.modifiers import MetaEntry, RuleModifier
from yaraast.ast.rules import Import, Include, Rule, Tag
from yaraast.ast.strings import StringDefinition
from yaraast.errors import SerializationError
from yaraast.serialization._serialization_primitives import _expected_type_names
from yaraast.serialization.meta_scopes import serialize_meta_scope
from yaraast.serialization.serializer_helpers import (
    require_bool_option,
    require_input_path,
    require_positive_int_option,
)


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


def _required_string(value: Any, context: str) -> str:
    if isinstance(value, str):
        return value
    msg = f"{context} must be a string"
    raise SerializationError(msg)


def _required_nonempty_string(value: Any, context: str) -> str:
    text = _required_string(value, context)
    if not text.strip():
        msg = f"{context} must not be empty"
        raise SerializationError(msg)
    return text


def _nullable_nonempty_string(value: Any, context: str) -> str | None:
    if value is None:
        return None
    return _required_nonempty_string(value, context)


def _serialized_meta_value(value: Any) -> str | int | bool:
    if isinstance(value, str | bool):
        return value
    if isinstance(value, int):
        return value
    msg = "Meta value must be a string, integer, or boolean"
    raise SerializationError(msg)


def _serialized_meta_entry_value(value: Any) -> str | int | bool | float:
    if isinstance(value, str | bool):
        return value
    if isinstance(value, int):
        return value
    if isinstance(value, float) and math.isfinite(value):
        return value
    msg = "Meta value must be a string, integer, boolean, or finite float"
    raise SerializationError(msg)


def _validated_rule_modifiers(values: Any) -> list[str]:
    if not isinstance(values, list | tuple):
        msg = "Rule modifiers must be a list of rule modifiers"
        raise SerializationError(msg)

    serialized = []
    for value in values:
        if isinstance(value, RuleModifier):
            serialized.append(str(value))
            continue
        if isinstance(value, str):
            serialized.append(value)
            continue
        msg = "Rule modifiers item must be a string or RuleModifier"
        raise SerializationError(msg)
    if any(not modifier.strip() for modifier in serialized):
        msg = "Rule modifiers must contain non-empty strings"
        raise SerializationError(msg)
    return serialized


def _validated_import_modules(imports: list[Any]) -> list[str]:
    modules = []
    for imp in imports:
        modules.append(_required_nonempty_string(imp.module, "Import module"))
        _nullable_nonempty_string(getattr(imp, "alias", None), "Import alias")
    return modules


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


def build_pipeline_statistics(ast: Any) -> dict[str, Any]:
    imports = _validated_node_collection(ast.imports, "YaraFile imports", Import)
    rules = _validated_node_collection(ast.rules, "YaraFile rules", Rule)
    for rule in rules:
        _required_nonempty_string(rule.name, "Rule name")
    return {
        "total_rules": len(rules),
        "imports": _validated_import_modules(imports),
        "rule_tags": collect_all_tags(ast),
        "string_patterns": count_string_types(ast),
    }


def build_rules_manifest(ast: Any) -> dict[str, Any]:
    imports = _validated_node_collection(ast.imports, "YaraFile imports", Import)
    includes = _validated_node_collection(ast.includes, "YaraFile includes", Include)
    rules = _validated_node_collection(ast.rules, "YaraFile rules", Rule)
    manifest: dict[str, Any] = {
        "manifest_version": "2.0",
        "generated_at": datetime.now().isoformat(),
        "rules": [],
    }
    private_rules = 0
    global_rules = 0
    tagged_rules = 0
    import_modules = _validated_import_modules(imports)
    include_paths = [_required_nonempty_string(inc.path, "Include path") for inc in includes]

    for rule in rules:
        rule_name = _required_nonempty_string(rule.name, "Rule name")
        modifiers = _validated_rule_modifiers(rule.modifiers)
        tags = _validated_node_collection(rule.tags, "Rule tags", Tag)
        meta = _validated_node_collection(rule.meta, "Rule meta", (Meta, MetaEntry))
        strings = _validated_node_collection(rule.strings, "Rule strings", StringDefinition)
        tag_names = [_required_nonempty_string(tag.name, "Tag name") for tag in tags]
        _validate_string_identifiers(strings)
        if any(modifier == "private" for modifier in modifiers):
            private_rules += 1
        if any(modifier == "global" for modifier in modifiers):
            global_rules += 1
        if tags:
            tagged_rules += 1

        rule_manifest = {
            "name": rule_name,
            "modifiers": modifiers,
            "tags": tag_names,
            "meta": _build_rule_meta(meta),
            "string_count": len(strings),
            "has_condition": rule.condition is not None,
        }
        manifest["rules"].append(rule_manifest)
    manifest["summary"] = {
        "total_rules": len(rules),
        "private_rules": private_rules,
        "global_rules": global_rules,
        "tagged_rules": tagged_rules,
        "imports": import_modules,
        "includes": include_paths,
    }
    return manifest


def _build_rule_meta(meta: Any) -> list[dict[str, Any]]:
    if not meta:
        return []

    entries = []
    for entry in meta:
        scope = getattr(entry, "scope", None)
        value = (
            _serialized_meta_entry_value(entry.value)
            if isinstance(entry, MetaEntry)
            else _serialized_meta_value(entry.value)
        )
        entry_data = {
            "key": _required_nonempty_string(entry.key, "Meta key"),
            "value": value,
        }
        if scope is not None:
            entry_data["scope"] = serialize_meta_scope(scope)
        entries.append(entry_data)
    return entries


def collect_all_tags(ast: Any) -> list[str]:
    rules = _validated_node_collection(ast.rules, "YaraFile rules", Rule)
    tags = set()
    for rule in rules:
        rule_tags = _validated_node_collection(rule.tags, "Rule tags", Tag)
        for tag in rule_tags:
            tags.add(_required_nonempty_string(tag.name, "Tag name"))
    return sorted(tags)


def _validate_string_identifiers(strings: list[Any]) -> None:
    for string_def in strings:
        context = f"{type(string_def).__name__} identifier"
        _required_nonempty_string(string_def.identifier, context)


def count_string_types(ast: Any) -> dict[str, int]:
    rules = _validated_node_collection(ast.rules, "YaraFile rules", Rule)
    counts = {"plain": 0, "hex": 0, "regex": 0}
    for rule in rules:
        _required_nonempty_string(rule.name, "Rule name")
        strings = _validated_node_collection(rule.strings, "Rule strings", StringDefinition)
        _validate_string_identifiers(strings)
        for string_def in strings:
            if hasattr(string_def, "value"):
                counts["plain"] += 1
            elif hasattr(string_def, "tokens"):
                counts["hex"] += 1
            elif hasattr(string_def, "regex"):
                counts["regex"] += 1
    return counts


def dump_pipeline_yaml(
    data: Any,
    output_path: str | Path | None,
    *,
    width: object = 100,
    explicit_markers: object = False,
) -> str:
    yaml_width = require_positive_int_option(width, "width")
    yaml_explicit_markers = require_bool_option(explicit_markers, "explicit_markers")
    yaml_str = yaml.safe_dump(
        data,
        default_flow_style=False,
        allow_unicode=True,
        sort_keys=False,
        indent=2,
        width=yaml_width,
        explicit_start=yaml_explicit_markers,
        explicit_end=yaml_explicit_markers,
    )
    if output_path is not None:
        with require_input_path(output_path, "output_path").open("w", encoding="utf-8") as handle:
            handle.write(yaml_str)
    return yaml_str
