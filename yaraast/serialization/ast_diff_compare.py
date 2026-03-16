"""Comparison helpers for AST diffing."""

from __future__ import annotations

from typing import Any

from yaraast.serialization.ast_diff_condition import condition_hashes, emit_condition_diff
from yaraast.serialization.ast_diff_meta import emit_meta_diff, meta_payloads
from yaraast.serialization.ast_diff_modifiers import emit_modifiers_diff, modifier_payloads
from yaraast.serialization.ast_diff_strings import (
    emit_string_added,
    emit_string_modified,
    emit_string_removed,
    string_maps,
)
from yaraast.serialization.ast_diff_tags import emit_tags_diff, tag_payloads


def compare_imports(old_imports, new_imports, result, diff_node, diff_type) -> None:
    """Compare import lists."""
    old_modules = {imp.module: imp for imp in old_imports}
    new_modules = {imp.module: imp for imp in new_imports}

    for module in new_modules:
        if module not in old_modules:
            result.differences.append(
                diff_node(
                    path=f"/imports/{module}",
                    diff_type=diff_type.ADDED,
                    new_value=module,
                    node_type="Import",
                ),
            )

    for module in old_modules:
        if module not in new_modules:
            result.differences.append(
                diff_node(
                    path=f"/imports/{module}",
                    diff_type=diff_type.REMOVED,
                    old_value=module,
                    node_type="Import",
                ),
            )

    for module in old_modules:
        if module in new_modules:
            old_alias = getattr(old_modules[module], "alias", None)
            new_alias = getattr(new_modules[module], "alias", None)
            if old_alias != new_alias:
                result.differences.append(
                    diff_node(
                        path=f"/imports/{module}/alias",
                        diff_type=diff_type.MODIFIED,
                        old_value=old_alias,
                        new_value=new_alias,
                        node_type="Import",
                    ),
                )


def compare_includes(old_includes, new_includes, result, diff_node, diff_type) -> None:
    """Compare include lists."""
    old_paths = {inc.path for inc in old_includes}
    new_paths = {inc.path for inc in new_includes}

    for path in new_paths - old_paths:
        result.differences.append(
            diff_node(
                path=f"/includes/{path}",
                diff_type=diff_type.ADDED,
                new_value=path,
                node_type="Include",
            ),
        )

    for path in old_paths - new_paths:
        result.differences.append(
            diff_node(
                path=f"/includes/{path}",
                diff_type=diff_type.REMOVED,
                old_value=path,
                node_type="Include",
            ),
        )


def compare_rules(old_rules, new_rules, result, hasher, diff_node, diff_type) -> None:
    """Compare rule lists."""
    old_rule_map = {rule.name: rule for rule in old_rules}
    new_rule_map = {rule.name: rule for rule in new_rules}

    for name in new_rule_map:
        if name not in old_rule_map:
            result.differences.append(
                diff_node(
                    path=f"/rules/{name}",
                    diff_type=diff_type.ADDED,
                    new_value=name,
                    node_type="Rule",
                    details={
                        "rule_summary": get_rule_summary(new_rule_map[name]),
                    },
                ),
            )

    for name in old_rule_map:
        if name not in new_rule_map:
            result.differences.append(
                diff_node(
                    path=f"/rules/{name}",
                    diff_type=diff_type.REMOVED,
                    old_value=name,
                    node_type="Rule",
                    details={
                        "rule_summary": get_rule_summary(old_rule_map[name]),
                    },
                ),
            )

    for name in old_rule_map:
        if name in new_rule_map:
            compare_rule_content(
                old_rule_map[name],
                new_rule_map[name],
                f"/rules/{name}",
                result,
                hasher,
                diff_node,
                diff_type,
            )


def compare_rule_content(
    old_rule,
    new_rule,
    base_path: str,
    result,
    hasher,
    diff_node,
    diff_type,
) -> None:
    """Compare content of two rules."""
    compare_rule_modifiers(old_rule, new_rule, base_path, result, diff_node, diff_type)
    compare_rule_tags(old_rule, new_rule, base_path, result, diff_node, diff_type)

    compare_rule_meta(old_rule, new_rule, base_path, result, diff_node, diff_type)

    compare_rule_strings(
        old_rule.strings,
        new_rule.strings,
        f"{base_path}/strings",
        result,
        hasher,
        diff_node,
        diff_type,
    )

    compare_rule_condition(old_rule, new_rule, base_path, result, hasher, diff_node, diff_type)


def compare_rule_meta(old_rule, new_rule, base_path, result, diff_node, diff_type) -> None:
    """Compare rule meta fields."""
    old_meta, new_meta = meta_payloads(old_rule, new_rule)
    if old_meta != new_meta:
        emit_meta_diff(base_path, result, diff_node, diff_type, old_meta, new_meta)


def compare_rule_modifiers(old_rule, new_rule, base_path, result, diff_node, diff_type) -> None:
    """Compare rule modifiers."""
    old_mods, new_mods = modifier_payloads(old_rule, new_rule)
    if old_mods != new_mods:
        emit_modifiers_diff(base_path, result, diff_node, diff_type, old_mods, new_mods)


def compare_rule_tags(old_rule, new_rule, base_path, result, diff_node, diff_type) -> None:
    """Compare rule tags."""
    old_tags, new_tags = tag_payloads(old_rule, new_rule)
    if old_tags != new_tags:
        emit_tags_diff(base_path, result, diff_node, diff_type, old_tags, new_tags)


def compare_rule_condition(
    old_rule,
    new_rule,
    base_path: str,
    result,
    hasher,
    diff_node,
    diff_type,
) -> None:
    """Compare rule conditions."""
    old_condition_hash, new_condition_hash = condition_hashes(old_rule, new_rule, hasher)
    if old_condition_hash != new_condition_hash:
        emit_condition_diff(
            base_path,
            result,
            diff_node,
            diff_type,
            old_condition_hash,
            new_condition_hash,
        )


def compare_rule_strings(
    old_strings,
    new_strings,
    base_path: str,
    result,
    hasher,
    diff_node,
    diff_type,
) -> None:
    """Compare string definitions in rules."""
    old_string_map, new_string_map = string_maps(old_strings, new_strings)

    for identifier in new_string_map:
        if identifier not in old_string_map:
            emit_string_added(base_path, result, diff_node, diff_type, identifier)

    for identifier in old_string_map:
        if identifier not in new_string_map:
            emit_string_removed(base_path, result, diff_node, diff_type, identifier)

    for identifier in old_string_map:
        if identifier in new_string_map:
            old_hash = hasher.visit(old_string_map[identifier])
            new_hash = hasher.visit(new_string_map[identifier])
            if old_hash != new_hash:
                emit_string_modified(
                    base_path,
                    result,
                    diff_node,
                    diff_type,
                    identifier,
                    old_hash,
                    new_hash,
                )


def get_rule_summary(rule) -> dict[str, Any]:
    """Get a summary of a rule for diff details."""
    return {
        "name": rule.name,
        "modifiers": rule.modifiers,
        "tags_count": len(rule.tags),
        "meta_count": len(rule.meta),
        "strings_count": len(rule.strings),
        "has_condition": rule.condition is not None,
    }
