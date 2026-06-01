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
    old_modules = _nodes_by_key(old_imports, _import_key)
    new_modules = _nodes_by_key(new_imports, _import_key)

    for module in sorted(new_modules.keys() - old_modules.keys()):
        if module not in old_modules:
            new_bucket = new_modules[module]
            result.differences.append(
                diff_node(
                    path=f"/imports/{module}",
                    diff_type=diff_type.ADDED,
                    new_value=_import_bucket_value(module, new_bucket),
                    node_type="Import",
                ),
            )

    for module in sorted(old_modules.keys() - new_modules.keys()):
        if module not in new_modules:
            old_bucket = old_modules[module]
            result.differences.append(
                diff_node(
                    path=f"/imports/{module}",
                    diff_type=diff_type.REMOVED,
                    old_value=_import_bucket_value(module, old_bucket),
                    node_type="Import",
                ),
            )

    for module in sorted(old_modules.keys() & new_modules.keys()):
        if module in new_modules:
            old_bucket = old_modules[module]
            new_bucket = new_modules[module]
            if len(old_bucket) == 1 and len(new_bucket) == 1:
                old_alias = getattr(old_bucket[0], "alias", None)
                new_alias = getattr(new_bucket[0], "alias", None)
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
            else:
                old_value = _import_payloads(old_bucket)
                new_value = _import_payloads(new_bucket)
                if old_value != new_value:
                    result.differences.append(
                        diff_node(
                            path=f"/imports/{module}",
                            diff_type=diff_type.MODIFIED,
                            old_value=old_value,
                            new_value=new_value,
                            node_type="Import",
                        ),
                    )


def compare_extended_file_fields(old_ast, new_ast, result, hasher, diff_node, diff_type) -> None:
    """Compare extended file-level AST collections."""
    compare_node_collection(
        old_ast.extern_imports,
        new_ast.extern_imports,
        "/extern_imports",
        "ExternImport",
        _extern_import_key,
        result,
        hasher,
        diff_node,
        diff_type,
    )
    compare_node_collection(
        old_ast.extern_rules,
        new_ast.extern_rules,
        "/extern_rules",
        "ExternRule",
        _extern_rule_key,
        result,
        hasher,
        diff_node,
        diff_type,
    )
    compare_pragma_collection(
        old_ast.pragmas,
        new_ast.pragmas,
        "/pragmas",
        "Pragma",
        _pragma_key,
        result,
        hasher,
        diff_node,
        diff_type,
    )
    compare_node_collection(
        old_ast.namespaces,
        new_ast.namespaces,
        "/namespaces",
        "ExternNamespace",
        _name_key,
        result,
        hasher,
        diff_node,
        diff_type,
    )


def compare_node_collection(
    old_nodes,
    new_nodes,
    base_path: str,
    node_type: str,
    key_func,
    result,
    hasher,
    diff_node,
    diff_type,
) -> None:
    """Compare AST node collections by stable identity and structural hash."""
    old_map = _nodes_by_key(old_nodes, key_func)
    new_map = _nodes_by_key(new_nodes, key_func)

    for key in sorted(new_map.keys() - old_map.keys()):
        result.differences.append(
            diff_node(
                path=f"{base_path}/{key}",
                diff_type=diff_type.ADDED,
                new_value=key,
                node_type=node_type,
            ),
        )

    for key in sorted(old_map.keys() - new_map.keys()):
        result.differences.append(
            diff_node(
                path=f"{base_path}/{key}",
                diff_type=diff_type.REMOVED,
                old_value=key,
                node_type=node_type,
            ),
        )

    for key in sorted(old_map.keys() & new_map.keys()):
        old_bucket = old_map[key]
        new_bucket = new_map[key]
        if len(old_bucket) == 1 and len(new_bucket) == 1:
            old_value = hasher.visit(old_bucket[0])
            new_value = hasher.visit(new_bucket[0])
        else:
            old_value = sorted(hasher.visit(node) for node in old_bucket)
            new_value = sorted(hasher.visit(node) for node in new_bucket)
        if old_value != new_value:
            result.differences.append(
                diff_node(
                    path=f"{base_path}/{key}",
                    diff_type=diff_type.MODIFIED,
                    old_value=old_value,
                    new_value=new_value,
                    node_type=node_type,
                ),
            )


def compare_pragma_collection(
    old_pragmas,
    new_pragmas,
    base_path: str,
    node_type: str,
    key_func,
    result,
    hasher,
    diff_node,
    diff_type,
) -> None:
    """Compare pragma collections, including semantically relevant ordering."""
    compare_node_collection(
        old_pragmas,
        new_pragmas,
        base_path,
        node_type,
        key_func,
        result,
        hasher,
        diff_node,
        diff_type,
    )
    _emit_pragma_order_diff(
        old_pragmas,
        new_pragmas,
        f"{base_path}/order",
        node_type,
        result,
        hasher,
        diff_node,
        diff_type,
    )


def _nodes_by_key(nodes, key_func) -> dict[str, list]:
    """Group nodes by comparison key without dropping duplicates."""
    grouped: dict[str, list] = {}
    for node in nodes:
        grouped.setdefault(key_func(node), []).append(node)
    return grouped


def _import_key(node) -> str:
    return _string_attr_or_empty(node, "module", "Import module")


def _import_payload(node) -> dict[str, str | None]:
    return {
        "alias": getattr(node, "alias", None),
        "module": _import_key(node),
    }


def _import_payloads(imports) -> list[dict[str, str | None]]:
    return sorted(
        [_import_payload(import_node) for import_node in imports],
        key=lambda item: (item["module"] or "", item["alias"] or ""),
    )


def _import_bucket_value(module: str, imports):
    if len(imports) == 1:
        return module
    return _import_payloads(imports)


def _include_key(node) -> str:
    return _string_attr_or_empty(node, "path", "Include path")


def _include_bucket_value(path: str, includes):
    if len(includes) == 1:
        return path
    return [path] * len(includes)


def _include_payloads(path: str, includes) -> list[str]:
    return [path] * len(includes)


def _extern_import_key(node) -> str:
    if hasattr(node, "module_path"):
        return _string_attr_or_empty(node, "module_path", "ExternImport module path")
    return _string_attr_or_empty(node, "module", "ExternImport module")


def _extern_rule_key(node) -> str:
    name = _string_attr_or_empty(node, "name", "ExternRule name")
    namespace = _optional_string_attr(node, "namespace", "ExternRule namespace")
    return f"{namespace}.{name}" if namespace else name


def _pragma_key(node) -> str:
    pragma_type = _pragma_type_value(node)
    name = _string_attr_or_empty(node, "name", "Pragma name")
    macro_name = _string_attr_or_empty(node, "macro_name", "Pragma macro name")
    return f"{pragma_type}:{name}:{macro_name}"


def _in_rule_pragma_key(node) -> str:
    position = _string_attr_or_empty(node, "position", "InRulePragma position")
    return f"{position}:{_pragma_key(getattr(node, 'pragma', None))}"


def _name_key(node) -> str:
    return _string_attr_or_empty(node, "name", "Node name")


def _string_attr_or_empty(node, attr: str, field_name: str) -> str:
    if not hasattr(node, attr):
        return ""
    value = getattr(node, attr)
    if not isinstance(value, str):
        msg = f"{field_name} must be a string"
        raise TypeError(msg)
    return value


def _optional_string_attr(node, attr: str, field_name: str) -> str | None:
    value = getattr(node, attr, None)
    if value is None:
        return None
    if not isinstance(value, str):
        msg = f"{field_name} must be a string"
        raise TypeError(msg)
    return value


def _pragma_type_value(node) -> str:
    pragma_type = getattr(node, "pragma_type", None)
    if pragma_type is None:
        return ""
    value = getattr(pragma_type, "value", "")
    if not isinstance(value, str):
        msg = "Pragma type value must be a string"
        raise TypeError(msg)
    return value


def compare_includes(old_includes, new_includes, result, diff_node, diff_type) -> None:
    """Compare include lists."""
    old_paths = _nodes_by_key(old_includes, _include_key)
    new_paths = _nodes_by_key(new_includes, _include_key)

    for path in sorted(new_paths.keys() - old_paths.keys()):
        new_bucket = new_paths[path]
        result.differences.append(
            diff_node(
                path=f"/includes/{path}",
                diff_type=diff_type.ADDED,
                new_value=_include_bucket_value(path, new_bucket),
                node_type="Include",
            ),
        )

    for path in sorted(old_paths.keys() - new_paths.keys()):
        old_bucket = old_paths[path]
        result.differences.append(
            diff_node(
                path=f"/includes/{path}",
                diff_type=diff_type.REMOVED,
                old_value=_include_bucket_value(path, old_bucket),
                node_type="Include",
            ),
        )

    for path in sorted(old_paths.keys() & new_paths.keys()):
        old_bucket = old_paths[path]
        new_bucket = new_paths[path]
        old_value = _include_payloads(path, old_bucket)
        new_value = _include_payloads(path, new_bucket)
        if old_value != new_value:
            result.differences.append(
                diff_node(
                    path=f"/includes/{path}",
                    diff_type=diff_type.MODIFIED,
                    old_value=old_value,
                    new_value=new_value,
                    node_type="Include",
                ),
            )


def compare_rules(old_rules, new_rules, result, hasher, diff_node, diff_type) -> None:
    """Compare rule lists."""
    old_rule_map = _nodes_by_key(old_rules, _name_key)
    new_rule_map = _nodes_by_key(new_rules, _name_key)

    for name in new_rule_map:
        if name not in old_rule_map:
            new_bucket = new_rule_map[name]
            result.differences.append(
                diff_node(
                    path=f"/rules/{name}",
                    diff_type=diff_type.ADDED,
                    new_value=_rule_bucket_value(name, new_bucket, hasher),
                    node_type="Rule",
                    details=_rule_added_details(new_bucket),
                ),
            )

    for name in old_rule_map:
        if name not in new_rule_map:
            old_bucket = old_rule_map[name]
            result.differences.append(
                diff_node(
                    path=f"/rules/{name}",
                    diff_type=diff_type.REMOVED,
                    old_value=_rule_bucket_value(name, old_bucket, hasher),
                    node_type="Rule",
                    details=_rule_removed_details(old_bucket),
                ),
            )

    for name in old_rule_map:
        if name in new_rule_map:
            old_bucket = old_rule_map[name]
            new_bucket = new_rule_map[name]
            if len(old_bucket) == 1 and len(new_bucket) == 1:
                compare_rule_content(
                    old_bucket[0],
                    new_bucket[0],
                    f"/rules/{name}",
                    result,
                    hasher,
                    diff_node,
                    diff_type,
                )
            else:
                _compare_duplicate_rule_bucket(
                    name,
                    old_bucket,
                    new_bucket,
                    result,
                    hasher,
                    diff_node,
                    diff_type,
                )


def _rule_bucket_hashes(rules, hasher) -> list[str]:
    return sorted(hasher.visit(rule) for rule in rules)


def _rule_bucket_value(name: str, rules, hasher):
    if len(rules) == 1:
        return name
    return _rule_bucket_hashes(rules, hasher)


def _rule_added_details(rules) -> dict[str, Any]:
    if len(rules) == 1:
        return {"rule_summary": get_rule_summary(rules[0])}
    return {"new_rule_summaries": [get_rule_summary(rule) for rule in rules]}


def _rule_removed_details(rules) -> dict[str, Any]:
    if len(rules) == 1:
        return {"rule_summary": get_rule_summary(rules[0])}
    return {"old_rule_summaries": [get_rule_summary(rule) for rule in rules]}


def _compare_duplicate_rule_bucket(
    name: str,
    old_rules,
    new_rules,
    result,
    hasher,
    diff_node,
    diff_type,
) -> None:
    old_value = _rule_bucket_hashes(old_rules, hasher)
    new_value = _rule_bucket_hashes(new_rules, hasher)
    if old_value == new_value:
        return
    result.differences.append(
        diff_node(
            path=f"/rules/{name}",
            diff_type=diff_type.MODIFIED,
            old_value=old_value,
            new_value=new_value,
            node_type="Rule",
            details={
                "old_rule_summaries": [get_rule_summary(rule) for rule in old_rules],
                "new_rule_summaries": [get_rule_summary(rule) for rule in new_rules],
            },
        ),
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

    compare_rule_pragmas(old_rule, new_rule, base_path, result, hasher, diff_node, diff_type)

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


def compare_rule_pragmas(
    old_rule,
    new_rule,
    base_path,
    result,
    hasher,
    diff_node,
    diff_type,
) -> None:
    """Compare rule-level pragmas."""
    compare_node_collection(
        old_rule.pragmas,
        new_rule.pragmas,
        f"{base_path}/pragmas",
        "InRulePragma",
        _in_rule_pragma_key,
        result,
        hasher,
        diff_node,
        diff_type,
    )
    _emit_in_rule_pragma_order_diff(
        old_rule.pragmas,
        new_rule.pragmas,
        f"{base_path}/pragmas/order",
        result,
        hasher,
        diff_node,
        diff_type,
    )


def _emit_in_rule_pragma_order_diff(
    old_pragmas,
    new_pragmas,
    path: str,
    result,
    hasher,
    diff_node,
    diff_type,
) -> None:
    old_signature = _in_rule_pragma_order_signature(old_pragmas, hasher)
    new_signature = _in_rule_pragma_order_signature(new_pragmas, hasher)
    if old_signature == new_signature:
        return
    if sorted(hasher.visit(pragma) for pragma in old_pragmas) != sorted(
        hasher.visit(pragma) for pragma in new_pragmas
    ):
        return
    result.differences.append(
        diff_node(
            path=path,
            diff_type=diff_type.MODIFIED,
            old_value=old_signature,
            new_value=new_signature,
            node_type="InRulePragmaOrder",
        ),
    )


def _emit_pragma_order_diff(
    old_pragmas,
    new_pragmas,
    path: str,
    node_type: str,
    result,
    hasher,
    diff_node,
    diff_type,
) -> None:
    old_signature = _pragma_order_signature(old_pragmas, hasher)
    new_signature = _pragma_order_signature(new_pragmas, hasher)
    if old_signature == new_signature:
        return
    if sorted(hasher.visit(pragma) for pragma in old_pragmas) != sorted(
        hasher.visit(pragma) for pragma in new_pragmas
    ):
        return
    result.differences.append(
        diff_node(
            path=path,
            diff_type=diff_type.MODIFIED,
            old_value=old_signature,
            new_value=new_signature,
            node_type=f"{node_type}Order",
        ),
    )


def _in_rule_pragma_order_signature(pragmas, hasher) -> list[str]:
    grouped: dict[str, list] = {}
    for pragma in pragmas:
        position = str(getattr(pragma, "position", ""))
        grouped.setdefault(position, []).append(pragma)
    return [
        f"{position}:{_pragma_order_signature(grouped[position], hasher)}"
        for position in sorted(grouped)
    ]


def _pragma_order_signature(pragmas, hasher) -> list[str]:
    signature: list[str] = []
    unordered_run: list[str] = []

    def flush_unordered_run() -> None:
        if unordered_run:
            signature.append("Set(" + "|".join(sorted(unordered_run)) + ")")
            unordered_run.clear()

    for pragma in pragmas:
        pragma_hash = hasher.visit(pragma)
        if _is_order_insensitive_pragma(pragma):
            unordered_run.append(pragma_hash)
        else:
            flush_unordered_run()
            signature.append(pragma_hash)

    flush_unordered_run()
    return signature


def _is_order_insensitive_pragma(node) -> bool:
    pragma = getattr(node, "pragma", node)
    pragma_type = getattr(getattr(pragma, "pragma_type", None), "value", None)
    return pragma_type in {"custom", "include_once"}


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

    for identifier in sorted(new_string_map.keys() - old_string_map.keys()):
        new_bucket = new_string_map[identifier]
        if len(new_bucket) == 1:
            emit_string_added(base_path, result, diff_node, diff_type, identifier)
        else:
            result.differences.append(
                diff_node(
                    path=f"{base_path}/{identifier}",
                    diff_type=diff_type.ADDED,
                    new_value=_string_bucket_hashes(new_bucket, hasher),
                    node_type="StringDefinition",
                ),
            )

    for identifier in sorted(old_string_map.keys() - new_string_map.keys()):
        old_bucket = old_string_map[identifier]
        if len(old_bucket) == 1:
            emit_string_removed(base_path, result, diff_node, diff_type, identifier)
        else:
            result.differences.append(
                diff_node(
                    path=f"{base_path}/{identifier}",
                    diff_type=diff_type.REMOVED,
                    old_value=_string_bucket_hashes(old_bucket, hasher),
                    node_type="StringDefinition",
                ),
            )

    for identifier in sorted(old_string_map.keys() & new_string_map.keys()):
        old_bucket = old_string_map[identifier]
        new_bucket = new_string_map[identifier]
        if len(old_bucket) == 1 and len(new_bucket) == 1:
            old_hash = hasher.visit(old_bucket[0])
            new_hash = hasher.visit(new_bucket[0])
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
        else:
            old_value = _string_bucket_hashes(old_bucket, hasher)
            new_value = _string_bucket_hashes(new_bucket, hasher)
            if old_value != new_value:
                result.differences.append(
                    diff_node(
                        path=f"{base_path}/{identifier}",
                        diff_type=diff_type.MODIFIED,
                        old_value=old_value,
                        new_value=new_value,
                        node_type="StringDefinition",
                    ),
                )


def _string_bucket_hashes(strings, hasher) -> list[str]:
    return sorted(hasher.visit(string_def) for string_def in strings)


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
