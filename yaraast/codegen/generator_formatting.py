"""Formatting helpers for code generation."""

from __future__ import annotations

import re
from typing import Any

from yaraast.ast.modifiers import RuleModifier
from yaraast.codegen.generator_helpers import (
    escape_plain_string_value,
    escape_regex_delimiter,
    format_hex_jump_bounds,
    validate_string_identifier_text,
)
from yaraast.lexer.lexer_tables import KEYWORDS, YARA_IDENTIFIER_MAX_LENGTH
from yaraast.regex_literals import validate_regex_modifiers

_YARA_IDENTIFIER_RE = re.compile(r"^[A-Za-z_][A-Za-z0-9_]*$")
_YARA_KEYWORDS = frozenset(KEYWORDS)
_YARA_RULE_MODIFIERS = frozenset({"global", "private"})
_YARA_EXPRESSION_KEYWORDS = frozenset(
    {"all", "any", "entrypoint", "false", "filesize", "none", "true"}
)
_YARA_FILE_COLLECTION_FIELDS = (
    "imports",
    "includes",
    "rules",
    "extern_rules",
    "extern_imports",
    "pragmas",
    "namespaces",
)
_RULE_COLLECTION_FIELDS = (
    ("tags", "Rule tags"),
    ("pragmas", "Rule pragmas"),
)


def format_rule_modifiers(modifiers: list[Any] | tuple[Any, ...] | None) -> str:
    if modifiers is None:
        return ""
    if not isinstance(modifiers, list | tuple):
        msg = "Rule modifiers must be a list or tuple for libyara output"
        raise TypeError(msg)
    if not modifiers:
        return ""
    validate_rule_modifiers(modifiers)
    return " ".join(_rule_modifier_name(modifier) for modifier in modifiers)


def validate_rule_modifiers(modifiers: list[Any] | tuple[Any, ...]) -> None:
    for modifier in modifiers:
        name = _rule_modifier_name(modifier)
        if name in _YARA_RULE_MODIFIERS:
            continue
        msg = f"Invalid rule modifier '{name}' for libyara output"
        raise ValueError(msg)


def _rule_modifier_name(modifier: Any) -> str:
    if isinstance(modifier, str):
        return modifier
    if isinstance(modifier, RuleModifier):
        return str(modifier)
    msg = "Rule modifiers must contain strings or RuleModifier nodes for libyara output"
    raise TypeError(msg)


def validate_rule_identifiers(rules: list[Any] | tuple[Any, ...]) -> None:
    if not rules:
        return

    seen: set[str] = set()
    for rule in rules:
        name = str(getattr(rule, "name", ""))
        _validate_yara_identifier(name, "rule")
        if name in seen:
            msg = f"Duplicate rule identifier '{name}' for libyara output"
            raise ValueError(msg)
        seen.add(name)


def validate_extern_rule_identifiers(
    rules: list[Any] | tuple[Any, ...],
    extern_rules: list[Any] | tuple[Any, ...],
    namespaces: list[Any] | tuple[Any, ...],
) -> None:
    rule_names = {str(getattr(rule, "name", "")) for rule in rules}
    seen: set[tuple[str | None, str]] = set()

    for extern_rule in extern_rules:
        _validate_extern_rule_identifier(extern_rule, None, rule_names, seen)

    for namespace in namespaces:
        namespace_name = validate_yara_identifier_path(getattr(namespace, "name", ""), "namespace")
        namespace_rules = getattr(namespace, "extern_rules", [])
        if not isinstance(namespace_rules, list | tuple):
            continue
        for extern_rule in namespace_rules:
            _validate_extern_rule_identifier(
                extern_rule,
                namespace_name,
                rule_names,
                seen,
            )


def _validate_extern_rule_identifier(
    extern_rule: Any,
    default_namespace: str | None,
    rule_names: set[str],
    seen: set[tuple[str | None, str]],
) -> None:
    name = validate_yara_identifier(getattr(extern_rule, "name", ""), "extern rule")
    namespace = validate_optional_namespace(
        getattr(extern_rule, "namespace", None),
        default_namespace,
    )

    if namespace is None and name in rule_names:
        msg = f"Duplicate rule identifier '{name}' for libyara output"
        raise ValueError(msg)

    key = (namespace, name)
    if key in seen:
        qualified_name = f"{namespace}.{name}" if namespace else name
        msg = f"Duplicate extern rule identifier '{qualified_name}' for libyara output"
        raise ValueError(msg)
    seen.add(key)


def validate_yara_file_collections(node: Any) -> None:
    for field_name in _YARA_FILE_COLLECTION_FIELDS:
        value = getattr(node, field_name)
        if isinstance(value, list | tuple):
            continue
        msg = f"YaraFile {field_name} must be a list or tuple for libyara output"
        raise TypeError(msg)


def validate_rule_collections(node: Any) -> None:
    for field_name, display_name in _RULE_COLLECTION_FIELDS:
        value = getattr(node, field_name)
        if isinstance(value, list | tuple):
            continue
        msg = f"{display_name} must be a list or tuple for libyara output"
        raise TypeError(msg)


def format_rule_tags(tags: list[Any] | tuple[Any, ...] | None) -> str:
    if tags is None:
        return ""
    if not isinstance(tags, list | tuple):
        msg = "Rule tags must be a list or tuple for libyara output"
        raise TypeError(msg)
    if not tags:
        return ""
    validate_rule_tags(tags)
    tag_names = [validate_rule_tag_name(tag) for tag in tags]
    return " ".join(tag_names)


def validate_rule_tags(tags: list[Any] | tuple[Any, ...]) -> None:
    if not tags:
        return

    seen: set[str] = set()
    for tag in tags:
        name = validate_rule_tag_name(tag)
        _validate_yara_identifier(name, "tag")
        if name in seen:
            msg = f"Duplicate tag identifier '{name}' for libyara output"
            raise ValueError(msg)
        seen.add(name)


def validate_rule_meta(meta: object) -> None:
    if meta is None:
        return
    if not isinstance(meta, dict | list | tuple):
        msg = "Rule meta must be a dictionary, list, or tuple for libyara output"
        raise TypeError(msg)
    if isinstance(meta, dict):
        for key, value in meta.items():
            format_meta_value(key, value)
        return
    for entry in meta:
        if not (hasattr(entry, "key") and hasattr(entry, "value")):
            msg = "Rule meta must contain meta entries for libyara output"
            raise TypeError(msg)
        format_meta_value(entry.key, entry.value, getattr(entry, "scope", None))


def validate_rule_tag_name(tag: Any) -> str:
    if isinstance(tag, str):
        return tag
    if hasattr(tag, "name"):
        name = tag.name
        if isinstance(name, str):
            return name
        msg = "Tag name must be a string for libyara output"
        raise TypeError(msg)
    msg = "Rule tags must contain strings or Tag nodes for libyara output"
    raise TypeError(msg)


def _validate_yara_identifier(name: str, kind: str) -> None:
    if (
        len(name) <= YARA_IDENTIFIER_MAX_LENGTH
        and _YARA_IDENTIFIER_RE.fullmatch(name) is not None
        and name not in _YARA_KEYWORDS
    ):
        return

    msg = f"Invalid {kind} identifier '{name}' for libyara output"
    raise ValueError(msg)


def validate_yara_identifier(name: str, kind: str) -> str:
    _validate_yara_identifier(name, kind)
    return name


def validate_yara_expression_identifier(name: str) -> str:
    if name.startswith("$"):
        return validate_string_identifier_text(name)
    if name in _YARA_EXPRESSION_KEYWORDS:
        return name
    return validate_yara_identifier(name, "identifier")


def validate_yara_identifier_path(path: str, kind: str) -> str:
    parts = path.split(".")
    if not parts or any(part == "" for part in parts):
        msg = f"Invalid {kind} identifier '{path}' for libyara output"
        raise ValueError(msg)
    for part in parts:
        _validate_yara_identifier(part, kind)
    return path


def validate_optional_namespace(
    namespace: object, default_namespace: str | None = None
) -> str | None:
    if namespace is None:
        return default_namespace
    if not isinstance(namespace, str):
        msg = "Namespace must be a string for libyara output"
        raise TypeError(msg)
    return validate_yara_identifier_path(namespace, "namespace")


def format_meta_key(key: str, scope: object | None = None) -> str:
    _validate_yara_identifier(key, "meta")
    scope_value = getattr(scope, "value", scope)
    if scope_value and scope_value != "public":
        msg = f"Unsupported meta scope '{scope_value}' for libyara output"
        raise ValueError(msg)
    return key


def format_meta_literal(value: Any, *, preserve_quoted: bool = False) -> str:
    if isinstance(value, str):
        if preserve_quoted and value.startswith('"') and value.endswith('"'):
            return value
        return f'"{escape_string_literal(value)}"'
    if isinstance(value, bool):
        return "true" if value else "false"
    if isinstance(value, int):
        return str(value)
    msg = f"Invalid meta value type '{type(value).__name__}' for libyara output"
    raise TypeError(msg)


def format_meta_value(key: str, value: Any, scope: object | None = None) -> str:
    rendered_key = format_meta_key(key, scope)
    return f"{rendered_key} = {format_meta_literal(value)}"


def escape_string_literal(value: str) -> str:
    return escape_plain_string_value(value)


def format_nonempty_quoted_value(value: str, kind: str) -> str:
    if not isinstance(value, str):
        msg = f"{kind} must be a string for libyara output"
        raise TypeError(msg)
    if not value:
        msg = f"{kind} must not be empty for libyara output"
        raise ValueError(msg)
    return escape_string_literal(value)


def reject_import_alias(alias: object) -> None:
    if alias is None:
        return
    if not isinstance(alias, str):
        msg = "Import alias must be a string for libyara output"
        raise TypeError(msg)
    msg = "Import aliases are not supported for libyara output"
    raise ValueError(msg)


def format_import_alias(alias: object) -> str:
    if alias is None:
        return ""
    if not isinstance(alias, str):
        msg = "Import alias must be a string for libyara output"
        raise TypeError(msg)
    return f" as {validate_yara_identifier(alias, 'import alias')}"


def format_regex_literal(pattern: str, modifiers: str) -> str:
    validate_regex_modifiers(modifiers)
    escaped_pattern = escape_regex_delimiter(pattern)
    return f"/{escaped_pattern}/{modifiers}"


def format_boolean_literal(value: bool) -> str:
    if not isinstance(value, bool):
        msg = "Boolean literal value must be a boolean"
        raise TypeError(msg)
    return "true" if value else "false"


def format_hex_jump(min_jump: int | None, max_jump: int | None) -> str:
    return format_hex_jump_bounds(min_jump, max_jump)
