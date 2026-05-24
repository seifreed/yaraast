"""Formatting helpers for code generation."""

from __future__ import annotations

import re

from yaraast.codegen.generator_helpers import (
    escape_plain_string_value,
    escape_regex_delimiter,
    format_hex_jump_bounds,
    validate_string_identifier_text,
)
from yaraast.lexer.lexer_tables import KEYWORDS
from yaraast.regex_literals import validate_regex_modifiers

_YARA_IDENTIFIER_RE = re.compile(r"^[A-Za-z_][A-Za-z0-9_]*$")
_YARA_KEYWORDS = frozenset(KEYWORDS)
_YARA_RULE_MODIFIERS = frozenset({"global", "private"})
_YARA_EXPRESSION_KEYWORDS = frozenset(
    {"all", "any", "entrypoint", "false", "filesize", "none", "true"}
)


def format_rule_modifiers(modifiers) -> str:
    if not modifiers:
        return ""
    if isinstance(modifiers, list | tuple):
        validate_rule_modifiers(modifiers)
        return " ".join(str(m) for m in modifiers)
    return ""


def validate_rule_modifiers(modifiers) -> None:
    for modifier in modifiers:
        name = str(modifier)
        if name in _YARA_RULE_MODIFIERS:
            continue
        msg = f"Invalid rule modifier '{name}' for libyara output"
        raise ValueError(msg)


def validate_rule_identifiers(rules) -> None:
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


def format_rule_tags(tags) -> str:
    if not tags:
        return ""
    validate_rule_tags(tags)
    tag_names = [_rule_tag_name(tag) for tag in tags]
    return " ".join(tag_names)


def validate_rule_tags(tags) -> None:
    if not tags:
        return

    seen: set[str] = set()
    for tag in tags:
        name = _rule_tag_name(tag)
        _validate_yara_identifier(name, "tag")
        if name in seen:
            msg = f"Duplicate tag identifier '{name}' for libyara output"
            raise ValueError(msg)
        seen.add(name)


def _rule_tag_name(tag) -> str:
    if isinstance(tag, str):
        return tag
    return str(tag.name if hasattr(tag, "name") else tag)


def _validate_yara_identifier(name: str, kind: str) -> None:
    if _YARA_IDENTIFIER_RE.fullmatch(name) is not None and name not in _YARA_KEYWORDS:
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


def format_meta_key(key: str, scope: object | None = None) -> str:
    _validate_yara_identifier(key, "meta")
    scope_value = getattr(scope, "value", scope)
    if scope_value and scope_value != "public":
        return f"{scope_value}:{key}"
    return key


def format_meta_literal(value, *, preserve_quoted: bool = False) -> str:
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


def format_meta_value(key: str, value, scope: object | None = None) -> str:
    rendered_key = format_meta_key(key, scope)
    return f"{rendered_key} = {format_meta_literal(value)}"


def escape_string_literal(value: str) -> str:
    return escape_plain_string_value(value)


def format_regex_literal(pattern: str, modifiers: str) -> str:
    validate_regex_modifiers(modifiers)
    escaped_pattern = escape_regex_delimiter(pattern)
    return f"/{escaped_pattern}/{modifiers}"


def format_boolean_literal(value: bool) -> str:
    if not isinstance(value, bool):
        msg = "Boolean literal value must be a boolean"
        raise TypeError(msg)
    return "true" if value else "false"


def format_hex_jump(min_jump, max_jump) -> str:
    return format_hex_jump_bounds(min_jump, max_jump)
