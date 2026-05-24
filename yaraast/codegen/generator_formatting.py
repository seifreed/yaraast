"""Formatting helpers for code generation."""

from __future__ import annotations

from yaraast.codegen.generator_helpers import (
    escape_plain_string_value,
    escape_regex_delimiter,
    format_hex_jump_bounds,
)


def format_rule_modifiers(modifiers) -> str:
    if not modifiers:
        return ""
    if isinstance(modifiers, list | tuple):
        return " ".join(str(m) for m in modifiers)
    return ""


def format_rule_tags(tags) -> str:
    if not tags:
        return ""
    tag_names = []
    for tag in tags:
        if isinstance(tag, str):
            tag_names.append(tag)
        else:
            tag_names.append(tag.name)
    return " ".join(tag_names)


def format_meta_key(key: str, scope: object | None = None) -> str:
    scope_value = getattr(scope, "value", scope)
    if scope_value and scope_value != "public":
        return f"{scope_value}:{key}"
    return key


def format_meta_value(key: str, value, scope: object | None = None) -> str:
    rendered_key = format_meta_key(key, scope)
    if isinstance(value, str):
        return f'{rendered_key} = "{escape_string_literal(value)}"'
    if isinstance(value, bool):
        return f"{rendered_key} = {'true' if value else 'false'}"
    return f"{rendered_key} = {value}"


def escape_string_literal(value: str) -> str:
    return escape_plain_string_value(value)


def format_regex_literal(pattern: str, modifiers: str) -> str:
    escaped_pattern = escape_regex_delimiter(pattern)
    return f"/{escaped_pattern}/{modifiers}"


def format_boolean_literal(value: bool) -> str:
    return "true" if value else "false"


def format_hex_jump(min_jump, max_jump) -> str:
    return format_hex_jump_bounds(min_jump, max_jump)
