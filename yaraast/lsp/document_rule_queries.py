"""Rule-oriented query helpers for LSP document contexts."""

from __future__ import annotations

import re
from typing import TYPE_CHECKING, Any

from yaraast.lsp.structure import find_rule_end, find_rule_line, find_section_header_position

if TYPE_CHECKING:
    from yaraast.lsp.document_context import DocumentContext

_RULE_HEADER_RE = re.compile(
    r"^\s*(?P<modifiers>(?:(?:global|private)\s+)*)rule\s+(?P<name>\w+)"
    r"\s*(?:\:\s*(?P<tags>[^{]+))?\s*\{?"
)


def _copy_rule_info(info: dict[str, Any]) -> dict[str, Any]:
    copied = dict(info)
    for key in ("modifiers", "tags", "meta"):
        value = copied.get(key)
        if isinstance(value, list):
            copied[key] = list(value)
    return copied


def get_rule_info(ctx: DocumentContext, rule_name: str) -> dict[str, Any] | None:
    cache_key = f"rule_info:{rule_name}"
    cached = ctx.get_cached(cache_key)
    if cached is not None:
        return _copy_rule_info(cached)
    rule = ctx.get_rule(rule_name)
    if rule is None:
        rule_line = find_rule_line(ctx.lines, rule_name)
        if rule_line < 0:
            return None
        header = ctx.lines[rule_line]
        match = _RULE_HEADER_RE.match(header)
        if match is None:
            return None
        modifiers = match.group("modifiers").split()
        tags = match.group("tags").split() if match.group("tags") else []
        meta_items: list[tuple[str, Any]] = []
        strings_count = len(
            [
                symbol
                for symbol in ctx._symbols_of_kind("string")
                if symbol.container_name == rule_name
            ]
        )
        section_names = get_rule_sections(ctx, rule_name)
        result = {
            "name": rule_name,
            "modifiers": modifiers,
            "tags": tags,
            "meta": meta_items,
            "strings_count": strings_count,
            "has_events": "events" in section_names,
            "has_match": "match" in section_names,
            "has_outcome": "outcome" in section_names,
            "has_options": "options" in section_names,
        }
        ctx.set_cached(cache_key, result)
        return _copy_rule_info(result)
    modifiers = getattr(rule, "modifiers", None) or []
    tags = getattr(rule, "tags", None) or []
    meta = getattr(rule, "meta", None)
    if isinstance(meta, list):
        meta_items = [(getattr(m, "key", ""), getattr(m, "value", "")) for m in meta]
    elif hasattr(meta, "entries"):
        meta_items = [(entry.key, entry.value) for entry in getattr(meta, "entries", [])]
    else:
        meta_items = []
    result = {
        "name": rule_name,
        "modifiers": [str(m) for m in modifiers],
        "tags": [tag.name if hasattr(tag, "name") else str(tag) for tag in tags],
        "meta": meta_items,
        "strings_count": len(getattr(rule, "strings", None) or []),
        "has_events": getattr(rule, "events", None) is not None,
        "has_match": getattr(rule, "match", None) is not None,
        "has_outcome": getattr(rule, "outcome", None) is not None,
        "has_options": getattr(rule, "options", None) is not None,
    }
    ctx.set_cached(cache_key, result)
    return _copy_rule_info(result)


def get_rule_meta_items(ctx: DocumentContext, rule_name: str) -> list[tuple[str, Any]]:
    cache_key = f"rule_meta_items:{rule_name}"
    cached = ctx.get_cached(cache_key)
    if cached is not None:
        return list(cached)
    rule = ctx.get_rule(rule_name)
    if rule is None:
        return []
    meta = getattr(rule, "meta", None)
    if isinstance(meta, list):
        result = [(getattr(m, "key", ""), getattr(m, "value", "")) for m in meta]
    elif hasattr(meta, "entries"):
        result = [(entry.key, entry.value) for entry in getattr(meta, "entries", [])]
    else:
        result = []
    ctx.set_cached(cache_key, result)
    return list(result)


def get_rule_string_identifiers(ctx: DocumentContext, rule_name: str) -> list[str]:
    cache_key = f"rule_string_identifiers:{rule_name}"
    cached = ctx.get_cached(cache_key)
    if cached is not None:
        return list(cached)
    rule = ctx.get_rule(rule_name)
    if rule is None:
        result = [
            symbol.name
            for symbol in ctx._symbols_of_kind("string")
            if symbol.container_name == rule_name and symbol.name
        ]
        ctx.set_cached(cache_key, result)
        return list(result)
    result = [
        "$" if getattr(string_def, "is_anonymous", False) else string_def.identifier
        for string_def in getattr(rule, "strings", []) or []
        if getattr(string_def, "identifier", None)
    ]
    ctx.set_cached(cache_key, result)
    return list(result)


def get_rule_sections(ctx: DocumentContext, rule_name: str) -> list[str]:
    cache_key = f"rule_sections:{rule_name}"
    cached = ctx.get_cached(cache_key)
    if cached is not None:
        return list(cached)
    sections: list[str] = []
    seen: set[str] = set()
    for symbol in ctx._symbols_of_kind("section"):
        if symbol.container_name == rule_name and symbol.name not in seen:
            sections.append(symbol.name)
            seen.add(symbol.name)
    if not sections and ctx.get_rule(rule_name) is None:
        rule_line = find_rule_line(ctx.lines, rule_name)
        if rule_line >= 0:
            rule_end = find_rule_end(ctx.lines, rule_line)
            for name in ("meta", "strings", "condition", "events", "match", "outcome", "options"):
                if find_section_header_position(ctx.lines, name, rule_line, rule_end) is not None:
                    sections.append(name)
    order = {
        name: idx
        for idx, name in enumerate(
            ("meta", "strings", "condition", "events", "match", "outcome", "options")
        )
    }
    sections.sort(key=lambda name: (order.get(name, 99), name))
    ctx.set_cached(cache_key, sections)
    return list(sections)
