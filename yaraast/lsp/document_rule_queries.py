"""Rule-oriented query helpers for LSP document contexts."""

from __future__ import annotations

from typing import TYPE_CHECKING, Any

if TYPE_CHECKING:
    from yaraast.lsp.document_context import DocumentContext


def get_rule_info(ctx: DocumentContext, rule_name: str) -> dict[str, Any] | None:
    cache_key = f"rule_info:{rule_name}"
    cached = ctx.get_cached(cache_key)
    if cached is not None:
        return cached
    rule = ctx.get_rule(rule_name)
    if rule is None:
        return None
    modifiers = getattr(rule, "modifiers", None) or []
    tags = getattr(rule, "tags", None) or []
    meta = getattr(rule, "meta", None)
    if isinstance(meta, dict):
        meta_items = list(meta.items())
    elif hasattr(meta, "entries"):
        meta_items = [(entry.key, entry.value) for entry in getattr(meta, "entries", [])]
    else:
        meta_items = []
    result = {
        "name": rule_name,
        "modifiers": [str(m) if not isinstance(m, str) else m for m in modifiers],
        "tags": [tag.name if hasattr(tag, "name") else str(tag) for tag in tags],
        "meta": meta_items,
        "strings_count": len(getattr(rule, "strings", None) or []),
        "has_events": getattr(rule, "events", None) is not None,
        "has_match": getattr(rule, "match", None) is not None,
        "has_outcome": getattr(rule, "outcome", None) is not None,
        "has_options": getattr(rule, "options", None) is not None,
    }
    ctx.set_cached(cache_key, result)
    return result


def get_rule_meta_items(ctx: DocumentContext, rule_name: str) -> list[tuple[str, Any]]:
    cache_key = f"rule_meta_items:{rule_name}"
    cached = ctx.get_cached(cache_key)
    if cached is not None:
        return cached
    rule = ctx.get_rule(rule_name)
    if rule is None:
        return []
    meta = getattr(rule, "meta", None)
    if isinstance(meta, dict):
        result = list(meta.items())
    elif hasattr(meta, "entries"):
        result = [(entry.key, entry.value) for entry in getattr(meta, "entries", [])]
    else:
        result = []
    ctx.set_cached(cache_key, result)
    return result


def get_rule_string_identifiers(ctx: DocumentContext, rule_name: str) -> list[str]:
    cache_key = f"rule_string_identifiers:{rule_name}"
    cached = ctx.get_cached(cache_key)
    if cached is not None:
        return cached
    rule = ctx.get_rule(rule_name)
    if rule is None:
        return []
    result = [
        string_def.identifier
        for string_def in getattr(rule, "strings", []) or []
        if getattr(string_def, "identifier", None)
    ]
    ctx.set_cached(cache_key, result)
    return result


def get_rule_sections(ctx: DocumentContext, rule_name: str) -> list[str]:
    cache_key = f"rule_sections:{rule_name}"
    cached = ctx.get_cached(cache_key)
    if cached is not None:
        return cached
    sections: list[str] = []
    seen: set[str] = set()
    for symbol in ctx._symbols_of_kind("section"):
        if symbol.container_name == rule_name and symbol.name not in seen:
            sections.append(symbol.name)
            seen.add(symbol.name)
    order = {
        name: idx
        for idx, name in enumerate(
            ("meta", "strings", "condition", "events", "match", "outcome", "options")
        )
    }
    sections.sort(key=lambda name: (order.get(name, 99), name))
    ctx.set_cached(cache_key, sections)
    return sections
