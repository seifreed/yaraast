"""Lookup-oriented query helpers for LSP document contexts."""

from __future__ import annotations

from pathlib import Path
from typing import TYPE_CHECKING, Any

from lsprotocol.types import Position, Range

from yaraast.types.module_loader import ModuleLoader

if TYPE_CHECKING:
    from yaraast.lsp.document_context import DocumentContext


def get_meta_value(ctx: DocumentContext, key: str) -> Any | None:
    cache_key = f"meta_value:{key}"
    cached = ctx.get_cached(cache_key)
    if cached is not None:
        return cached
    ast = ctx.ast()
    if ast is None:
        return None
    for rule in ctx._iter_rules(ast):
        meta = getattr(rule, "meta", None)
        if isinstance(meta, dict) and key in meta:
            result = meta[key]
            ctx.set_cached(cache_key, result)
            return result
        if hasattr(meta, "entries"):
            for entry in getattr(meta, "entries", []):
                if getattr(entry, "key", None) == key:
                    result = getattr(entry, "value", None)
                    ctx.set_cached(cache_key, result)
                    return result
    return None


def get_string_definition_node(ctx: DocumentContext, identifier: str) -> tuple[Any, Any] | None:
    cache_key = f"string_definition_node:{identifier}"
    cached = ctx.get_cached(cache_key)
    if cached is not None:
        return cached
    ast = ctx.ast()
    if ast is None:
        return None
    for rule in ctx._iter_rules(ast):
        for string_def in getattr(rule, "strings", []):
            if getattr(string_def, "identifier", None) == identifier:
                result = (string_def, rule)
                ctx.set_cached(cache_key, result)
                return result
    return None


def get_string_definition_info(ctx: DocumentContext, identifier: str) -> dict[str, Any] | None:
    cache_key = f"string_definition_info:{identifier}"
    cached = ctx.get_cached(cache_key)
    if cached is not None:
        return cached
    string_data = ctx.get_string_definition_node(identifier)
    if string_data is None:
        return None
    string_def, _rule = string_data
    if hasattr(string_def, "value"):
        value = string_def.value
        string_type = "text string"
    elif hasattr(string_def, "regex"):
        value = string_def.regex
        string_type = "regex"
    elif hasattr(string_def, "tokens"):
        value = "<hex pattern>"
        string_type = "hex string"
    else:
        value = "<unknown>"
        string_type = "string"
    modifiers = []
    if hasattr(string_def, "modifiers"):
        modifiers = [m.name for m in string_def.modifiers]
    result = {"identifier": identifier, "type": string_type, "value": value, "modifiers": modifiers}
    ctx.set_cached(cache_key, result)
    return result


def get_module_member_info(ctx: DocumentContext, qualified_name: str) -> dict[str, Any] | None:
    cache_key = f"module_member_info:{qualified_name}"
    cached = ctx.get_cached(cache_key)
    if cached is not None:
        return cached
    parts = qualified_name.split(".")
    if len(parts) != 2:
        return None
    module_name, member_name = parts
    module_def = ModuleLoader().get_module(module_name)
    if not module_def:
        return None
    if member_name in module_def.functions:
        func_def = module_def.functions[member_name]
        result = {
            "module": module_name,
            "member": member_name,
            "kind": "function",
            "parameters": list(getattr(func_def, "parameters", [])),
            "return_type": getattr(func_def, "return_type", "unknown"),
            "description": getattr(func_def, "description", None),
        }
        ctx.set_cached(cache_key, result)
        return result
    fields = getattr(module_def, "fields", None) or {}
    if member_name in fields:
        field_def = fields[member_name]
        result = {
            "module": module_name,
            "member": member_name,
            "kind": "field",
            "type": getattr(field_def, "type", "unknown"),
            "description": getattr(field_def, "description", None),
        }
        ctx.set_cached(cache_key, result)
        return result
    return None


def get_include_info(ctx: DocumentContext, include_path: str) -> dict[str, Any]:
    cache_key = f"include_info:{include_path}"
    cached = ctx.get_cached(cache_key)
    if cached is not None:
        return cached
    resolved_path: Path | None = None
    doc_path = ctx.path
    if doc_path is not None:
        candidate = doc_path.parent / include_path
        if candidate.exists():
            resolved_path = candidate.resolve()
    result = {"path": include_path, "resolved_path": str(resolved_path) if resolved_path else None}
    ctx.set_cached(cache_key, result)
    return result


def get_include_target_uri(ctx: DocumentContext, include_path: str) -> str | None:
    include_info = ctx.get_include_info(include_path)
    resolved_path = include_info.get("resolved_path")
    return f"file://{resolved_path}" if resolved_path else None


def get_dotted_symbol_at_position(
    ctx: DocumentContext, position: Position
) -> tuple[str, Range] | None:
    if position.line < 0 or position.line >= len(ctx.lines):
        return None
    line = ctx.lines[position.line]
    if position.character < 0 or position.character >= len(line):
        return None
    allowed = set("abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789_.")
    start = position.character
    while start > 0 and line[start - 1] in allowed:
        start -= 1
    end = position.character
    while end < len(line) and line[end] in allowed:
        end += 1
    token = line[start:end]
    if token.count(".") != 1:
        return None
    left, right = token.split(".", 1)
    if not left or not right:
        return None
    return token, Range(
        start=Position(line=position.line, character=start),
        end=Position(line=position.line, character=end),
    )
