"""Lookup-oriented query helpers for LSP document contexts."""

from __future__ import annotations

from pathlib import Path
from typing import TYPE_CHECKING, Any, cast

from lsprotocol.types import Position, Range

from yaraast.codegen.generator_helpers import escape_plain_string_value
from yaraast.lsp.meta_value_parsing import parse_meta_scalar
from yaraast.lsp.utf16 import utf8_col_to_utf16, utf16_col_to_utf8, utf16_len
from yaraast.lsp.utils import path_exists
from yaraast.shared.path_safety import path_is_symlink, path_is_within_directory
from yaraast.types.module_loader import ModuleLoader

if TYPE_CHECKING:
    from yaraast.lsp.document_context import DocumentContext


def _copy_info_dict(info: dict[str, Any]) -> dict[str, Any]:
    copied = dict(info)
    for key, value in copied.items():
        if isinstance(value, list):
            copied[key] = list(value)
    return copied


def _require_include_path(include_path: object) -> str:
    if not isinstance(include_path, str):
        msg = "Include path must be a string"
        raise TypeError(msg)
    if not include_path.strip():
        msg = "Include path must not be empty"
        raise ValueError(msg)
    return include_path


def _require_module_member_name(qualified_name: object) -> str:
    if not isinstance(qualified_name, str):
        msg = "Module member name must be a string"
        raise TypeError(msg)
    return qualified_name


def _require_document_position(position: object) -> Position:
    if not isinstance(position, Position):
        msg = "Document position must be an LSP Position"
        raise TypeError(msg)
    return position


def get_meta_value(ctx: DocumentContext, key: str) -> Any | None:
    cache_key = f"meta_value:{key}"
    cached = ctx.get_cached(cache_key)
    if cached is not None:
        return cached
    ast = ctx.ast()
    if ast is None:
        result = _fallback_meta_value(ctx, key)
        if result is not None:
            ctx.set_cached(cache_key, result)
        return result
    for rule in ctx._iter_rules(ast):
        meta = getattr(rule, "meta", None)
        if isinstance(meta, list):
            for entry in meta:
                if getattr(entry, "key", None) == key:
                    result = getattr(entry, "value", None)
                    ctx.set_cached(cache_key, result)
                    return result
        elif hasattr(meta, "entries"):
            for entry in getattr(meta, "entries", []):
                if getattr(entry, "key", None) == key:
                    result = getattr(entry, "value", None)
                    ctx.set_cached(cache_key, result)
                    return result
    return None


def _fallback_meta_value(ctx: DocumentContext, key: str) -> Any | None:
    lines = ctx.lines
    for line_num, line in enumerate(lines):
        if not line.strip().startswith("meta:"):
            continue
        for meta_line in lines[line_num + 1 :]:
            stripped = meta_line.strip()
            if not stripped:
                continue
            if not meta_line.startswith((" ", "\t")):
                break
            if "=" not in stripped:
                continue
            candidate_key, raw_value = stripped.split("=", 1)
            if candidate_key.strip() != key:
                continue
            parsed = _parse_meta_value(raw_value.strip())
            if parsed is not None:
                return parsed
    return None


def _parse_meta_value(raw_value: str) -> Any | None:
    found, parsed = parse_meta_scalar(raw_value)
    if found:
        return parsed
    return raw_value.strip('"')


def get_string_definition_node(ctx: DocumentContext, identifier: str) -> tuple[Any, Any] | None:
    cache_key = f"string_definition_node:{identifier}"
    cached = ctx.get_cached(cache_key)
    if cached is not None:
        return cast(tuple[Any, Any], cached)
    ast = ctx.ast()
    if ast is None:
        return None
    for rule in ctx._iter_rules(ast):
        for string_def in getattr(rule, "strings", []):
            if getattr(string_def, "is_anonymous", False):
                continue
            if getattr(string_def, "identifier", None) == identifier:
                result = (string_def, rule)
                ctx.set_cached(cache_key, result)
                return result
    return None


def get_string_definition_info(ctx: DocumentContext, identifier: str) -> dict[str, Any] | None:
    cache_key = f"string_definition_info:{identifier}"
    cached = ctx.get_cached(cache_key)
    if cached is not None:
        return _copy_info_dict(cached)
    string_data = ctx.get_string_definition_node(identifier)
    if string_data is None:
        return None
    string_def, _rule = string_data
    if hasattr(string_def, "value"):
        value = escape_plain_string_value(string_def.value)
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
        modifiers = [m if isinstance(m, str) else str(m.name) for m in string_def.modifiers]
    result = {"identifier": identifier, "type": string_type, "value": value, "modifiers": modifiers}
    ctx.set_cached(cache_key, result)
    return _copy_info_dict(result)


def get_module_member_info(ctx: DocumentContext, qualified_name: str) -> dict[str, Any] | None:
    qualified_name = _require_module_member_name(qualified_name)
    cache_key = f"module_member_info:{qualified_name}"
    cached = ctx.get_cached(cache_key)
    if cached is not None:
        return _copy_info_dict(cached)
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
        return _copy_info_dict(result)
    fields = getattr(module_def, "fields", None) or getattr(module_def, "attributes", None) or {}
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
        return _copy_info_dict(result)
    return None


def get_include_info(ctx: DocumentContext, include_path: str) -> dict[str, Any]:
    include_path = _require_include_path(include_path)
    cache_key = f"include_info:{include_path}"
    cached = ctx.get_cached(cache_key)
    if cached is not None:
        return dict(cached)
    resolved_path: Path | None = None
    doc_path = ctx.path
    if doc_path is not None and not path_is_symlink(doc_path.parent):
        candidate = doc_path.parent / include_path
        if path_exists(candidate) and path_is_within_directory(candidate, doc_path.parent):
            resolved_path = candidate
    result = {"path": include_path, "resolved_path": str(resolved_path) if resolved_path else None}
    ctx.set_cached(cache_key, result)
    return dict(result)


def get_include_target_uri(ctx: DocumentContext, include_path: str) -> str | None:
    include_path = _require_include_path(include_path)
    include_info = ctx.get_include_info(include_path)
    resolved_path = include_info.get("resolved_path")
    return Path(resolved_path).absolute().as_uri() if resolved_path else None


def get_dotted_symbol_at_position(
    ctx: DocumentContext, position: Position
) -> tuple[str, Range] | None:
    position = _require_document_position(position)
    if position.line >= len(ctx.lines):
        return None
    line = ctx.lines[position.line]
    if position.character > utf16_len(line):
        return None
    allowed = set("abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789_.")
    position_character = utf16_col_to_utf8(line, position.character)
    start = position_character
    while start > 0 and line[start - 1] in allowed:
        start -= 1
    end = position_character
    while end < len(line) and line[end] in allowed:
        end += 1
    token = line[start:end]
    if token.count(".") != 1:
        return None
    left, right = token.split(".", 1)
    if not left or not right:
        return None
    return token, Range(
        start=Position(line=position.line, character=utf8_col_to_utf16(line, start)),
        end=Position(line=position.line, character=utf8_col_to_utf16(line, end)),
    )
