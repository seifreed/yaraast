"""Section and child symbol builders for LSP document symbols."""

from __future__ import annotations

from typing import TYPE_CHECKING, Any

from lsprotocol.types import Position, Range

from yaraast.ast.base import ASTNode
from yaraast.lsp.document_symbol_ranges import node_range, node_value_range
from yaraast.lsp.document_types import SymbolRecord
from yaraast.lsp.structure import (
    find_line_containing,
    find_section_header_range,
    find_section_range,
    find_string_line,
    make_range,
)

if TYPE_CHECKING:
    from yaraast.lsp.document_context import DocumentContext


def append_meta_symbols(
    ctx: DocumentContext,
    symbols: list[SymbolRecord],
    lines: list[str],
    rule: Any,
    rule_name: str,
    rule_block_range: Range,
) -> None:
    meta = getattr(rule, "meta", None)
    if not meta:
        return
    meta_header_range = find_section_header_in_rule(lines, "meta", rule_block_range)
    if meta_header_range is not None:
        meta_range = section_content_range(meta_header_range, meta_item_ranges(rule, ctx.text))
        if meta_range is None:
            meta_line = meta_header_range.start.line
            meta_range = find_section_range(
                lines, "meta", rule_block_range.start.line, rule_block_range.end.line
            )
            if meta_range is None:
                meta_range = make_range(meta_line, 0, len(lines[meta_line]))
        symbols.append(SymbolRecord("meta", "section", ctx.uri, meta_range, rule_name))
        symbols.append(
            SymbolRecord("meta", "section_header", ctx.uri, meta_header_range, rule_name)
        )
    if isinstance(meta, list):
        items = ((getattr(m, "key", ""), getattr(m, "value", "")) for m in meta)
    elif hasattr(meta, "entries"):
        items = ((entry.key, entry.value) for entry in getattr(meta, "entries", []))
    else:
        items = iter([])
    for key, _value in items:
        key_text = str(key)
        key_range = meta_item_range(meta, key_text, ctx.text)
        if key_range is None:
            line_num = find_line_containing(lines, f"{key} =", rule_block_range.start.line)
            if line_num >= 0:
                key_start = lines[line_num].find(key_text)
                key_range = (
                    make_range(line_num, key_start, key_start + len(key_text))
                    if key_start >= 0
                    else make_range(line_num, 0, len(lines[line_num]))
                )
        if key_range is not None:
            symbols.append(SymbolRecord(key_text, "meta", ctx.uri, key_range, rule_name))


def append_string_symbols(
    ctx: DocumentContext,
    symbols: list[SymbolRecord],
    lines: list[str],
    rule: Any,
    rule_name: str,
    rule_block_range: Range,
    source_text: str,
) -> None:
    strings_header_range = find_section_header_in_rule(lines, "strings", rule_block_range)
    if strings_header_range is not None:
        strings_range = section_content_range(
            strings_header_range,
            [node_range(string_def, source_text) for string_def in getattr(rule, "strings", [])],
        )
        if strings_range is None:
            strings_line = strings_header_range.start.line
            strings_range = find_section_range(
                lines, "strings", rule_block_range.start.line, rule_block_range.end.line
            )
            if strings_range is None:
                strings_range = make_range(strings_line, 0, len(lines[strings_line]))
        symbols.append(SymbolRecord("strings", "section", ctx.uri, strings_range, rule_name))
        symbols.append(
            SymbolRecord("strings", "section_header", ctx.uri, strings_header_range, rule_name)
        )
    for string_def in getattr(rule, "strings", []):
        string_id = getattr(string_def, "identifier", None)
        if not string_id:
            continue
        string_range = node_value_range(string_def, source_text, string_id)
        if string_range is None:
            line_num = find_string_line(lines, string_id, rule_block_range.start.line)
            if line_num >= 0:
                start = lines[line_num].find(string_id)
                string_range = make_range(line_num, start, start + len(string_id))
        if string_range is not None:
            symbols.append(SymbolRecord(string_id, "string", ctx.uri, string_range, rule_name))


def append_condition_symbols(
    ctx: DocumentContext,
    symbols: list[SymbolRecord],
    lines: list[str],
    rule: Any,
    rule_name: str,
    rule_block_range: Range,
    source_text: str,
) -> None:
    cond_header_range = find_section_header_in_rule(lines, "condition", rule_block_range)
    if cond_header_range is None:
        return
    condition_node_range = node_range(getattr(rule, "condition", None), source_text)
    condition_range = section_content_range(cond_header_range, [condition_node_range])
    if condition_range is None:
        cond_line = cond_header_range.start.line
        condition_range = find_section_range(
            lines, "condition", rule_block_range.start.line, rule_block_range.end.line
        )
        if condition_range is None:
            condition_range = make_range(cond_line, 0, len(lines[cond_line]))
    symbols.append(SymbolRecord("condition", "section", ctx.uri, condition_range, rule_name))
    symbols.append(
        SymbolRecord("condition", "section_header", ctx.uri, cond_header_range, rule_name)
    )
    symbols.append(SymbolRecord("condition", "condition", ctx.uri, condition_range, rule_name))


def append_extra_section_symbols(
    ctx: DocumentContext,
    symbols: list[SymbolRecord],
    lines: list[str],
    rule: Any,
    rule_name: str,
    rule_block_range: Range,
    source_text: str,
) -> None:
    for section_name in ("events", "match", "outcome", "options"):
        section = getattr(rule, section_name, None)
        if section is None:
            continue
        section_header_range = find_section_header_in_rule(lines, section_name, rule_block_range)
        if section_header_range is None:
            continue
        section_range = section_content_range(
            section_header_range, [node_range(section, source_text)]
        )
        if section_range is None:
            section_line = section_header_range.start.line
            section_range = find_section_range(
                lines, section_name, rule_block_range.start.line, rule_block_range.end.line
            )
            if section_range is None:
                section_range = make_range(section_line, 0, len(lines[section_line]))
        symbols.append(SymbolRecord(section_name, "section", ctx.uri, section_range, rule_name))
        symbols.append(
            SymbolRecord(section_name, "section_header", ctx.uri, section_header_range, rule_name)
        )


def find_section_header_in_rule(
    lines: list[str], section_name: str, rule_block_range: Range
) -> Range | None:
    for line_num in range(
        rule_block_range.start.line, min(rule_block_range.end.line, len(lines) - 1) + 1
    ):
        line = lines[line_num]
        start = line.find(section_name)
        if start >= 0 and line[start:].startswith(f"{section_name}:"):
            return find_section_header_range(lines, section_name, line_num)
    return None


def section_content_range(header_range: Range, content_ranges: list[Range | None]) -> Range | None:
    actual_ranges = [range_ for range_ in content_ranges if range_ is not None]
    if not actual_ranges:
        return None
    end_range = max(actual_ranges, key=lambda range_: (range_.end.line, range_.end.character))
    return Range(start=Position(line=header_range.start.line, character=0), end=end_range.end)


def meta_item_ranges(rule: Any, source_text: str) -> list[Range | None]:
    meta = getattr(rule, "meta", None)
    if isinstance(meta, list):
        return [node_range(item, source_text) for item in meta if isinstance(item, ASTNode)]
    if hasattr(meta, "entries"):
        return [
            node_range(entry, source_text)
            for entry in getattr(meta, "entries", [])
            if isinstance(entry, ASTNode)
        ]
    return []


def meta_item_range(meta: Any, key: str, source_text: str) -> Range | None:
    if isinstance(meta, list):
        for item in meta:
            if isinstance(item, ASTNode) and getattr(item, "key", None) == key:
                return node_value_range(item, source_text, key)
    if hasattr(meta, "entries"):
        for entry in getattr(meta, "entries", []):
            if isinstance(entry, ASTNode) and getattr(entry, "key", None) == key:
                return node_value_range(entry, source_text, key)
    return None
