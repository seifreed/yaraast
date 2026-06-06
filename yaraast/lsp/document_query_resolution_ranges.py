"""Range helpers for AST-driven LSP symbol resolution."""

from __future__ import annotations

from typing import TYPE_CHECKING

from lsprotocol.types import Position, Range

from yaraast.lsp.document_types import ResolvedSymbol
from yaraast.lsp.utf16 import utf8_col_to_utf16, utf16_col_to_utf8

if TYPE_CHECKING:
    from yaraast.lsp.document_context import DocumentContext


def narrow_range_to_name(ctx: DocumentContext, node_range: Range, name: str) -> Range:
    if not name:
        return node_range
    line = ctx.lines[node_range.start.line] if 0 <= node_range.start.line < len(ctx.lines) else ""
    source_start = utf16_col_to_utf8(line, node_range.start.character)
    start = line.find(name, max(0, source_start - 1))
    if start < 0:
        return node_range
    end = start + len(name)
    return Range(
        start=Position(
            line=node_range.start.line,
            character=utf8_col_to_utf16(line, start),
        ),
        end=Position(
            line=node_range.start.line,
            character=utf8_col_to_utf16(line, end),
        ),
    )


def range_contains_position(range_obj: Range, position: Position) -> bool:
    if position.line < range_obj.start.line or position.line > range_obj.end.line:
        return False
    if position.line == range_obj.start.line and position.character < range_obj.start.character:
        return False
    return not (
        position.line == range_obj.end.line and position.character >= range_obj.end.character
    )


def resolved_if_contains(position: Position, resolved: ResolvedSymbol) -> ResolvedSymbol | None:
    if range_contains_position(resolved.range, position):
        return resolved
    return None
