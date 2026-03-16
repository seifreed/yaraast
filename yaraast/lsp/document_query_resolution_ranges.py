"""Range helpers for AST-driven LSP symbol resolution."""

from __future__ import annotations

from yaraast.lsp.document_types import ResolvedSymbol
from yaraast.lsp.structure import make_range


def narrow_range_to_name(ctx, node_range, name: str):
    line = ctx.lines[node_range.start.line] if 0 <= node_range.start.line < len(ctx.lines) else ""
    start = line.find(name, max(0, node_range.start.character - 1))
    if start < 0:
        return node_range
    return make_range(node_range.start.line, start, start + len(name))


def range_contains_position(range_obj, position) -> bool:
    if position.line < range_obj.start.line or position.line > range_obj.end.line:
        return False
    if position.line == range_obj.start.line and position.character < range_obj.start.character:
        return False
    return not (
        position.line == range_obj.end.line and position.character > range_obj.end.character
    )


def resolved_if_contains(position, resolved: ResolvedSymbol) -> ResolvedSymbol | None:
    if range_contains_position(resolved.range, position):
        return resolved
    return None
