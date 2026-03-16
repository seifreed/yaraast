"""Symbol resolution helpers for LSP document contexts."""

from __future__ import annotations

from typing import TYPE_CHECKING

from lsprotocol.types import Position

from yaraast.lsp.document_query_resolution_ast import resolve_symbol_from_ast
from yaraast.lsp.document_query_resolution_symbol_records import (
    prefer_symbol_resolution,
    resolve_symbol_from_symbol_records,
)
from yaraast.lsp.document_query_resolution_text import resolve_symbol_from_text_fallback
from yaraast.lsp.document_types import ResolvedSymbol

if TYPE_CHECKING:
    from yaraast.lsp.document_context import DocumentContext


def resolve_symbol(ctx: DocumentContext, position: Position) -> ResolvedSymbol | None:
    cache_key = f"resolve_symbol:{position.line}:{position.character}"
    cached = ctx.get_cached(cache_key)
    if cached is not None:
        return cached
    ast_resolved = resolve_symbol_from_ast(ctx, position)
    symbol_resolved = resolve_symbol_from_symbol_records(ctx, position)
    if symbol_resolved is not None and prefer_symbol_resolution(symbol_resolved, ast_resolved):
        ctx.set_cached(cache_key, symbol_resolved)
        return symbol_resolved
    if ast_resolved is not None:
        ctx.set_cached(cache_key, ast_resolved)
        return ast_resolved
    result = resolve_symbol_from_text_fallback(
        ctx,
        position,
        allow_generic_identifier=True,
    )
    if result is None:
        return None
    ctx.set_cached(cache_key, result)
    return result
