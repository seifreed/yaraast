"""Symbol-record based resolution helpers for LSP."""

from __future__ import annotations

from yaraast.lsp.document_types import ResolvedSymbol


def resolve_symbol_from_symbol_records(ctx, position) -> ResolvedSymbol | None:
    best_result: ResolvedSymbol | None = None
    best_span: int | None = None
    for symbol in ctx.symbols():
        if not _symbol_contains_position(symbol, position):
            continue
        kind = {
            "string": "string",
            "rule": "rule",
            "import": "module",
            "include": "include",
            "meta": "meta",
            "section_header": "section",
        }.get(symbol.kind)
        if kind is None:
            continue
        span = range_span_size(symbol.range)
        if best_span is None or span < best_span:
            best_span = span
            best_result = ResolvedSymbol(ctx.uri, symbol.name, symbol.name, kind, symbol.range)
    return best_result


def prefer_symbol_resolution(
    symbol_resolved: ResolvedSymbol, ast_resolved: ResolvedSymbol | None
) -> bool:
    if ast_resolved is None:
        return True
    if (
        symbol_resolved.kind in {"string", "module", "include", "meta", "section"}
        and ast_resolved.kind == "rule"
    ):
        return True
    symbol_span = range_span_size(symbol_resolved.range)
    ast_span = range_span_size(ast_resolved.range)
    if symbol_span < ast_span:
        return True
    return bool(symbol_span == ast_span and symbol_resolved.kind != ast_resolved.kind)


def range_span_size(range_obj) -> int:
    return ((range_obj.end.line - range_obj.start.line) * 10_000) + max(
        1,
        range_obj.end.character - range_obj.start.character,
    )


def _symbol_contains_position(symbol, position) -> bool:
    if not (symbol.range.start.line <= position.line <= symbol.range.end.line):
        return False
    if (
        position.line == symbol.range.start.line
        and position.character < symbol.range.start.character
    ):
        return False
    return not (
        position.line == symbol.range.end.line and position.character > symbol.range.end.character
    )
