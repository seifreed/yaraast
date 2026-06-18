"""Workspace symbol queries for the LSP runtime."""

from __future__ import annotations

import logging
from typing import TYPE_CHECKING

from lsprotocol.types import SymbolInformation

from yaraast.lsp.document_types import SymbolRecord, require_workspace_symbol_query
from yaraast.parser._shared import ParserError

logger = logging.getLogger(__name__)

if TYPE_CHECKING:
    from yaraast.lsp.runtime import LspRuntime


def workspace_symbols(runtime: LspRuntime, query: object) -> list[SymbolInformation]:
    query = require_workspace_symbol_query(query)
    query_lower = query.lower()
    return [
        record.to_symbol_information()
        for record in workspace_symbol_records(runtime, query)
        if not query or query_lower in record.name.lower()
    ]


def workspace_symbol_records(runtime: LspRuntime, query: object = "") -> list[SymbolRecord]:
    query = require_workspace_symbol_query(query)
    if not runtime.config.cache_workspace:
        return _uncached_workspace_symbol_records(runtime, query)
    cache_key = (runtime.cache.generation, query)
    cached = runtime.cache.workspace_symbol_cache.get(cache_key)
    if cached is not None:
        return list(cached)
    query_lower = query.lower()
    open_uris = set(runtime.documents)
    records: list[SymbolRecord] = []
    hidden_kinds = {"rule_block", "section_header"}
    for uri in list(runtime._dirty_documents):
        runtime._sync_document_to_index(uri)
    for doc in runtime.documents.values():
        try:
            doc_symbols = doc.symbols()
        except Exception:
            logger.debug("Operation failed in %s", __name__, exc_info=True)
            continue
        parse_error = doc.parse_error()
        trailing_names = _trailing_parse_error_symbol_names(doc_symbols, parse_error)
        for record in doc_symbols:
            if record.kind in hidden_kinds:
                continue
            if _skip_trailing_parse_error_symbol(record, parse_error, trailing_names):
                continue
            if query and query_lower not in record.name.lower():
                continue
            records.append(record)
    persisted = runtime.index.search_records(query, exclude_uris=open_uris)
    records.extend(record for record in persisted if record.kind not in hidden_kinds)
    runtime.cache.workspace_symbol_cache[cache_key] = list(records)
    return records


def _uncached_workspace_symbol_records(runtime: LspRuntime, query: str) -> list[SymbolRecord]:
    query_lower = query.lower()
    hidden_kinds = {"rule_block", "section_header"}
    records: list[SymbolRecord] = []
    for doc in runtime.iter_workspace_documents():
        try:
            doc_symbols = doc.symbols()
        except Exception:
            logger.debug("Operation failed in %s", __name__, exc_info=True)
            continue
        parse_error = doc.parse_error()
        trailing_names = _trailing_parse_error_symbol_names(doc_symbols, parse_error)
        for record in doc_symbols:
            if record.kind in hidden_kinds:
                continue
            if _skip_trailing_parse_error_symbol(record, parse_error, trailing_names):
                continue
            if query and query_lower not in record.name.lower():
                continue
            records.append(record)
    return records


def _trailing_parse_error_symbol_names(
    doc_symbols: list[SymbolRecord], parse_error: Exception | None
) -> set[str]:
    if not isinstance(parse_error, ParserError):
        return set()
    token = getattr(parse_error, "token", None)
    if getattr(token, "value", object()) is not None:
        return set()
    error_line = getattr(parse_error, "line", None)
    if not isinstance(error_line, int):
        return set()
    trailing_names: set[str] = set()
    for record in doc_symbols:
        if record.kind == "rule":
            continue
        if record.range.end.line >= error_line - 1:
            trailing_names.add(record.name)
    return trailing_names


def _skip_trailing_parse_error_symbol(
    record: SymbolRecord,
    parse_error: Exception | None,
    trailing_names: set[str],
) -> bool:
    if not isinstance(parse_error, ParserError):
        return False
    token = getattr(parse_error, "token", None)
    if getattr(token, "value", object()) is not None:
        return False
    error_line = getattr(parse_error, "line", None)
    if not isinstance(error_line, int):
        return False
    if record.kind == "rule":
        return record.name in trailing_names
    return record.range.end.line >= error_line - 1 and record.name in trailing_names
