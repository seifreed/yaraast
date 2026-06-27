"""Workspace symbol queries for the LSP runtime."""

from __future__ import annotations

import logging
from typing import TYPE_CHECKING

from lsprotocol.types import SymbolInformation

from yaraast.lsp.document_types import SymbolRecord, require_workspace_symbol_query

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
        for record in doc_symbols:
            if record.kind in hidden_kinds:
                continue
            if query and query_lower not in record.name.lower():
                continue
            records.append(record)
    for uri, symbols in runtime.index.persisted_symbols.items():
        if uri in open_uris:
            continue
        if runtime.index.workspace_folders and runtime.index._workspace_root_for_uri(uri) is None:
            continue
        for record in symbols:
            if record.kind in hidden_kinds:
                continue
            if query and query_lower not in record.name.lower():
                continue
            records.append(record)
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
        for record in doc_symbols:
            if record.kind in hidden_kinds:
                continue
            if query and query_lower not in record.name.lower():
                continue
            records.append(record)
    return records
