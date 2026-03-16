"""Workspace symbol queries for the LSP runtime."""

from __future__ import annotations

from typing import TYPE_CHECKING

from lsprotocol.types import SymbolInformation

from yaraast.lsp.document_types import SymbolRecord

if TYPE_CHECKING:
    from yaraast.lsp.runtime import LspRuntime


def workspace_symbols(runtime: LspRuntime, query: str) -> list[SymbolInformation]:
    query_lower = query.lower()
    return [
        record.to_symbol_information()
        for record in workspace_symbol_records(runtime, query)
        if not query or query_lower in record.name.lower()
    ]


def workspace_symbol_records(runtime: LspRuntime, query: str = "") -> list[SymbolRecord]:
    cache_key = (runtime._workspace_generation, query)
    cached = runtime._workspace_symbol_cache.get(cache_key)
    if cached is not None:
        return list(cached)
    query_lower = query.lower()
    open_uris = set(runtime.documents)
    records: list[SymbolRecord] = []
    hidden_kinds = {"rule_block", "section_header"}
    for uri in list(runtime._dirty_documents):
        runtime._sync_document_to_index(uri)
    for doc in runtime.documents.values():
        for record in doc.symbols():
            if record.kind in hidden_kinds:
                continue
            if query and query_lower not in record.name.lower():
                continue
            records.append(record)
    persisted = runtime.index.search_records(query, exclude_uris=open_uris)
    records.extend(record for record in persisted if record.kind not in hidden_kinds)
    runtime._workspace_symbol_cache[cache_key] = list(records)
    return records
