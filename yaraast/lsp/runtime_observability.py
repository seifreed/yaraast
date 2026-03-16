"""Debounce and status helpers for the LSP runtime."""

from __future__ import annotations

import time
from collections import deque
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from yaraast.lsp.runtime import LspRuntime


def should_debounce(
    runtime: LspRuntime,
    uri: str,
    task: str,
    *,
    debounce_ms: int | None = None,
) -> bool:
    threshold = runtime.config.diagnostics_debounce_ms if debounce_ms is None else debounce_ms
    if threshold <= 0:
        return False
    key = (uri, task)
    now = time.perf_counter() * 1000.0
    previous = runtime._task_timestamps.get(key)
    runtime._task_timestamps[key] = now
    return previous is not None and (now - previous) < threshold


def record_latency(runtime: LspRuntime, operation: str, duration_ms: float) -> None:
    samples = runtime._latency.setdefault(operation, deque(maxlen=50))
    samples.append(duration_ms)


def get_latency_metrics(runtime: LspRuntime) -> dict[str, dict[str, float]]:
    metrics: dict[str, dict[str, float]] = {}
    for operation, samples in runtime._latency.items():
        if not samples:
            continue
        values = list(samples)
        metrics[operation] = {
            "count": float(len(values)),
            "avg_ms": sum(values) / len(values),
            "max_ms": max(values),
            "min_ms": min(values),
        }
    return metrics


def get_status(runtime: LspRuntime) -> dict[str, object]:
    cache_path = runtime.index._cache_path()
    document_cache_entries = sum(len(doc._analysis_cache) for doc in runtime.documents.values())
    return {
        "open_documents": len([doc for doc in runtime.documents.values() if doc.is_open]),
        "cached_documents": len(runtime.documents),
        "workspace_symbols": sum(
            len(symbols) for symbols in runtime.index.persisted_symbols.values()
        ),
        "dirty_documents": len(runtime._dirty_documents),
        "cache_workspace": runtime.config.cache_workspace,
        "language_mode": runtime.config.language_mode.value,
        "workspace_folders": [str(path) for path in runtime.index.workspace_folders],
        "index_path": str(cache_path) if cache_path is not None else None,
        "cache_stats": {
            "workspace_generation": runtime._workspace_generation,
            "workspace_symbol_queries": len(runtime._workspace_symbol_cache),
            "rule_definition_entries": len(runtime._rule_definition_cache),
            "rule_reference_entries": len(runtime._rule_references_cache),
            "rule_reference_record_entries": len(runtime._rule_reference_records_cache),
            "document_analysis_entries": document_cache_entries,
        },
        "latency": get_latency_metrics(runtime),
    }
