"""Debounce and status helpers for the LSP runtime."""

from __future__ import annotations

from collections import deque
import math
import time
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from yaraast.lsp.runtime import LspRuntime


def _require_observability_text(value: object, field_name: str) -> str:
    if not isinstance(value, str):
        msg = f"{field_name} must be a string"
        raise TypeError(msg)
    return value


def _require_debounce_threshold(value: object) -> int | None:
    if value is None:
        return None
    if isinstance(value, bool) or not isinstance(value, int):
        msg = "Debounce threshold must be an integer or None"
        raise TypeError(msg)
    if value < 0:
        msg = "Debounce threshold must be non-negative"
        raise ValueError(msg)
    return value


def _require_latency_duration(value: object) -> float:
    if isinstance(value, bool) or not isinstance(value, int | float):
        msg = "Latency duration must be numeric"
        raise TypeError(msg)
    duration = float(value)
    if not math.isfinite(duration):
        msg = "Latency duration must be finite"
        raise ValueError(msg)
    if duration < 0:
        msg = "Latency duration must be non-negative"
        raise ValueError(msg)
    return duration


def should_debounce(
    runtime: LspRuntime,
    uri: str,
    task: str,
    *,
    debounce_ms: int | None = None,
) -> bool:
    uri = _require_observability_text(uri, "Debounce URI")
    task = _require_observability_text(task, "Debounce task")
    explicit_threshold = _require_debounce_threshold(debounce_ms)
    threshold = (
        runtime.config.diagnostics_debounce_ms if explicit_threshold is None else explicit_threshold
    )
    if threshold <= 0:
        return False
    key = (uri, task)
    now = time.perf_counter() * 1000.0
    previous = runtime._task_timestamps.get(key)
    runtime._task_timestamps[key] = now
    return previous is not None and (now - previous) < threshold


def record_latency(runtime: LspRuntime, operation: str, duration_ms: float) -> None:
    operation = _require_observability_text(operation, "Latency operation")
    duration = _require_latency_duration(duration_ms)
    samples = runtime._latency.setdefault(operation, deque(maxlen=50))
    samples.append(duration)


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
            "workspace_generation": runtime.cache.generation,
            "workspace_symbol_queries": len(runtime.cache.workspace_symbol_cache),
            "rule_definition_entries": len(runtime.cache.rule_definition_cache),
            "rule_reference_entries": len(runtime.cache.rule_references_cache),
            "rule_reference_record_entries": len(runtime.cache.rule_reference_records_cache),
            "document_analysis_entries": document_cache_entries,
        },
        "latency": get_latency_metrics(runtime),
    }
