"""Executor-based helpers for ParallelAnalyzer."""

from __future__ import annotations

import concurrent.futures
import multiprocessing as mp
import time
from typing import TYPE_CHECKING, Any

from yaraast.performance.validation import (
    validate_file_path_sequence,
    validate_positive_int_setting,
)

if TYPE_CHECKING:
    from collections.abc import Callable

    from yaraast.ast.rules import Rule
    from yaraast.performance.parallel_analyzer import ParallelAnalyzer


def _resolve_worker_count(analyzer: ParallelAnalyzer, max_workers: int | None) -> int:
    worker_count = analyzer.max_workers if max_workers is None else max_workers
    validate_positive_int_setting(worker_count, "max_workers")
    return worker_count


def analyze_rules(
    analyzer: ParallelAnalyzer,
    rules: list[Rule],
    max_workers: int | None = None,
) -> list[dict[str, Any]]:
    """Analyze multiple rules with a process pool."""
    worker_count = _resolve_worker_count(analyzer, max_workers)
    ordered_results: list[dict[str, Any] | None] = [None] * len(rules)
    start_time = time.time()
    rules_analyzed = 0
    errors = 0

    with concurrent.futures.ProcessPoolExecutor(max_workers=worker_count) as executor:
        future_to_rule = {
            executor.submit(analyzer._analyze_single_rule, rule): (index, rule)
            for index, rule in enumerate(rules)
        }
        for future in concurrent.futures.as_completed(future_to_rule):
            index, rule = future_to_rule[future]
            try:
                result = future.result()
                ordered_results[index] = result
                rules_analyzed += 1
            except Exception as exc:
                rule_name = getattr(rule, "name", str(rule))
                ordered_results[index] = {"rule": rule_name, "error": str(exc), "analysis": None}
                errors += 1

    # Update stats atomically after all futures complete
    analyzer._stats["rules_analyzed"] += rules_analyzed
    analyzer._stats["errors"] += errors
    analyzer._stats["total_time"] = time.time() - start_time
    return [result for result in ordered_results if result is not None]


def batch_analyze_files(
    analyzer: ParallelAnalyzer,
    file_paths: list[str],
    max_workers: int | None = None,
) -> list[dict[str, Any]]:
    """Analyze multiple files with a thread pool."""
    normalized_file_paths = validate_file_path_sequence(file_paths)
    worker_count = _resolve_worker_count(analyzer, max_workers)
    ordered_results: list[dict[str, Any] | None] = [None] * len(normalized_file_paths)
    with concurrent.futures.ThreadPoolExecutor(max_workers=worker_count) as executor:
        future_to_path = {
            executor.submit(analyzer._analyze_file_path, path): (index, path)
            for index, path in enumerate(normalized_file_paths)
        }
        for future in concurrent.futures.as_completed(future_to_path):
            index, path = future_to_path[future]
            try:
                ordered_results[index] = future.result()
            except Exception as exc:
                ordered_results[index] = {"file": path, "error": str(exc), "analysis": None}
    return [result for result in ordered_results if result is not None]


def analyze_with_custom_function(
    analyzer: ParallelAnalyzer,
    rules: list[Rule],
    analyze_func: Callable[[Rule], Any],
    max_workers: int | None = None,
) -> list[Any]:
    """Run a custom rule analysis across a process pool."""
    worker_count = _resolve_worker_count(analyzer, max_workers)
    results: list[Any] = [None] * len(rules)
    with concurrent.futures.ProcessPoolExecutor(max_workers=worker_count) as executor:
        future_to_index = {
            executor.submit(analyze_func, rule): index for index, rule in enumerate(rules)
        }
        for future in concurrent.futures.as_completed(future_to_index):
            index = future_to_index[future]
            try:
                results[index] = future.result()
            except Exception as exc:
                results[index] = {"error": str(exc)}
    return results


def profile_performance(
    analyzer: ParallelAnalyzer,
    rules: list[Rule],
    worker_counts: list[int] | None = None,
) -> dict[str, Any]:
    """Measure analyze_rules throughput across worker counts."""
    if worker_counts is None:
        worker_counts = [1, 2, 4, 8, mp.cpu_count()]

    results = {}
    for workers in worker_counts:
        if not isinstance(workers, int) or isinstance(workers, bool):
            msg = "worker_counts must contain integers"
            raise TypeError(msg)
        if workers < 1:
            msg = "worker_counts must contain values at least 1"
            raise ValueError(msg)
        if workers > mp.cpu_count():
            continue
        start_time = time.time()
        analyzer.analyze_rules(rules, max_workers=workers)
        elapsed = time.time() - start_time
        results[workers] = {
            "time": elapsed,
            "rules_per_second": len(rules) / elapsed if elapsed > 0 else 0,
        }

    if not results:
        return {
            "worker_performance": {},
            "optimal_workers": None,
            "rule_count": len(rules),
        }

    return {
        "worker_performance": results,
        "optimal_workers": min(results, key=lambda key: results[key]["time"]),
        "rule_count": len(rules),
    }
