"""Executor-based helpers for ParallelAnalyzer."""

from __future__ import annotations

import concurrent.futures
import multiprocessing as mp
import time
from typing import TYPE_CHECKING, Any

if TYPE_CHECKING:
    from collections.abc import Callable

    from yaraast.ast.rules import Rule
    from yaraast.performance.parallel_analyzer import ParallelAnalyzer


def analyze_rules(
    analyzer: ParallelAnalyzer,
    rules: list[Rule],
    max_workers: int | None = None,
) -> list[dict[str, Any]]:
    """Analyze multiple rules with a process pool."""
    worker_count = max_workers or analyzer.max_workers
    results = []
    start_time = time.time()
    rules_analyzed = 0
    errors = 0

    with concurrent.futures.ProcessPoolExecutor(max_workers=worker_count) as executor:
        future_to_rule = {
            executor.submit(analyzer._analyze_single_rule, rule): rule for rule in rules
        }
        for future in concurrent.futures.as_completed(future_to_rule):
            rule = future_to_rule[future]
            try:
                result = future.result()
                results.append(result)
                rules_analyzed += 1
            except Exception as exc:
                rule_name = getattr(rule, "name", str(rule))
                results.append({"rule": rule_name, "error": str(exc), "analysis": None})
                errors += 1

    # Update stats atomically after all futures complete
    analyzer._stats["rules_analyzed"] += rules_analyzed
    analyzer._stats["errors"] += errors
    analyzer._stats["total_time"] = time.time() - start_time
    return results


def batch_analyze_files(
    analyzer: ParallelAnalyzer,
    file_paths: list[str],
    max_workers: int | None = None,
) -> list[dict[str, Any]]:
    """Analyze multiple files with a thread pool."""
    worker_count = max_workers or analyzer.max_workers
    results = []
    with concurrent.futures.ThreadPoolExecutor(max_workers=worker_count) as executor:
        future_to_path = {
            executor.submit(analyzer._analyze_file_path, path): path for path in file_paths
        }
        for future in concurrent.futures.as_completed(future_to_path):
            path = future_to_path[future]
            try:
                results.append(future.result())
            except Exception as exc:
                results.append({"file": path, "error": str(exc), "analysis": None})
    return results


def analyze_with_custom_function(
    analyzer: ParallelAnalyzer,
    rules: list[Rule],
    analyze_func: Callable[[Rule], Any],
    max_workers: int | None = None,
) -> list[Any]:
    """Run a custom rule analysis across a process pool."""
    worker_count = max_workers or analyzer.max_workers
    results = []
    with concurrent.futures.ProcessPoolExecutor(max_workers=worker_count) as executor:
        futures = [executor.submit(analyze_func, rule) for rule in rules]
        for future in concurrent.futures.as_completed(futures):
            try:
                results.append(future.result())
            except Exception as exc:
                results.append({"error": str(exc)})
    return results


def profile_performance(
    analyzer: ParallelAnalyzer,
    rules: list[Rule],
    worker_counts: list[int] | None = None,
) -> dict[str, Any]:
    """Measure analyze_rules throughput across worker counts."""
    if not worker_counts:
        worker_counts = [1, 2, 4, 8, mp.cpu_count()]

    results = {}
    for workers in worker_counts:
        if workers > mp.cpu_count():
            continue
        start_time = time.time()
        analyzer.analyze_rules(rules, max_workers=workers)
        elapsed = time.time() - start_time
        results[workers] = {
            "time": elapsed,
            "rules_per_second": len(rules) / elapsed if elapsed > 0 else 0,
        }

    return {
        "worker_performance": results,
        "optimal_workers": min(results, key=lambda key: results[key]["time"]),
        "rule_count": len(rules),
    }
