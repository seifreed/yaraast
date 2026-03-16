"""Benchmark helpers for CLI (logic without IO)."""

from __future__ import annotations

from pathlib import Path


def _run_benchmarks_for_all_files(
    benchmarker,
    file_paths: list[Path],
    operations: str,
    iterations: int,
) -> list[dict]:
    """Run benchmarks for all files and return results."""
    all_results = []

    for file_path in file_paths:
        # Reporting is handled in bench_cmd/bench_reporting.
        file_results = _run_benchmarks_for_single_file(
            benchmarker, file_path, operations, iterations
        )

        all_results.append(
            {
                "file": str(file_path),
                "file_name": file_path.name,
                "results": file_results,
            }
        )

    return all_results


def _run_benchmarks_for_single_file(
    benchmarker,
    file_path: Path,
    operations: str,
    iterations: int,
) -> dict:
    """Run benchmarks for a single file."""
    ops_to_run = _determine_operations_to_run(operations)
    file_results = {}

    for op in ops_to_run:
        result = _run_single_operation(benchmarker, file_path, op, iterations)
        if result and result.success:
            file_results[op] = result

    return file_results


def _determine_operations_to_run(operations: str) -> list[str]:
    """Determine which operations to run based on input."""
    if operations == "all":
        return ["parse", "codegen", "roundtrip"]
    if operations == "roundtrip":
        return ["roundtrip"]
    return [operations]


def _run_single_operation(benchmarker, file_path: Path, op: str, iterations: int):
    """Run a single benchmark operation."""
    if op == "parse":
        return benchmarker.benchmark_parsing(file_path, iterations)
    if op == "codegen":
        return benchmarker.benchmark_codegen(file_path, iterations)
    if op == "roundtrip":
        results = benchmarker.benchmark_roundtrip(file_path, iterations)
        return results[0] if results else None
    return None


def _get_benchmark_summary(benchmarker) -> dict:
    """Return benchmark summary data."""
    return benchmarker.get_benchmark_summary()
