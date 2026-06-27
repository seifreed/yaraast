"""Benchmark helpers for CLI (logic without IO)."""

from __future__ import annotations

from pathlib import Path

_BENCHMARK_OPERATIONS = frozenset({"all", "codegen", "parse", "roundtrip"})
_SINGLE_BENCHMARK_OPERATIONS = frozenset({"codegen", "parse", "roundtrip"})


def _determine_operations_to_run(operations: object) -> list[str]:
    """Determine which operations to run based on input."""
    operations = _require_benchmark_operation(operations)
    if operations == "all":
        return ["parse", "codegen", "roundtrip"]
    if operations == "roundtrip":
        return ["roundtrip"]
    return [operations]


def _run_single_operation(benchmarker, file_path: Path, op: object, iterations: int):
    """Run a single benchmark operation."""
    op = _require_single_benchmark_operation(op)
    if op == "parse":
        return benchmarker.benchmark_parsing(file_path, iterations)
    if op == "codegen":
        return benchmarker.benchmark_codegen(file_path, iterations)
    results = benchmarker.benchmark_roundtrip(file_path, iterations)
    return results[0] if results else None


def _require_benchmark_operation(operations: object) -> str:
    if not isinstance(operations, str):
        raise TypeError("benchmark operation must be a string")
    if operations not in _BENCHMARK_OPERATIONS:
        valid = ", ".join(sorted(_BENCHMARK_OPERATIONS))
        raise ValueError(f"benchmark operation must be one of: {valid}")
    return operations


def _require_single_benchmark_operation(op: object) -> str:
    if not isinstance(op, str):
        raise TypeError("benchmark operation must be a string")
    if op not in _SINGLE_BENCHMARK_OPERATIONS:
        valid = ", ".join(sorted(_SINGLE_BENCHMARK_OPERATIONS))
        raise ValueError(f"benchmark operation must be one of: {valid}")
    return op

