"""AST benchmarking utilities for CLI."""

from __future__ import annotations

from dataclasses import dataclass
from os import PathLike, fspath
from pathlib import Path
import statistics
import time
from typing import Any

from yaraast.ast.base import ASTNode, YaraFile
from yaraast.cli.utils import _path_exists_and_is_dir
from yaraast.parser.source import parse_yara_source
from yaraast.shared.numeric_validation import validate_positive_int_setting
from yaraast.yarax.generator import YaraXGenerator


def _require_benchmark_file_path(file_path: object) -> Path:
    if isinstance(file_path, bool | bytes) or not isinstance(file_path, str | PathLike):
        msg = "file_path must be a string or path-like object"
        raise TypeError(msg)
    raw_path = fspath(file_path)
    if not isinstance(raw_path, str):
        msg = "file_path must be a string or path-like object"
        raise TypeError(msg)
    if not raw_path.strip():
        msg = "file_path must not be empty"
        raise ValueError(msg)
    path = Path(raw_path)
    if _path_exists_and_is_dir(path):
        msg = "file_path must not be a directory"
        raise ValueError(msg)
    return path


def _read_benchmark_yara_text(file_path: object) -> str:
    try:
        with _require_benchmark_file_path(file_path).open(encoding="utf-8") as f:
            return f.read()
    except UnicodeDecodeError as exc:
        msg = "YARA file must contain valid UTF-8 text"
        raise ValueError(msg) from exc


@dataclass
class BenchmarkResult:
    """Result of performance benchmark."""

    operation: str
    file_size: int
    execution_time: float
    rules_count: int
    strings_count: int
    ast_nodes: int
    memory_usage: int | None = None
    success: bool = True
    error: str | None = None


class ASTBenchmarker:
    """Performance benchmarking for AST operations."""

    def __init__(self) -> None:
        self.results: list[BenchmarkResult] = []

    @staticmethod
    def _validate_iterations(iterations: int) -> None:
        validate_positive_int_setting(iterations, "iterations")

    def benchmark_parsing(
        self,
        file_path: str | PathLike[str],
        iterations: int = 10,
    ) -> BenchmarkResult:
        """Benchmark parsing performance."""
        self._validate_iterations(iterations)
        try:
            # Read file once
            content = _read_benchmark_yara_text(file_path)

            file_size = len(content.encode())
            # Warm up
            ast = parse_yara_source(content)
            rules_count = len(ast.rules)
            strings_count = sum(len(rule.strings) for rule in ast.rules)
            ast_nodes = self._count_ast_nodes(ast)

            # Benchmark
            times = []
            for _ in range(iterations):
                start = time.perf_counter()
                ast = parse_yara_source(content)
                end = time.perf_counter()
                times.append(end - start)

            avg_time = statistics.mean(times)

            result = BenchmarkResult(
                operation="parsing",
                file_size=file_size,
                execution_time=avg_time,
                rules_count=rules_count,
                strings_count=strings_count,
                ast_nodes=ast_nodes,
                success=True,
            )

            self.results.append(result)
            return result

        except Exception as e:  # benchmark error boundary
            result = BenchmarkResult(
                operation="parsing",
                file_size=0,
                execution_time=0,
                rules_count=0,
                strings_count=0,
                ast_nodes=0,
                success=False,
                error=str(e),
            )
            self.results.append(result)
            return result

    def benchmark_codegen(
        self,
        file_path: str | PathLike[str],
        iterations: int = 10,
    ) -> BenchmarkResult:
        """Benchmark code generation performance."""
        self._validate_iterations(iterations)
        try:
            # Parse file once
            content = _read_benchmark_yara_text(file_path)

            file_size = len(content.encode())
            ast = parse_yara_source(content)
            rules_count = len(ast.rules)
            strings_count = sum(len(rule.strings) for rule in ast.rules)
            ast_nodes = self._count_ast_nodes(ast)

            generator = YaraXGenerator()

            # Benchmark
            times = []
            for _ in range(iterations):
                start = time.perf_counter()
                generator.generate(ast)
                end = time.perf_counter()
                times.append(end - start)

            avg_time = statistics.mean(times)

            result = BenchmarkResult(
                operation="codegen",
                file_size=file_size,
                execution_time=avg_time,
                rules_count=rules_count,
                strings_count=strings_count,
                ast_nodes=ast_nodes,
                success=True,
            )

            self.results.append(result)
            return result

        except Exception as e:  # benchmark error boundary
            result = BenchmarkResult(
                operation="codegen",
                file_size=0,
                execution_time=0,
                rules_count=0,
                strings_count=0,
                ast_nodes=0,
                success=False,
                error=str(e),
            )
            self.results.append(result)
            return result

    def benchmark_roundtrip(
        self,
        file_path: str | PathLike[str],
        iterations: int = 5,
    ) -> list[BenchmarkResult]:
        """Benchmark full parse->generate roundtrip."""
        self._validate_iterations(iterations)
        results = []

        try:
            content = _read_benchmark_yara_text(file_path)

            file_size = len(content.encode())
            avg_time = self._time_roundtrip(content, iterations)

            # Parse once more for statistics
            ast = parse_yara_source(content)

            result = BenchmarkResult(
                operation="roundtrip",
                file_size=file_size,
                execution_time=avg_time,
                rules_count=len(ast.rules),
                strings_count=sum(len(rule.strings) for rule in ast.rules),
                ast_nodes=self._count_ast_nodes(ast),
                success=True,
            )

            results.append(result)
            self.results.append(result)

        except Exception as e:  # benchmark error boundary
            result = BenchmarkResult(
                operation="roundtrip",
                file_size=0,
                execution_time=0,
                rules_count=0,
                strings_count=0,
                ast_nodes=0,
                success=False,
                error=str(e),
            )
            results.append(result)
            self.results.append(result)

        return results

    @staticmethod
    def _time_roundtrip(content: str, iterations: int) -> float:
        """Run parse->generate roundtrip iterations and return average time."""
        ASTBenchmarker._validate_iterations(iterations)
        times = []
        for _ in range(iterations):
            start = time.perf_counter()
            ast = parse_yara_source(content)
            generator = YaraXGenerator()
            generator.generate(ast)
            end = time.perf_counter()
            times.append(end - start)
        return statistics.mean(times)

    def _count_ast_nodes(self, ast: YaraFile) -> int:
        """Count total AST nodes."""
        count = 1  # YaraFile itself

        def count_node(node: ASTNode) -> int:
            node_count = 1
            for child in node.children():
                node_count += count_node(child)
            return node_count

        for child in ast.children():
            count += count_node(child)

        return count

    def get_benchmark_summary(self) -> dict[str, Any]:
        """Get summary of all benchmark results."""
        if not self.results:
            return {"message": "No benchmarks run"}

        by_operation: dict[str, list[BenchmarkResult]] = {}
        for result in self.results:
            if result.operation not in by_operation:
                by_operation[result.operation] = []
            by_operation[result.operation].append(result)

        summary: dict[str, Any] = {}
        for operation, results in by_operation.items():
            successful = [r for r in results if r.success]
            if successful:
                times = [r.execution_time for r in successful]
                summary[operation] = {
                    "count": len(successful),
                    "avg_time": statistics.mean(times),
                    "min_time": min(times),
                    "max_time": max(times),
                    "total_files_processed": len(successful),
                    "total_rules_processed": sum(r.rules_count for r in successful),
                    "avg_rules_per_second": (
                        sum(r.rules_count for r in successful) / sum(times) if sum(times) > 0 else 0
                    ),
                }

        return summary
