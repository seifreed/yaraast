"""AST benchmarking utilities for CLI."""

from __future__ import annotations

from collections.abc import Callable
from dataclasses import dataclass
from os import PathLike, fspath
from pathlib import Path
import statistics
import time
from typing import Any, TypeVar

from yaraast.ast.base import ASTNode, YaraFile
from yaraast.cli.utils import _path_exists_and_is_dir
from yaraast.parser.source import parse_yara_source
from yaraast.performance import StreamingParser
from yaraast.performance.timeout_helpers import run_with_timeout
from yaraast.shared.numeric_validation import (
    validate_positive_int_setting,
    validate_positive_number_setting,
)
from yaraast.shared.path_safety import path_has_symlink_ancestor, path_is_symlink
from yaraast.yarax.generator import YaraXGenerator

_BENCHMARK_STREAMING_PARSE_THRESHOLD_BYTES = 10 * 1024 * 1024
_BENCHMARK_STREAMING_AST_NODE_COUNT_LIMIT_BYTES = 50 * 1024 * 1024
_T = TypeVar("_T")


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
    if "\x00" in raw_path:
        msg = "file_path must not contain null bytes"
        raise ValueError(msg)
    path = Path(raw_path)
    if _path_exists_and_is_dir(path):
        msg = "file_path must not be a directory"
        raise ValueError(msg)
    if path_is_symlink(path) or path_has_symlink_ancestor(path):
        msg = "file_path must not traverse a symlink"
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
    success: bool = True
    error: str | None = None


class ASTBenchmarker:
    """Performance benchmarking for AST operations."""

    def __init__(
        self,
        streaming_parse_threshold_bytes: int = _BENCHMARK_STREAMING_PARSE_THRESHOLD_BYTES,
    ) -> None:
        self.results: list[BenchmarkResult] = []
        validate_positive_int_setting(
            streaming_parse_threshold_bytes,
            "streaming_parse_threshold_bytes",
        )
        self._streaming_parse_threshold_bytes = streaming_parse_threshold_bytes

    @staticmethod
    def _should_use_streaming_parser(file_size: int, threshold: int) -> bool:
        return file_size > threshold

    @staticmethod
    def _validate_iterations(iterations: int) -> None:
        validate_positive_int_setting(iterations, "iterations")

    @staticmethod
    def _validate_file_timeout(file_timeout: float | None) -> None:
        if file_timeout is not None:
            validate_positive_number_setting(file_timeout, "file_timeout")

    @staticmethod
    def _run_with_timeout(operation: str, timeout: float | None, fn: Callable[[], _T]) -> _T:
        """Run a callback with an optional timeout."""
        return run_with_timeout(operation, timeout, fn)

    @staticmethod
    def _collect_streaming_parse_counts(file_path: Path) -> tuple[int, int, int]:
        """Parse a YARA file via streaming parser and collect lightweight statistics."""
        parser = StreamingParser()
        count_ast_nodes = (
            file_path.stat().st_size <= _BENCHMARK_STREAMING_AST_NODE_COUNT_LIMIT_BYTES
        )
        rules_count = 0
        strings_count = 0
        ast_nodes = 1 if count_ast_nodes else 0

        for rule in parser.parse_file(file_path):
            parse_errors = parser.get_statistics().get("parse_errors", 0)
            if parse_errors > 0:
                msg = f"streaming parser reported {parse_errors} parse errors"
                raise ValueError(msg)
            rules_count += 1
            strings_count += len(rule.strings)
            if count_ast_nodes:
                ast_nodes += ASTBenchmarker._count_ast_nodes(rule)

        parse_errors = parser.get_statistics().get("parse_errors", 0)
        if parse_errors > 0 and rules_count > 0:
            msg = f"streaming parser reported {parse_errors} parse errors"
            raise ValueError(msg)
        if rules_count == 0:
            # Fallback to full parse to validate files that stream as empty.
            content = _read_benchmark_yara_text(file_path)
            ast = parse_yara_source(content)
            rules_count = len(ast.rules)
            strings_count = sum(len(rule.strings) for rule in ast.rules)
            ast_nodes = ASTBenchmarker._count_ast_nodes(ast)

        return rules_count, strings_count, ast_nodes

    @staticmethod
    def _run_streaming_parse_once(file_path: Path) -> None:
        """Run a single streaming parse over a file."""
        parser = StreamingParser()
        rules_count = 0
        for _ in parser.parse_file(file_path):
            rules_count += 1

        parse_errors = parser.get_statistics().get("parse_errors", 0)
        if parse_errors == 0 and rules_count > 0:
            return

        # Validate files that stream as empty.
        content = _read_benchmark_yara_text(file_path)
        parse_yara_source(content)

    def benchmark_parsing(
        self,
        file_path: str | PathLike[str],
        iterations: int = 10,
        file_timeout: float | None = None,
    ) -> BenchmarkResult:
        """Benchmark parsing performance."""
        self._validate_iterations(iterations)
        self._validate_file_timeout(file_timeout)
        try:
            file_path_obj = _require_benchmark_file_path(file_path)
            file_size = file_path_obj.stat().st_size
            use_streaming_parser = self._should_use_streaming_parser(
                file_size,
                self._streaming_parse_threshold_bytes,
            )

            content = ""

            if use_streaming_parser:
                # Warm-up and count via streaming parser for large files.
                rules_count, strings_count, ast_nodes = self._run_with_timeout(
                    "parsing",
                    file_timeout,
                    lambda: self._collect_streaming_parse_counts(file_path_obj),
                )
            else:
                # Read file once for small files
                content = _read_benchmark_yara_text(file_path_obj)
                # Warm up
                ast = self._run_with_timeout(
                    "parsing",
                    file_timeout,
                    lambda: parse_yara_source(content),
                )
                rules_count = len(ast.rules)
                strings_count = sum(len(rule.strings) for rule in ast.rules)
                ast_nodes = self._count_ast_nodes(ast)

            # Benchmark
            times = []
            for _ in range(iterations):
                start = time.perf_counter()
                if use_streaming_parser:
                    self._run_with_timeout(
                        "parsing",
                        file_timeout,
                        lambda: ASTBenchmarker._run_streaming_parse_once(file_path_obj),
                    )
                else:
                    self._run_with_timeout(
                        "parsing",
                        file_timeout,
                        lambda: parse_yara_source(content),
                    )
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
        file_timeout: float | None = None,
    ) -> BenchmarkResult:
        """Benchmark code generation performance."""
        self._validate_iterations(iterations)
        self._validate_file_timeout(file_timeout)
        try:
            # Parse file once
            content = _read_benchmark_yara_text(file_path)

            file_size = len(content.encode())
            avg_time, rules_count, strings_count, ast_nodes = self._run_with_timeout(
                "codegen",
                file_timeout,
                lambda: self._time_codegen(content, iterations),
            )

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
        file_timeout: float | None = None,
    ) -> list[BenchmarkResult]:
        """Benchmark full parse->generate roundtrip."""
        self._validate_iterations(iterations)
        self._validate_file_timeout(file_timeout)
        results = []

        try:
            content = _read_benchmark_yara_text(file_path)

            file_size = len(content.encode())
            avg_time, rules_count, strings_count, ast_nodes = self._run_with_timeout(
                "roundtrip",
                file_timeout,
                lambda: self._time_roundtrip(content, iterations),
            )

            result = BenchmarkResult(
                operation="roundtrip",
                file_size=file_size,
                execution_time=avg_time,
                rules_count=rules_count,
                strings_count=strings_count,
                ast_nodes=ast_nodes,
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
    def _time_roundtrip(content: str, iterations: int) -> tuple[float, int, int, int]:
        """Run parse->generate roundtrip iterations and return average time and stats."""
        ASTBenchmarker._validate_iterations(iterations)
        times = []
        ast: YaraFile | None = None
        for _ in range(iterations):
            start = time.perf_counter()
            ast = parse_yara_source(content)
            generator = YaraXGenerator()
            generator.generate(ast)
            end = time.perf_counter()
            times.append(end - start)

        if ast is None:
            msg = "iterations must be at least 1"
            raise ValueError(msg)
        return (
            statistics.mean(times),
            len(ast.rules),
            sum(len(rule.strings) for rule in ast.rules),
            ASTBenchmarker._count_ast_nodes(ast),
        )

    @staticmethod
    def _time_codegen(content: str, iterations: int) -> tuple[float, int, int, int]:
        """Run parse->generate codegen iterations and return average time and stats."""
        ASTBenchmarker._validate_iterations(iterations)
        ast = parse_yara_source(content)
        times = []
        generator = YaraXGenerator()
        for _ in range(iterations):
            start = time.perf_counter()
            generator.generate(ast)
            end = time.perf_counter()
            times.append(end - start)

        return (
            statistics.mean(times),
            len(ast.rules),
            sum(len(rule.strings) for rule in ast.rules),
            ASTBenchmarker._count_ast_nodes(ast),
        )

    @staticmethod
    def _count_ast_nodes(ast: ASTNode) -> int:
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
