"""AST benchmarking utilities for CLI."""

from __future__ import annotations

import statistics
import time
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from yaraast.ast.base import ASTNode, YaraFile
from yaraast.codegen.generator import CodeGenerator
from yaraast.parser.parser import Parser


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

    def benchmark_parsing(
        self,
        file_path: Path,
        iterations: int = 10,
    ) -> BenchmarkResult:
        """Benchmark parsing performance."""
        try:
            # Read file once
            with Path(file_path).open() as f:
                content = f.read()

            file_size = len(content.encode())
            # Parser will be instantiated with content

            # Warm up
            parser = Parser(content)
            ast = parser.parse()
            rules_count = len(ast.rules)
            strings_count = sum(len(rule.strings) for rule in ast.rules)
            ast_nodes = self._count_ast_nodes(ast)

            # Benchmark
            times = []
            for _ in range(iterations):
                start = time.perf_counter()
                parser = Parser(content)
                ast = parser.parse()
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

        except Exception as e:
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
        file_path: Path,
        iterations: int = 10,
    ) -> BenchmarkResult:
        """Benchmark code generation performance."""
        try:
            # Parse file once
            # Parser will be instantiated with content
            with Path(file_path).open() as f:
                content = f.read()

            file_size = len(content.encode())
            parser = Parser(content)
            ast = parser.parse()
            rules_count = len(ast.rules)
            strings_count = sum(len(rule.strings) for rule in ast.rules)
            ast_nodes = self._count_ast_nodes(ast)

            generator = CodeGenerator()

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

        except Exception as e:
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
        file_path: Path,
        iterations: int = 5,
    ) -> list[BenchmarkResult]:
        """Benchmark full parse->generate roundtrip."""
        results = []

        try:
            with Path(file_path).open() as f:
                content = f.read()

            file_size = len(content.encode())

            # Test roundtrip
            times = []
            for _ in range(iterations):
                start = time.perf_counter()

                parser = Parser(content)
                ast = parser.parse()

                generator = CodeGenerator()
                generator.generate(ast)

                end = time.perf_counter()
                times.append(end - start)

            avg_time = statistics.mean(times)

            # Parse once more for statistics
            # Parser will be instantiated with content
            parser = Parser(content)
            ast = parser.parse()
            rules_count = len(ast.rules)
            strings_count = sum(len(rule.strings) for rule in ast.rules)
            ast_nodes = self._count_ast_nodes(ast)

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

        except Exception as e:
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

        by_operation = {}
        for result in self.results:
            if result.operation not in by_operation:
                by_operation[result.operation] = []
            by_operation[result.operation].append(result)

        summary = {}
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

    def clear_results(self) -> None:
        """Clear benchmark results."""
        self.results.clear()
