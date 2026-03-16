"""
Copyright (c) 2025 Marc Rivero López
Licensed under GPLv3. See LICENSE file for details.
This test suite validates real code behavior without mocks or stubs.

Comprehensive benchmarking suite for YARA AST Parser.

This module provides tools for benchmarking parser performance,
comparing standard Parser vs StreamingParser, and measuring
memory usage and throughput.
"""

import gc
import json
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

import psutil

from yaraast.parser import Parser
from yaraast.performance.streaming_parser import StreamingParser


@dataclass
class BenchmarkResult:
    """Container for benchmark results."""

    parser_type: str
    file_path: str
    file_size_mb: float
    parse_time_seconds: float
    peak_memory_mb: float
    rule_count: int
    throughput_rules_per_second: float
    throughput_mb_per_second: float
    success: bool
    error_message: str | None = None
    metadata: dict[str, Any] = field(default_factory=dict)


class ParserBenchmark:
    """Benchmark suite for YARA parser performance testing."""

    def __init__(self, results_dir: Path) -> None:
        """Initialize the benchmark suite.

        Args:
            results_dir: Directory where results will be saved
        """
        self.results_dir = results_dir
        self.results_dir.mkdir(parents=True, exist_ok=True)
        self.results: list[BenchmarkResult] = []

    def measure_memory(self) -> float:
        """Measure current process memory usage in MB.

        Returns:
            Current memory usage in megabytes
        """
        process = psutil.Process()
        return process.memory_info().rss / (1024 * 1024)

    def benchmark_standard_parser(
        self,
        file_path: Path,
        warmup: bool = True,
    ) -> BenchmarkResult:
        """Benchmark the standard Parser implementation.

        Args:
            file_path: Path to YARA file to parse
            warmup: Whether to perform a warmup run

        Returns:
            BenchmarkResult containing performance metrics
        """
        print(f"\nBenchmarking standard Parser on {file_path.name}...")

        file_size_mb = file_path.stat().st_size / (1024 * 1024)

        # Warmup run to eliminate cold start effects
        if warmup:
            print("  Performing warmup run...")
            try:
                content = file_path.read_text(encoding="utf-8")
                parser = Parser(content)
                _ = parser.parse()
                del parser
                del _
                gc.collect()
            except Exception as e:
                print(f"  Warmup failed: {e}")

        # Actual benchmark run
        gc.collect()
        memory_before = self.measure_memory()

        try:
            start_time = time.perf_counter()
            content = file_path.read_text(encoding="utf-8")
            parser = Parser(content)
            ast = parser.parse()
            parse_time = time.perf_counter() - start_time

            memory_after = self.measure_memory()
            peak_memory = memory_after - memory_before

            rule_count = len(ast.rules)
            throughput_rules = rule_count / parse_time if parse_time > 0 else 0
            throughput_mb = file_size_mb / parse_time if parse_time > 0 else 0

            result = BenchmarkResult(
                parser_type="Standard Parser",
                file_path=str(file_path),
                file_size_mb=file_size_mb,
                parse_time_seconds=parse_time,
                peak_memory_mb=peak_memory,
                rule_count=rule_count,
                throughput_rules_per_second=throughput_rules,
                throughput_mb_per_second=throughput_mb,
                success=True,
                metadata={
                    "import_count": len(ast.imports),
                    "include_count": len(ast.includes),
                },
            )

            print(f"  Success! Parsed {rule_count} rules in {parse_time:.3f}s")
            print(f"  Throughput: {throughput_rules:.2f} rules/s, {throughput_mb:.2f} MB/s")
            print(f"  Memory: {peak_memory:.2f} MB")

        except Exception as e:
            result = BenchmarkResult(
                parser_type="Standard Parser",
                file_path=str(file_path),
                file_size_mb=file_size_mb,
                parse_time_seconds=0,
                peak_memory_mb=0,
                rule_count=0,
                throughput_rules_per_second=0,
                throughput_mb_per_second=0,
                success=False,
                error_message=str(e),
            )
            print(f"  Failed: {e}")

        self.results.append(result)
        return result

    def benchmark_streaming_parser(
        self,
        file_path: Path,
        warmup: bool = True,
    ) -> BenchmarkResult:
        """Benchmark the StreamingParser implementation.

        Args:
            file_path: Path to YARA file to parse
            warmup: Whether to perform a warmup run

        Returns:
            BenchmarkResult containing performance metrics
        """
        print(f"\nBenchmarking StreamingParser on {file_path.name}...")

        file_size_mb = file_path.stat().st_size / (1024 * 1024)

        # Warmup run
        if warmup:
            print("  Performing warmup run...")
            try:
                parser = StreamingParser(buffer_size=8192)
                list(parser.parse_file(file_path))
                del parser
                gc.collect()
            except Exception as e:
                print(f"  Warmup failed: {e}")

        # Actual benchmark run
        gc.collect()
        memory_before = self.measure_memory()

        try:
            start_time = time.perf_counter()
            parser = StreamingParser(buffer_size=8192)
            rules = list(parser.parse_file(file_path))
            parse_time = time.perf_counter() - start_time

            memory_after = self.measure_memory()
            peak_memory = memory_after - memory_before

            rule_count = len(rules)
            throughput_rules = rule_count / parse_time if parse_time > 0 else 0
            throughput_mb = file_size_mb / parse_time if parse_time > 0 else 0

            stats = parser.get_statistics()

            result = BenchmarkResult(
                parser_type="StreamingParser",
                file_path=str(file_path),
                file_size_mb=file_size_mb,
                parse_time_seconds=parse_time,
                peak_memory_mb=peak_memory,
                rule_count=rule_count,
                throughput_rules_per_second=throughput_rules,
                throughput_mb_per_second=throughput_mb,
                success=True,
                metadata={
                    "bytes_processed": stats.get("bytes_processed", 0),
                    "parse_errors": stats.get("parse_errors", 0),
                },
            )

            print(f"  Success! Parsed {rule_count} rules in {parse_time:.3f}s")
            print(f"  Throughput: {throughput_rules:.2f} rules/s, {throughput_mb:.2f} MB/s")
            print(f"  Memory: {peak_memory:.2f} MB")

        except Exception as e:
            result = BenchmarkResult(
                parser_type="StreamingParser",
                file_path=str(file_path),
                file_size_mb=file_size_mb,
                parse_time_seconds=0,
                peak_memory_mb=0,
                rule_count=0,
                throughput_rules_per_second=0,
                throughput_mb_per_second=0,
                success=False,
                error_message=str(e),
            )
            print(f"  Failed: {e}")

        self.results.append(result)
        return result

    def benchmark_comparison(
        self,
        file_path: Path,
        warmup: bool = True,
    ) -> dict[str, BenchmarkResult]:
        """Run both parsers and compare results.

        Args:
            file_path: Path to YARA file to parse
            warmup: Whether to perform warmup runs

        Returns:
            Dictionary mapping parser type to BenchmarkResult
        """
        print(f"\n{'=' * 60}")
        print(f"Comparing parsers on: {file_path.name}")
        print(f"File size: {file_path.stat().st_size / (1024 * 1024):.2f} MB")
        print(f"{'=' * 60}")

        results = {}

        # Benchmark standard parser
        results["standard"] = self.benchmark_standard_parser(file_path, warmup=warmup)

        # Short pause between benchmarks
        time.sleep(1)
        gc.collect()

        # Benchmark streaming parser
        results["streaming"] = self.benchmark_streaming_parser(file_path, warmup=warmup)

        # Print comparison
        self._print_comparison(results)

        return results

    def _print_comparison(self, results: dict[str, BenchmarkResult]) -> None:
        """Print comparison between parser results.

        Args:
            results: Dictionary of benchmark results
        """
        standard = results.get("standard")
        streaming = results.get("streaming")

        if not standard or not streaming:
            return

        if not standard.success or not streaming.success:
            print("\n  Warning: One or both parsers failed")
            return

        print("\n  Comparison:")
        print(f"  {'Metric':<30} {'Standard':<15} {'Streaming':<15} {'Difference':<15}")
        print(f"  {'-' * 75}")

        # Parse time comparison
        time_diff = (
            (streaming.parse_time_seconds - standard.parse_time_seconds)
            / standard.parse_time_seconds
            * 100
        )
        print(
            f"  {'Parse Time (s)':<30} "
            f"{standard.parse_time_seconds:<15.3f} "
            f"{streaming.parse_time_seconds:<15.3f} "
            f"{time_diff:+.1f}%"
        )

        # Memory comparison
        mem_diff = (
            (streaming.peak_memory_mb - standard.peak_memory_mb) / standard.peak_memory_mb * 100
            if standard.peak_memory_mb > 0
            else 0
        )
        print(
            f"  {'Peak Memory (MB)':<30} "
            f"{standard.peak_memory_mb:<15.2f} "
            f"{streaming.peak_memory_mb:<15.2f} "
            f"{mem_diff:+.1f}%"
        )

        # Throughput comparison
        throughput_diff = (
            (streaming.throughput_rules_per_second - standard.throughput_rules_per_second)
            / standard.throughput_rules_per_second
            * 100
            if standard.throughput_rules_per_second > 0
            else 0
        )
        print(
            f"  {'Throughput (rules/s)':<30} "
            f"{standard.throughput_rules_per_second:<15.2f} "
            f"{streaming.throughput_rules_per_second:<15.2f} "
            f"{throughput_diff:+.1f}%"
        )

    def benchmark_suite(
        self,
        test_data_dir: Path,
        pattern: str = "*.yar",
    ) -> list[dict[str, BenchmarkResult]]:
        """Run benchmarks on all test files in a directory.

        Args:
            test_data_dir: Directory containing test YARA files
            pattern: Glob pattern for finding test files

        Returns:
            List of comparison results for each file
        """
        test_files = sorted(test_data_dir.glob(pattern))

        if not test_files:
            print(f"No test files found in {test_data_dir} matching {pattern}")
            return []

        print(f"\nFound {len(test_files)} test files")

        all_results = []

        for test_file in test_files:
            results = self.benchmark_comparison(test_file)
            all_results.append(results)

            # Pause between files
            time.sleep(2)
            gc.collect()

        return all_results

    def save_results(self, filename: str = "benchmark_results.json") -> Path:
        """Save benchmark results to a JSON file.

        Args:
            filename: Name of the output file

        Returns:
            Path to the saved results file
        """
        output_path = self.results_dir / filename

        # Convert results to JSON-serializable format
        results_data = []
        for result in self.results:
            results_data.append(
                {
                    "parser_type": result.parser_type,
                    "file_path": result.file_path,
                    "file_size_mb": result.file_size_mb,
                    "parse_time_seconds": result.parse_time_seconds,
                    "peak_memory_mb": result.peak_memory_mb,
                    "rule_count": result.rule_count,
                    "throughput_rules_per_second": result.throughput_rules_per_second,
                    "throughput_mb_per_second": result.throughput_mb_per_second,
                    "success": result.success,
                    "error_message": result.error_message,
                    "metadata": result.metadata,
                }
            )

        output_data = {
            "timestamp": time.strftime("%Y-%m-%d %H:%M:%S"),
            "results": results_data,
        }

        with open(output_path, "w", encoding="utf-8") as f:
            json.dump(output_data, f, indent=2)

        print(f"\nResults saved to: {output_path}")
        return output_path

    def generate_report(self, filename: str = "benchmark_report.txt") -> Path:
        """Generate a human-readable report of benchmark results.

        Args:
            filename: Name of the output file

        Returns:
            Path to the saved report file
        """
        output_path = self.results_dir / filename

        with open(output_path, "w", encoding="utf-8") as f:
            f.write("YARA AST Parser Benchmark Report\n")
            f.write("=" * 80 + "\n\n")
            f.write(f"Generated: {time.strftime('%Y-%m-%d %H:%M:%S')}\n")
            f.write(f"Total benchmarks: {len(self.results)}\n\n")

            # Group results by file
            results_by_file = {}
            for result in self.results:
                if result.file_path not in results_by_file:
                    results_by_file[result.file_path] = []
                results_by_file[result.file_path].append(result)

            for file_path, file_results in results_by_file.items():
                f.write(f"\nFile: {Path(file_path).name}\n")
                f.write("-" * 80 + "\n")

                for result in file_results:
                    f.write(f"\nParser: {result.parser_type}\n")
                    f.write(f"  Status: {'SUCCESS' if result.success else 'FAILED'}\n")

                    if result.success:
                        f.write(f"  File Size: {result.file_size_mb:.2f} MB\n")
                        f.write(f"  Parse Time: {result.parse_time_seconds:.3f} seconds\n")
                        f.write(f"  Peak Memory: {result.peak_memory_mb:.2f} MB\n")
                        f.write(f"  Rules Parsed: {result.rule_count}\n")
                        f.write(
                            f"  Throughput: {result.throughput_rules_per_second:.2f} rules/s, "
                            f"{result.throughput_mb_per_second:.2f} MB/s\n"
                        )
                    else:
                        f.write(f"  Error: {result.error_message}\n")

        print(f"Report saved to: {output_path}")
        return output_path


def main() -> None:
    """Main entry point for benchmark execution."""
    benchmark_dir = Path(__file__).parent
    test_data_dir = benchmark_dir / "test_data"
    results_dir = benchmark_dir / "results"

    print("YARA AST Parser Benchmarking Suite")
    print("=" * 60)

    if not test_data_dir.exists():
        print(f"\nError: Test data directory not found: {test_data_dir}")
        print("Please run test_file_generator.py first to generate test files.")
        return

    test_files = sorted(test_data_dir.glob("*.yar"))
    if not test_files:
        print(f"\nError: No test files found in {test_data_dir}")
        print("Please run test_file_generator.py first to generate test files.")
        return

    print(f"\nTest data directory: {test_data_dir}")
    print(f"Results directory: {results_dir}")
    print(f"Found {len(test_files)} test files\n")

    # Create benchmark suite
    benchmark = ParserBenchmark(results_dir)

    # Run benchmarks
    benchmark.benchmark_suite(test_data_dir)

    # Save results
    benchmark.save_results()
    benchmark.generate_report()

    print("\nBenchmark suite complete!")


if __name__ == "__main__":
    main()
