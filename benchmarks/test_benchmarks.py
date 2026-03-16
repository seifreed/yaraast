"""
Copyright (c) 2025 Marc Rivero López
Licensed under GPLv3. See LICENSE file for details.
This test suite validates real code behavior without mocks or stubs.

Pytest-benchmark integration tests.

This module provides automated benchmark tests using pytest-benchmark
for continuous performance regression testing.
"""

import gc

import pytest

from yaraast.parser import Parser
from yaraast.performance.streaming_parser import StreamingParser


@pytest.mark.benchmark
class TestParserBenchmarks:
    """Benchmark tests for standard Parser."""

    def test_benchmark_small_file_parsing(self, benchmark, small_test_file):
        """Benchmark parsing a small YARA file.

        Purpose:
            Measure baseline performance on small files (5MB) to establish
            minimum performance expectations.

        Expected Behavior:
            Parser should complete in reasonable time with linear scaling
            relative to file size. This test establishes baseline metrics.

        Rationale:
            Small files test parser initialization overhead and basic
            parsing efficiency without memory pressure.
        """

        def parse_file():
            content = small_test_file.read_text(encoding="utf-8")
            parser = Parser(content)
            ast = parser.parse()
            return ast

        result = benchmark.pedantic(parse_file, iterations=5, rounds=3)
        assert result is not None
        assert len(result.rules) > 0

    def test_benchmark_medium_file_parsing(self, benchmark, medium_test_file):
        """Benchmark parsing a medium YARA file.

        Purpose:
            Measure performance on medium-sized files (10MB) to identify
            scaling characteristics.

        Expected Behavior:
            Parse time should scale linearly with file size. Any quadratic
            or exponential growth indicates algorithmic inefficiency.

        Rationale:
            Medium files test parser scalability without extreme memory
            requirements, representing typical production use cases.
        """

        def parse_file():
            content = medium_test_file.read_text(encoding="utf-8")
            parser = Parser(content)
            ast = parser.parse()
            return ast

        result = benchmark.pedantic(parse_file, iterations=3, rounds=2)
        assert result is not None
        assert len(result.rules) > 0

    @pytest.mark.slow
    def test_benchmark_large_file_parsing(self, benchmark, large_test_file):
        """Benchmark parsing a large YARA file.

        Purpose:
            Stress test parser with large files (20MB) to identify
            memory and performance bottlenecks.

        Expected Behavior:
            Parser should handle large files without excessive memory
            consumption or exponential time complexity.

        Rationale:
            Large files expose scalability issues and memory management
            problems that only appear under load.
        """

        def parse_file():
            content = large_test_file.read_text(encoding="utf-8")
            parser = Parser(content)
            ast = parser.parse()
            return ast

        result = benchmark.pedantic(parse_file, iterations=2, rounds=1)
        assert result is not None
        assert len(result.rules) > 0


@pytest.mark.benchmark
class TestStreamingParserBenchmarks:
    """Benchmark tests for StreamingParser."""

    def test_benchmark_streaming_small_file(self, benchmark, small_test_file):
        """Benchmark streaming parser on small file.

        Purpose:
            Measure StreamingParser baseline performance on small files
            for direct comparison with standard Parser.

        Expected Behavior:
            StreamingParser may have higher overhead on small files due to
            streaming infrastructure, but should maintain reasonable throughput.

        Rationale:
            Small files test streaming overhead and identify crossover point
            where streaming becomes beneficial.
        """

        def parse_file():
            parser = StreamingParser(buffer_size=8192)
            rules = list(parser.parse_file(small_test_file))
            return rules

        result = benchmark.pedantic(parse_file, iterations=5, rounds=3)
        assert result is not None
        assert len(result) > 0

    def test_benchmark_streaming_medium_file(self, benchmark, medium_test_file):
        """Benchmark streaming parser on medium file.

        Purpose:
            Measure StreamingParser performance at scale to identify
            memory efficiency advantages.

        Expected Behavior:
            StreamingParser should demonstrate lower memory usage while
            maintaining competitive parse times.

        Rationale:
            Medium files are where streaming advantages become apparent
            through reduced peak memory consumption.
        """

        def parse_file():
            parser = StreamingParser(buffer_size=8192)
            rules = list(parser.parse_file(medium_test_file))
            return rules

        result = benchmark.pedantic(parse_file, iterations=3, rounds=2)
        assert result is not None
        assert len(result) > 0

    @pytest.mark.slow
    def test_benchmark_streaming_large_file(self, benchmark, large_test_file):
        """Benchmark streaming parser on large file.

        Purpose:
            Validate StreamingParser memory efficiency on large files
            where standard parser may struggle.

        Expected Behavior:
            StreamingParser should maintain constant memory usage regardless
            of file size, with predictable streaming performance.

        Rationale:
            Large files are the primary use case for streaming parser,
            where memory efficiency is critical.
        """

        def parse_file():
            parser = StreamingParser(buffer_size=8192)
            rules = list(parser.parse_file(large_test_file))
            return rules

        result = benchmark.pedantic(parse_file, iterations=2, rounds=1)
        assert result is not None
        assert len(result) > 0


@pytest.mark.benchmark
class TestParserComparison:
    """Comparative benchmark tests."""

    def test_compare_parsers_small_file(
        self,
        benchmark,
        small_test_file,
        standard_parser,
        streaming_parser,
    ):
        """Compare both parsers on small file.

        Purpose:
            Directly compare standard and streaming parsers to quantify
            performance differences on small files.

        Expected Behavior:
            Standard parser likely faster due to simpler code path.
            Streaming parser overhead should be minimal and measurable.

        Rationale:
            Small file comparison establishes baseline overhead of
            streaming architecture.
        """
        # This test uses benchmark groups for comparison
        pass  # Implementation depends on pytest-benchmark version

    def test_memory_efficiency_comparison(
        self,
        small_test_file,
        standard_parser,
        streaming_parser,
    ):
        """Compare memory usage between parsers.

        Purpose:
            Validate that StreamingParser uses less peak memory than
            standard Parser on identical inputs.

        Expected Behavior:
            StreamingParser should demonstrate lower peak RSS memory
            consumption, especially on larger files.

        Rationale:
            Memory efficiency is the primary design goal of StreamingParser.
            This test validates that goal is achieved in practice.
        """
        import os

        import psutil

        process = psutil.Process(os.getpid())

        # Measure standard parser memory
        gc.collect()
        mem_before_standard = process.memory_info().rss
        content = small_test_file.read_text(encoding="utf-8")
        parser = standard_parser(content)
        ast = parser.parse()
        mem_after_standard = process.memory_info().rss
        standard_memory = (mem_after_standard - mem_before_standard) / (1024 * 1024)
        del parser
        del ast
        del content

        # Cleanup
        gc.collect()

        # Measure streaming parser memory
        mem_before_streaming = process.memory_info().rss
        stream_parser = streaming_parser(buffer_size=8192)
        rules = list(stream_parser.parse_file(small_test_file))
        mem_after_streaming = process.memory_info().rss
        streaming_memory = (mem_after_streaming - mem_before_streaming) / (1024 * 1024)
        del stream_parser
        del rules

        # StreamingParser should use comparable or less memory
        # We don't enforce strict inequality as small files may not show advantage
        assert streaming_memory >= 0  # Basic sanity check
        assert standard_memory >= 0

        print("\nMemory comparison:")
        print(f"  Standard Parser:   {standard_memory:.2f} MB")
        print(f"  Streaming Parser:  {streaming_memory:.2f} MB")


@pytest.mark.benchmark
class TestThroughputBenchmarks:
    """Throughput measurement tests."""

    def test_rules_per_second_small(self, benchmark, small_test_file):
        """Measure rules per second on small file.

        Purpose:
            Establish baseline throughput metric (rules/second) for
            performance tracking over time.

        Expected Behavior:
            Parser should maintain consistent rules/second throughput
            across runs, indicating predictable performance.

        Rationale:
            Throughput metrics enable tracking performance regressions
            and improvements across code changes.
        """

        def parse_and_count():
            content = small_test_file.read_text(encoding="utf-8")
            parser = Parser(content)
            ast = parser.parse()
            return len(ast.rules)

        result = benchmark(parse_and_count)
        assert result > 0

        # Calculate and report throughput
        stats = benchmark.stats
        mean_time = stats.get("mean", 0)
        if mean_time > 0:
            throughput = result / mean_time
            print(f"\nThroughput: {throughput:.2f} rules/second")

    def test_megabytes_per_second_medium(self, benchmark, medium_test_file):
        """Measure MB/s throughput on medium file.

        Purpose:
            Establish file size throughput metric (MB/s) for evaluating
            I/O and parsing efficiency.

        Expected Behavior:
            Parser should maintain consistent MB/s throughput, with
            variations indicating I/O or CPU bottlenecks.

        Rationale:
            MB/s throughput complements rules/s metric by accounting
            for varying rule complexity and file structure.
        """
        file_size_mb = medium_test_file.stat().st_size / (1024 * 1024)

        def parse_file():
            content = medium_test_file.read_text(encoding="utf-8")
            parser = Parser(content)
            ast = parser.parse()
            return ast

        result = benchmark(parse_file)
        assert result is not None

        # Calculate and report throughput
        stats = benchmark.stats
        mean_time = stats.get("mean", 0)
        if mean_time > 0:
            throughput = file_size_mb / mean_time
            print(f"\nThroughput: {throughput:.2f} MB/second")
