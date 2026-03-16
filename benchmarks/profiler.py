"""
Copyright (c) 2025 Marc Rivero López
Licensed under GPLv3. See LICENSE file for details.
This test suite validates real code behavior without mocks or stubs.

cProfile integration for YARA AST Parser profiling.

This module provides detailed function-level profiling
using Python's built-in cProfile for identifying performance bottlenecks.
"""

import cProfile
import pstats
from io import StringIO
from pathlib import Path

from yaraast.parser import Parser
from yaraast.performance.streaming_parser import StreamingParser


class ParserProfiler:
    """Profile YARA parser execution using cProfile."""

    def __init__(self, results_dir: Path) -> None:
        """Initialize the profiler.

        Args:
            results_dir: Directory where profiling results will be saved
        """
        self.results_dir = results_dir
        self.results_dir.mkdir(parents=True, exist_ok=True)

    def profile_standard_parser(
        self,
        file_path: Path,
        save_stats: bool = True,
    ) -> pstats.Stats:
        """Profile the standard Parser using cProfile.

        Args:
            file_path: Path to YARA file to parse
            save_stats: Whether to save profiling statistics

        Returns:
            pstats.Stats object containing profiling results
        """
        print(f"\nProfiling Standard Parser on {file_path.name}...")

        profiler = cProfile.Profile()

        # Profile the parsing operation
        profiler.enable()

        content = file_path.read_text(encoding="utf-8")
        parser = Parser(content)
        parser.parse()

        profiler.disable()

        # Create stats object
        stats = pstats.Stats(profiler)

        if save_stats:
            # Save binary stats file
            stats_file = self.results_dir / f"profile_standard_{file_path.stem}.prof"
            stats.dump_stats(str(stats_file))
            print(f"  Binary stats saved to: {stats_file}")

            # Save human-readable report
            self._save_readable_report(stats, file_path, "Standard Parser")

        return stats

    def profile_streaming_parser(
        self,
        file_path: Path,
        save_stats: bool = True,
    ) -> pstats.Stats:
        """Profile the StreamingParser using cProfile.

        Args:
            file_path: Path to YARA file to parse
            save_stats: Whether to save profiling statistics

        Returns:
            pstats.Stats object containing profiling results
        """
        print(f"\nProfiling StreamingParser on {file_path.name}...")

        profiler = cProfile.Profile()

        # Profile the parsing operation
        profiler.enable()

        parser = StreamingParser(buffer_size=8192)
        list(parser.parse_file(file_path))

        profiler.disable()

        # Create stats object
        stats = pstats.Stats(profiler)

        if save_stats:
            # Save binary stats file
            stats_file = self.results_dir / f"profile_streaming_{file_path.stem}.prof"
            stats.dump_stats(str(stats_file))
            print(f"  Binary stats saved to: {stats_file}")

            # Save human-readable report
            self._save_readable_report(stats, file_path, "StreamingParser")

        return stats

    def _save_readable_report(
        self,
        stats: pstats.Stats,
        file_path: Path,
        parser_type: str,
    ) -> None:
        """Save a human-readable profiling report.

        Args:
            stats: pstats.Stats object to format
            file_path: Original file being profiled
            parser_type: Type of parser being profiled
        """
        report_file = (
            self.results_dir
            / f"profile_{parser_type.lower().replace(' ', '_')}_{file_path.stem}.txt"
        )

        with open(report_file, "w", encoding="utf-8") as f:
            # Redirect stdout to file
            stream = StringIO()

            # Print header
            f.write(f"Profiling Report: {parser_type}\n")
            f.write("=" * 80 + "\n\n")
            f.write(f"File: {file_path.name}\n")
            f.write(f"File Size: {file_path.stat().st_size / (1024 * 1024):.2f} MB\n\n")

            # Top functions by cumulative time
            f.write("=" * 80 + "\n")
            f.write("Top 50 Functions by Cumulative Time\n")
            f.write("=" * 80 + "\n")

            ps = pstats.Stats(stats.stats, stream=stream)
            ps.strip_dirs()
            ps.sort_stats("cumulative")
            ps.print_stats(50)

            f.write(stream.getvalue())
            stream.truncate(0)
            stream.seek(0)

            # Top functions by total time
            f.write("\n" + "=" * 80 + "\n")
            f.write("Top 50 Functions by Total Time\n")
            f.write("=" * 80 + "\n")

            ps = pstats.Stats(stats.stats, stream=stream)
            ps.strip_dirs()
            ps.sort_stats("tottime")
            ps.print_stats(50)

            f.write(stream.getvalue())
            stream.truncate(0)
            stream.seek(0)

            # Callers information
            f.write("\n" + "=" * 80 + "\n")
            f.write("Caller Information (Top 30)\n")
            f.write("=" * 80 + "\n")

            ps = pstats.Stats(stats.stats, stream=stream)
            ps.strip_dirs()
            ps.sort_stats("cumulative")
            ps.print_callers(30)

            f.write(stream.getvalue())

        print(f"  Report saved to: {report_file}")

    def compare_parsers(
        self,
        file_path: Path,
    ) -> dict:
        """Profile and compare both parser implementations.

        Args:
            file_path: Path to YARA file to parse

        Returns:
            Dictionary with profiling stats for both parsers
        """
        print(f"\n{'=' * 60}")
        print(f"Profiling comparison: {file_path.name}")
        print(f"{'=' * 60}")

        results = {}

        # Profile standard parser
        results["standard"] = self.profile_standard_parser(file_path)

        # Profile streaming parser
        results["streaming"] = self.profile_streaming_parser(file_path)

        # Generate comparison report
        self._generate_comparison_report(results, file_path)

        return results

    def _generate_comparison_report(
        self,
        results: dict,
        file_path: Path,
    ) -> None:
        """Generate a comparison report between profiling results.

        Args:
            results: Dictionary with profiling stats
            file_path: Original file being profiled
        """
        report_file = self.results_dir / f"profile_comparison_{file_path.stem}.txt"

        with open(report_file, "w", encoding="utf-8") as f:
            f.write("Profiling Comparison Report\n")
            f.write("=" * 80 + "\n\n")
            f.write(f"File: {file_path.name}\n")
            f.write(f"File Size: {file_path.stat().st_size / (1024 * 1024):.2f} MB\n\n")

            # Extract key metrics from each parser
            f.write("Summary Statistics\n")
            f.write("-" * 80 + "\n\n")

            for parser_name, stats in results.items():
                f.write(f"{parser_name.upper()} Parser:\n")

                # Get total calls and primitive calls
                total_calls = stats.total_calls
                prim_calls = stats.prim_calls
                total_time = stats.total_tt

                f.write(f"  Total function calls: {total_calls:,}\n")
                f.write(f"  Primitive calls: {prim_calls:,}\n")
                f.write(f"  Total time: {total_time:.3f} seconds\n")

                # Get top 10 most time-consuming functions
                stream = StringIO()
                ps = pstats.Stats(stats.stats, stream=stream)
                ps.strip_dirs()
                ps.sort_stats("tottime")
                ps.print_stats(10)

                f.write("\n  Top 10 functions by total time:\n")
                f.write("  " + "-" * 76 + "\n")

                # Parse the output and format it
                output_lines = stream.getvalue().split("\n")
                for line in output_lines:
                    if line.strip():
                        f.write(f"  {line}\n")

                f.write("\n")

        print(f"\nComparison report saved to: {report_file}")

    def profile_suite(
        self,
        test_data_dir: Path,
        pattern: str = "*.yar",
    ) -> None:
        """Profile all test files in a directory.

        Args:
            test_data_dir: Directory containing test YARA files
            pattern: Glob pattern for finding test files
        """
        test_files = sorted(test_data_dir.glob(pattern))

        if not test_files:
            print(f"No test files found in {test_data_dir} matching {pattern}")
            return

        print(f"\nFound {len(test_files)} test files")

        for test_file in test_files:
            self.compare_parsers(test_file)

        print("\nProfiling suite complete!")


def main() -> None:
    """Main entry point for profiling execution."""
    benchmark_dir = Path(__file__).parent
    test_data_dir = benchmark_dir / "test_data"
    results_dir = benchmark_dir / "results"

    print("YARA AST Parser cProfile Suite")
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

    # Create profiler
    profiler = ParserProfiler(results_dir)

    # Profile all test files
    profiler.profile_suite(test_data_dir)

    print("\nProfiler complete!")
    print("\nTo analyze .prof files, use:")
    print("  python -m pstats results/profile_*.prof")
    print("\nOr use visualization tools like:")
    print("  snakeviz results/profile_*.prof")
    print("  gprof2dot -f pstats results/profile_*.prof | dot -Tpng -o output.png")


if __name__ == "__main__":
    main()
