#!/usr/bin/env python3
"""
Copyright (c) 2025 Marc Rivero López
Licensed under GPLv3. See LICENSE file for details.
This test suite validates real code behavior without mocks or stubs.

Comprehensive benchmark runner for YARA AST Parser.

This script runs all benchmarking tools in sequence and generates
a complete performance report.
"""

import sys
import time
from importlib import util
from pathlib import Path


def print_section(title: str) -> None:
    """Print a formatted section header.

    Args:
        title: Section title to display
    """
    print("\n" + "=" * 80)
    print(f"{title:^80}")
    print("=" * 80 + "\n")


def check_dependencies() -> bool:
    """Check if required dependencies are installed.

    Returns:
        True if all dependencies are available, False otherwise
    """
    missing = []

    if util.find_spec("psutil") is None:
        missing.append("psutil")

    if util.find_spec("pytest_benchmark") is None:
        missing.append("pytest-benchmark")

    if missing:
        print("Error: Missing required dependencies:")
        for dep in missing:
            print(f"  - {dep}")
        print("\nInstall with:")
        print("  pip install -r requirements.txt")
        return False

    return True


def check_test_files(test_data_dir: Path) -> bool:
    """Check if test files exist.

    Args:
        test_data_dir: Directory containing test files

    Returns:
        True if test files exist, False otherwise
    """
    if not test_data_dir.exists():
        return False

    test_files = list(test_data_dir.glob("*.yar"))
    return len(test_files) > 0


def generate_test_files(benchmark_dir: Path) -> bool:
    """Generate test files using the generator.

    Args:
        benchmark_dir: Benchmarks directory

    Returns:
        True if generation succeeded, False otherwise
    """
    print_section("Step 1: Generating Test Files")

    try:
        from benchmarks.test_file_generator import generate_test_files

        test_data_dir = benchmark_dir / "test_data"
        results = generate_test_files(test_data_dir)

        print(f"\nSuccessfully generated {len(results)} test files")
        total_size = sum(r["actual_size_mb"] for r in results)
        print(f"Total size: {total_size:.2f} MB")

        return True

    except Exception as e:
        print(f"Error generating test files: {e}")
        return False


def run_benchmarks(benchmark_dir: Path) -> bool:
    """Run performance benchmarks.

    Args:
        benchmark_dir: Benchmarks directory

    Returns:
        True if benchmarks succeeded, False otherwise
    """
    print_section("Step 2: Running Performance Benchmarks")

    try:
        from benchmarks.benchmark_large_files import ParserBenchmark

        test_data_dir = benchmark_dir / "test_data"
        results_dir = benchmark_dir / "results"

        benchmark = ParserBenchmark(results_dir)
        benchmark.benchmark_suite(test_data_dir)

        # Save results
        benchmark.save_results()
        benchmark.generate_report()

        print("\nPerformance benchmarks completed successfully")
        return True

    except Exception as e:
        print(f"Error running benchmarks: {e}")
        import traceback

        traceback.print_exc()
        return False


def run_memory_profiling(benchmark_dir: Path) -> bool:
    """Run memory profiling.

    Args:
        benchmark_dir: Benchmarks directory

    Returns:
        True if profiling succeeded, False otherwise
    """
    print_section("Step 3: Running Memory Profiling")

    try:
        from benchmarks.memory_profiler import MemoryProfiler

        test_data_dir = benchmark_dir / "test_data"
        results_dir = benchmark_dir / "results"

        profiler = MemoryProfiler(sampling_interval=0.1)

        # Profile first 3 test files to save time
        test_files = sorted(test_data_dir.glob("*.yar"))[:3]

        for test_file in test_files:
            print(f"\nProfiling {test_file.name}...")
            results = profiler.compare_parsers(test_file, detailed=True)

            # Save profiles
            for parser_type, profile in results.items():
                filename = f"memory_profile_{parser_type}_{test_file.stem}.txt"
                profiler.save_profile(profile, results_dir / filename)

        print("\nMemory profiling completed successfully")
        return True

    except Exception as e:
        print(f"Error running memory profiling: {e}")
        import traceback

        traceback.print_exc()
        return False


def run_cpu_profiling(benchmark_dir: Path) -> bool:
    """Run CPU profiling.

    Args:
        benchmark_dir: Benchmarks directory

    Returns:
        True if profiling succeeded, False otherwise
    """
    print_section("Step 4: Running CPU Profiling")

    try:
        from benchmarks.profiler import ParserProfiler

        test_data_dir = benchmark_dir / "test_data"
        results_dir = benchmark_dir / "results"

        profiler = ParserProfiler(results_dir)

        # Profile first 2 test files to save time
        test_files = sorted(test_data_dir.glob("*.yar"))[:2]

        for test_file in test_files:
            print(f"\nProfiling {test_file.name}...")
            profiler.compare_parsers(test_file)

        print("\nCPU profiling completed successfully")
        return True

    except Exception as e:
        print(f"Error running CPU profiling: {e}")
        import traceback

        traceback.print_exc()
        return False


def generate_summary_report(benchmark_dir: Path) -> None:
    """Generate a comprehensive summary report.

    Args:
        benchmark_dir: Benchmarks directory
    """
    print_section("Step 5: Generating Summary Report")

    results_dir = benchmark_dir / "results"
    summary_file = results_dir / "summary_report.txt"

    with open(summary_file, "w", encoding="utf-8") as f:
        f.write("YARA AST Parser - Comprehensive Benchmark Summary\n")
        f.write("=" * 80 + "\n\n")
        f.write(f"Generated: {time.strftime('%Y-%m-%d %H:%M:%S')}\n\n")

        # List all result files
        f.write("Generated Reports:\n")
        f.write("-" * 80 + "\n\n")

        result_files = sorted(results_dir.glob("*.txt"))
        for result_file in result_files:
            if result_file.name != "summary_report.txt":
                f.write(f"  - {result_file.name}\n")

        f.write("\n")

        # List profile files
        prof_files = sorted(results_dir.glob("*.prof"))
        if prof_files:
            f.write("\nProfile Files (use snakeviz or gprof2dot):\n")
            f.write("-" * 80 + "\n\n")
            for prof_file in prof_files:
                f.write(f"  - {prof_file.name}\n")

        f.write("\n")

        # List JSON results
        json_files = sorted(results_dir.glob("*.json"))
        if json_files:
            f.write("\nJSON Results (machine-readable):\n")
            f.write("-" * 80 + "\n\n")
            for json_file in json_files:
                f.write(f"  - {json_file.name}\n")

        f.write("\n" + "=" * 80 + "\n\n")
        f.write("Analysis Commands:\n")
        f.write("-" * 80 + "\n\n")
        f.write("View benchmark results:\n")
        f.write("  cat results/benchmark_report.txt\n\n")
        f.write("View memory profiles:\n")
        f.write("  cat results/memory_profile_*.txt\n\n")
        f.write("View CPU profiles:\n")
        f.write("  cat results/profile_comparison_*.txt\n\n")
        f.write("Interactive profile analysis:\n")
        f.write("  python -m pstats results/profile_*.prof\n\n")
        f.write("Visualize call graphs:\n")
        f.write("  snakeviz results/profile_*.prof\n\n")

    print(f"Summary report saved to: {summary_file}")


def main() -> int:
    """Main entry point for comprehensive benchmark suite.

    Returns:
        Exit code (0 for success, 1 for failure)
    """
    benchmark_dir = Path(__file__).parent

    print_section("YARA AST Parser - Comprehensive Benchmark Suite")

    print(f"Benchmark directory: {benchmark_dir}")
    print(f"Results directory: {benchmark_dir / 'results'}")

    # Check dependencies
    if not check_dependencies():
        return 1

    # Check if test files exist
    test_data_dir = benchmark_dir / "test_data"
    if not check_test_files(test_data_dir):
        print("\nTest files not found. Generating...")
        if not generate_test_files(benchmark_dir):
            return 1
    else:
        print(f"\nFound existing test files in {test_data_dir}")
        print("To regenerate, delete the test_data directory")

    # Run all benchmarks
    steps = [
        ("Performance Benchmarks", run_benchmarks),
        ("Memory Profiling", run_memory_profiling),
        ("CPU Profiling", run_cpu_profiling),
    ]

    failed_steps = []

    for step_name, step_func in steps:
        try:
            if not step_func(benchmark_dir):
                failed_steps.append(step_name)
        except Exception as e:
            print(f"\nError in {step_name}: {e}")
            failed_steps.append(step_name)

    # Generate summary
    generate_summary_report(benchmark_dir)

    # Print final status
    print_section("Benchmark Suite Complete")

    if failed_steps:
        print("Warning: Some steps failed:")
        for step in failed_steps:
            print(f"  - {step}")
        print("\nCheck error messages above for details")
        return 1

    print("All benchmarks completed successfully!")
    print(f"\nResults available in: {benchmark_dir / 'results'}")
    print("\nNext steps:")
    print("  1. Review results/summary_report.txt")
    print("  2. Check results/benchmark_report.txt for performance data")
    print("  3. Analyze profiles in results/profile_*.txt")
    print("  4. Run pytest test_benchmarks.py for automated tests")

    return 0


if __name__ == "__main__":
    sys.exit(main())
