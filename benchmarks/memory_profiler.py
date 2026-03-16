"""
Copyright (c) 2025 Marc Rivero López
Licensed under GPLv3. See LICENSE file for details.
This test suite validates real code behavior without mocks or stubs.

Memory profiling utilities for YARA AST Parser.

This module provides detailed memory profiling capabilities
for analyzing parser memory consumption patterns.
"""

import gc
import time
from dataclasses import dataclass, field
from pathlib import Path

import psutil

from yaraast.parser import Parser
from yaraast.performance.streaming_parser import StreamingParser


@dataclass
class MemorySnapshot:
    """Snapshot of memory usage at a specific point in time."""

    timestamp: float
    rss_mb: float  # Resident Set Size
    vms_mb: float  # Virtual Memory Size
    percent: float  # Memory percentage
    description: str


@dataclass
class MemoryProfile:
    """Complete memory profile for a parsing operation."""

    parser_type: str
    file_path: str
    file_size_mb: float
    snapshots: list[MemorySnapshot] = field(default_factory=list)
    peak_rss_mb: float = 0.0
    peak_vms_mb: float = 0.0
    average_rss_mb: float = 0.0
    memory_growth_mb: float = 0.0
    parse_time_seconds: float = 0.0
    success: bool = True
    error_message: str | None = None

    def calculate_statistics(self) -> None:
        """Calculate memory statistics from snapshots."""
        if not self.snapshots:
            return

        rss_values = [s.rss_mb for s in self.snapshots]
        vms_values = [s.vms_mb for s in self.snapshots]

        self.peak_rss_mb = max(rss_values)
        self.peak_vms_mb = max(vms_values)
        self.average_rss_mb = sum(rss_values) / len(rss_values)

        if len(self.snapshots) >= 2:
            self.memory_growth_mb = self.snapshots[-1].rss_mb - self.snapshots[0].rss_mb


class MemoryProfiler:
    """Profile memory usage during YARA parsing operations."""

    def __init__(self, sampling_interval: float = 0.1) -> None:
        """Initialize the memory profiler.

        Args:
            sampling_interval: Time interval between memory samples in seconds
        """
        self.sampling_interval = sampling_interval
        self.process = psutil.Process()

    def take_snapshot(self, description: str = "") -> MemorySnapshot:
        """Take a snapshot of current memory usage.

        Args:
            description: Description of this snapshot point

        Returns:
            MemorySnapshot containing current memory metrics
        """
        mem_info = self.process.memory_info()
        mem_percent = self.process.memory_percent()

        return MemorySnapshot(
            timestamp=time.perf_counter(),
            rss_mb=mem_info.rss / (1024 * 1024),
            vms_mb=mem_info.vms / (1024 * 1024),
            percent=mem_percent,
            description=description,
        )

    def profile_standard_parser(
        self,
        file_path: Path,
        detailed: bool = True,
    ) -> MemoryProfile:
        """Profile memory usage of the standard Parser.

        Args:
            file_path: Path to YARA file to parse
            detailed: Whether to take detailed snapshots during parsing

        Returns:
            MemoryProfile containing detailed memory metrics
        """
        profile = MemoryProfile(
            parser_type="Standard Parser",
            file_path=str(file_path),
            file_size_mb=file_path.stat().st_size / (1024 * 1024),
        )

        gc.collect()
        profile.snapshots.append(self.take_snapshot("Before parsing"))

        try:
            start_time = time.perf_counter()

            # Read file
            content = file_path.read_text(encoding="utf-8")
            if detailed:
                profile.snapshots.append(self.take_snapshot("After reading file"))

            # Create parser
            parser = Parser(content)
            if detailed:
                profile.snapshots.append(self.take_snapshot("After creating parser"))

            # Parse
            parser.parse()
            parse_time = time.perf_counter() - start_time

            profile.snapshots.append(self.take_snapshot("After parsing"))
            profile.parse_time_seconds = parse_time

            # Force garbage collection to see retained memory
            del content
            del parser
            gc.collect()

            if detailed:
                profile.snapshots.append(self.take_snapshot("After cleanup"))

            profile.success = True

        except Exception as e:
            profile.success = False
            profile.error_message = str(e)
            profile.snapshots.append(self.take_snapshot("After error"))

        profile.calculate_statistics()
        return profile

    def profile_streaming_parser(
        self,
        file_path: Path,
        detailed: bool = True,
    ) -> MemoryProfile:
        """Profile memory usage of the StreamingParser.

        Args:
            file_path: Path to YARA file to parse
            detailed: Whether to take detailed snapshots during parsing

        Returns:
            MemoryProfile containing detailed memory metrics
        """
        profile = MemoryProfile(
            parser_type="StreamingParser",
            file_path=str(file_path),
            file_size_mb=file_path.stat().st_size / (1024 * 1024),
        )

        gc.collect()
        profile.snapshots.append(self.take_snapshot("Before parsing"))

        try:
            start_time = time.perf_counter()

            # Create streaming parser
            parser = StreamingParser(buffer_size=8192)
            if detailed:
                profile.snapshots.append(self.take_snapshot("After creating parser"))

            # Parse file
            rules = []
            for rule_count, rule in enumerate(parser.parse_file(file_path), start=1):
                rules.append(rule)

                # Take periodic snapshots during streaming
                if detailed and rule_count % 100 == 0:
                    profile.snapshots.append(self.take_snapshot(f"After {rule_count} rules"))

            parse_time = time.perf_counter() - start_time
            profile.snapshots.append(self.take_snapshot("After parsing"))
            profile.parse_time_seconds = parse_time

            # Cleanup
            del rules
            del parser
            gc.collect()

            if detailed:
                profile.snapshots.append(self.take_snapshot("After cleanup"))

            profile.success = True

        except Exception as e:
            profile.success = False
            profile.error_message = str(e)
            profile.snapshots.append(self.take_snapshot("After error"))

        profile.calculate_statistics()
        return profile

    def compare_parsers(
        self,
        file_path: Path,
        detailed: bool = True,
    ) -> dict[str, MemoryProfile]:
        """Profile and compare both parser implementations.

        Args:
            file_path: Path to YARA file to parse
            detailed: Whether to take detailed snapshots

        Returns:
            Dictionary mapping parser type to MemoryProfile
        """
        print(f"\n{'=' * 60}")
        print(f"Memory profiling: {file_path.name}")
        print(f"File size: {file_path.stat().st_size / (1024 * 1024):.2f} MB")
        print(f"{'=' * 60}")

        results = {}

        # Profile standard parser
        print("\nProfiling Standard Parser...")
        results["standard"] = self.profile_standard_parser(file_path, detailed=detailed)
        self._print_profile(results["standard"])

        # Short pause
        time.sleep(1)
        gc.collect()

        # Profile streaming parser
        print("\nProfiling StreamingParser...")
        results["streaming"] = self.profile_streaming_parser(file_path, detailed=detailed)
        self._print_profile(results["streaming"])

        # Print comparison
        self._print_comparison(results)

        return results

    def _print_profile(self, profile: MemoryProfile) -> None:
        """Print memory profile details.

        Args:
            profile: Memory profile to print
        """
        if not profile.success:
            print(f"  Error: {profile.error_message}")
            return

        print(f"  Parse Time: {profile.parse_time_seconds:.3f} seconds")
        print(f"  Peak RSS: {profile.peak_rss_mb:.2f} MB")
        print(f"  Average RSS: {profile.average_rss_mb:.2f} MB")
        print(f"  Memory Growth: {profile.memory_growth_mb:.2f} MB")
        print(f"  Snapshots: {len(profile.snapshots)}")

    def _print_comparison(self, results: dict[str, MemoryProfile]) -> None:
        """Print comparison between memory profiles.

        Args:
            results: Dictionary of memory profiles
        """
        standard = results.get("standard")
        streaming = results.get("streaming")

        if not standard or not streaming:
            return

        if not standard.success or not streaming.success:
            print("\n  Warning: One or both parsers failed")
            return

        print("\n  Memory Comparison:")
        print(f"  {'Metric':<30} {'Standard':<15} {'Streaming':<15} {'Difference':<15}")
        print(f"  {'-' * 75}")

        # Peak memory comparison
        peak_diff = (
            (streaming.peak_rss_mb - standard.peak_rss_mb) / standard.peak_rss_mb * 100
            if standard.peak_rss_mb > 0
            else 0
        )
        print(
            f"  {'Peak RSS (MB)':<30} "
            f"{standard.peak_rss_mb:<15.2f} "
            f"{streaming.peak_rss_mb:<15.2f} "
            f"{peak_diff:+.1f}%"
        )

        # Average memory comparison
        avg_diff = (
            (streaming.average_rss_mb - standard.average_rss_mb) / standard.average_rss_mb * 100
            if standard.average_rss_mb > 0
            else 0
        )
        print(
            f"  {'Average RSS (MB)':<30} "
            f"{standard.average_rss_mb:<15.2f} "
            f"{streaming.average_rss_mb:<15.2f} "
            f"{avg_diff:+.1f}%"
        )

        # Memory growth comparison
        growth_diff = (
            (streaming.memory_growth_mb - standard.memory_growth_mb)
            / standard.memory_growth_mb
            * 100
            if standard.memory_growth_mb > 0
            else 0
        )
        print(
            f"  {'Memory Growth (MB)':<30} "
            f"{standard.memory_growth_mb:<15.2f} "
            f"{streaming.memory_growth_mb:<15.2f} "
            f"{growth_diff:+.1f}%"
        )

    def save_profile(self, profile: MemoryProfile, output_path: Path) -> None:
        """Save memory profile to a text file.

        Args:
            profile: Memory profile to save
            output_path: Path where profile will be saved
        """
        with open(output_path, "w", encoding="utf-8") as f:
            f.write(f"Memory Profile: {profile.parser_type}\n")
            f.write("=" * 80 + "\n\n")
            f.write(f"File: {Path(profile.file_path).name}\n")
            f.write(f"File Size: {profile.file_size_mb:.2f} MB\n")
            f.write(f"Status: {'SUCCESS' if profile.success else 'FAILED'}\n\n")

            if profile.success:
                f.write("Summary:\n")
                f.write(f"  Parse Time: {profile.parse_time_seconds:.3f} seconds\n")
                f.write(f"  Peak RSS: {profile.peak_rss_mb:.2f} MB\n")
                f.write(f"  Peak VMS: {profile.peak_vms_mb:.2f} MB\n")
                f.write(f"  Average RSS: {profile.average_rss_mb:.2f} MB\n")
                f.write(f"  Memory Growth: {profile.memory_growth_mb:.2f} MB\n\n")

                f.write("Detailed Snapshots:\n")
                f.write(f"{'Time':<12} {'RSS (MB)':<12} {'VMS (MB)':<12} {'%':<8} Description\n")
                f.write("-" * 80 + "\n")

                start_time = profile.snapshots[0].timestamp if profile.snapshots else 0

                for snapshot in profile.snapshots:
                    elapsed = snapshot.timestamp - start_time
                    f.write(
                        f"{elapsed:<12.3f} {snapshot.rss_mb:<12.2f} {snapshot.vms_mb:<12.2f} "
                        f"{snapshot.percent:<8.2f} {snapshot.description}\n"
                    )
            else:
                f.write(f"\nError: {profile.error_message}\n")

        print(f"Profile saved to: {output_path}")


def main() -> None:
    """Main entry point for memory profiling."""
    benchmark_dir = Path(__file__).parent
    test_data_dir = benchmark_dir / "test_data"
    results_dir = benchmark_dir / "results"
    results_dir.mkdir(parents=True, exist_ok=True)

    print("YARA AST Parser Memory Profiler")
    print("=" * 60)

    if not test_data_dir.exists():
        print(f"\nError: Test data directory not found: {test_data_dir}")
        return

    test_files = sorted(test_data_dir.glob("*.yar"))
    if not test_files:
        print(f"\nError: No test files found in {test_data_dir}")
        return

    print(f"\nFound {len(test_files)} test files")

    profiler = MemoryProfiler()

    for test_file in test_files:
        results = profiler.compare_parsers(test_file, detailed=True)

        # Save individual profiles
        for parser_type, profile in results.items():
            filename = f"memory_profile_{parser_type}_{test_file.stem}.txt"
            profiler.save_profile(profile, results_dir / filename)

        time.sleep(2)
        gc.collect()

    print("\nMemory profiling complete!")


if __name__ == "__main__":
    main()
