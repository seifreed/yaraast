"""Parallel analysis for YARA rules."""

from __future__ import annotations

import multiprocessing as mp
from pathlib import Path
from typing import TYPE_CHECKING, Any

from yaraast.analysis.dependency_analyzer import DependencyAnalyzer
from yaraast.analysis.rule_analyzer import RuleAnalyzer
from yaraast.performance.parallel_execution import analyze_rules as execution_analyze_rules
from yaraast.performance.parallel_execution import (
    analyze_with_custom_function as execution_analyze_with_custom_function,
)
from yaraast.performance.parallel_execution import (
    batch_analyze_files as execution_batch_analyze_files,
)
from yaraast.performance.parallel_execution import (
    profile_performance as execution_profile_performance,
)
from yaraast.performance.parallel_job_actions import (
    analyze_complexity_parallel as job_analyze_complexity_parallel,
)
from yaraast.performance.parallel_job_actions import (
    generate_graphs_parallel as job_generate_graphs_parallel,
)
from yaraast.performance.parallel_job_actions import (
    parse_files_parallel as job_parse_files_parallel,
)
from yaraast.performance.parallel_job_actions import process_batch as job_process_batch
from yaraast.performance.parallel_job_helpers import (
    analyze_file_path,
    default_parallel_stats,
    resettable_parallel_stats,
)
from yaraast.performance.parallel_models import Job

if TYPE_CHECKING:
    from collections.abc import Callable

    from yaraast.ast.base import YaraFile
    from yaraast.ast.rules import Rule


class ParallelAnalyzer:
    """Analyzes YARA rules in parallel for improved performance."""

    def __init__(self, max_workers: int | None = None) -> None:
        """Initialize parallel analyzer.

        Args:
            max_workers: Maximum number of parallel workers.
                        Defaults to CPU count.

        """
        self.max_workers = max_workers or mp.cpu_count()
        self.rule_analyzer = RuleAnalyzer()
        self._stats = default_parallel_stats()

    def __enter__(self) -> ParallelAnalyzer:
        """Enter context manager."""
        return self

    def __exit__(self, exc_type: Any, exc_val: Any, exc_tb: Any) -> None:
        """Exit context manager."""
        # Cleanup if needed
        pass

    def analyze_rules(
        self,
        rules: list[Rule],
        max_workers: int | None = None,
    ) -> list[dict[str, Any]]:
        """Analyze multiple rules in parallel.

        Args:
            rules: List of rules to analyze
            max_workers: Override default max workers

        Returns:
            List of analysis results

        """
        return execution_analyze_rules(self, rules, max_workers)

    def analyze_file(
        self,
        yara_file: YaraFile,
        max_workers: int | None = None,
    ) -> dict[str, Any]:
        """Analyze an entire YARA file in parallel.

        Args:
            yara_file: YARA file to analyze
            max_workers: Override default max workers

        Returns:
            Analysis results including rule analyses and dependencies

        """
        # Analyze rules in parallel
        rule_analyses = self.analyze_rules(yara_file.rules, max_workers)

        # Analyze dependencies (single-threaded for now)
        dep_analyzer = DependencyAnalyzer()
        dependencies = dep_analyzer.analyze(yara_file)

        return {
            "rules": rule_analyses,
            "dependencies": dependencies,
            "stats": {
                "total_rules": len(yara_file.rules),
                "analyzed": self._stats["rules_analyzed"],
                "errors": self._stats["errors"],
                "time": self._stats["total_time"],
            },
        }

    def batch_analyze_files(
        self,
        file_paths: list[str],
        max_workers: int | None = None,
    ) -> list[dict[str, Any]]:
        """Analyze multiple YARA files in parallel.

        Args:
            file_paths: List of file paths to analyze
            max_workers: Override default max workers

        Returns:
            List of file analysis results

        """
        return execution_batch_analyze_files(self, file_paths, max_workers)

    def analyze_with_custom_function(
        self,
        rules: list[Rule],
        analyze_func: Callable[[Rule], Any],
        max_workers: int | None = None,
    ) -> list[Any]:
        """Analyze rules with a custom analysis function.

        Args:
            rules: List of rules to analyze
            analyze_func: Custom analysis function
            max_workers: Override default max workers

        Returns:
            List of analysis results

        """
        return execution_analyze_with_custom_function(self, rules, analyze_func, max_workers)

    def _analyze_single_rule(self, rule: Rule) -> dict[str, Any]:
        """Analyze a single rule."""
        from yaraast.ast.base import YaraFile

        # RuleAnalyzer.analyze expects YaraFile, so wrap Rule in minimal YaraFile
        yara_file = YaraFile(imports=[], includes=[], rules=[rule])
        return self.rule_analyzer.analyze(yara_file)

    def _analyze_file_path(self, file_path: str) -> dict[str, Any]:
        """Analyze a file from path."""
        return analyze_file_path(file_path, self)

    def get_statistics(self) -> dict[str, Any]:
        """Get analysis statistics."""
        avg_time = 0.0
        if self._stats["rules_analyzed"] > 0:
            avg_time = self._stats["total_time"] / self._stats["rules_analyzed"]

        return {
            **self._stats,
            "avg_time_per_rule": avg_time,
            "max_workers": self.max_workers,
        }

    def reset_statistics(self) -> None:
        """Reset analysis statistics."""
        self._stats = resettable_parallel_stats()

    def optimize_worker_count(self, rules: list[Rule]) -> int:
        """Determine optimal worker count for rule set.

        Args:
            rules: Rules to analyze

        Returns:
            Optimal worker count

        """
        rule_count = len(rules)
        cpu_count = mp.cpu_count()

        # Heuristics for worker count
        if rule_count < 10:
            return 1  # Serial processing for small sets
        if rule_count < 50:
            return min(4, cpu_count)
        if rule_count < 200:
            return min(8, cpu_count)
        return cpu_count

    def analyze_complexity_parallel(
        self,
        asts: list[YaraFile],
        max_workers: int | None = None,
    ) -> list[Job]:
        """Analyze complexity of YARA files in parallel.

        Args:
            asts: List of YARA ASTs to analyze
            max_workers: Override default max workers

        Returns:
            List of Job objects

        """
        return job_analyze_complexity_parallel(self, asts, max_workers)

    def generate_graphs_parallel(
        self,
        asts: list[YaraFile],
        output_dir: str | Path,
        graph_types: list[str] | None = None,
    ) -> list[Job]:
        """Generate dependency graph exports for ASTs."""
        return job_generate_graphs_parallel(self, asts, output_dir, graph_types)

    def profile_performance(
        self,
        rules: list[Rule],
        worker_counts: list[int] | None = None,
    ) -> dict[str, Any]:
        """Profile performance with different worker counts.

        Args:
            rules: Rules to analyze
            worker_counts: Worker counts to test

        Returns:
            Performance profiling results

        """
        return execution_profile_performance(self, rules, worker_counts)

    def parse_files_parallel(
        self,
        file_paths: list,
        chunk_size: int = 10,
    ) -> list[Job]:
        """Parse multiple files in parallel and return jobs.

        Args:
            file_paths: List of file paths to parse
            chunk_size: Number of files per chunk

        Returns:
            List of Job objects

        """
        return job_parse_files_parallel(self, file_paths, chunk_size)

    def process_batch(
        self,
        items: list,
        worker_func: Callable,
        job_type: str = "batch",
        parameters: dict | None = None,
    ) -> list[Job]:
        """Process a batch of items with a custom worker function.

        Args:
            items: Items to process
            worker_func: Worker function to apply to each item
            job_type: Type of job for tracking
            parameters: Additional parameters for worker function

        Returns:
            List of Job objects

        """
        return job_process_batch(self, items, worker_func, job_type=job_type, parameters=parameters)
