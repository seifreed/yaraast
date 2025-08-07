"""Parallel analysis for YARA rules."""

from __future__ import annotations

import concurrent.futures
import multiprocessing as mp
import time
from typing import TYPE_CHECKING, Any

from yaraast.analysis.dependency_analyzer import DependencyAnalyzer
from yaraast.analysis.rule_analyzer import RuleAnalyzer

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
        self._stats = {
            "rules_analyzed": 0,
            "total_time": 0.0,
            "errors": 0,
        }

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
        max_workers = max_workers or self.max_workers
        results = []
        start_time = time.time()

        with concurrent.futures.ProcessPoolExecutor(
            max_workers=max_workers,
        ) as executor:
            # Submit all tasks
            future_to_rule = {
                executor.submit(self._analyze_single_rule, rule): rule for rule in rules
            }

            # Collect results
            for future in concurrent.futures.as_completed(future_to_rule):
                rule = future_to_rule[future]
                try:
                    result = future.result()
                    results.append(result)
                    self._stats["rules_analyzed"] += 1
                except Exception as e:
                    results.append(
                        {"rule": rule.name, "error": str(e), "analysis": None},
                    )
                    self._stats["errors"] += 1

        self._stats["total_time"] = time.time() - start_time
        return results

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
        max_workers = max_workers or self.max_workers
        results = []

        with concurrent.futures.ThreadPoolExecutor(max_workers=max_workers) as executor:
            # Submit file analysis tasks
            future_to_path = {
                executor.submit(self._analyze_file_path, path): path for path in file_paths
            }

            # Collect results
            for future in concurrent.futures.as_completed(future_to_path):
                path = future_to_path[future]
                try:
                    result = future.result()
                    results.append(result)
                except Exception as e:
                    results.append({"file": path, "error": str(e), "analysis": None})

        return results

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
        max_workers = max_workers or self.max_workers
        results = []

        with concurrent.futures.ProcessPoolExecutor(
            max_workers=max_workers,
        ) as executor:
            # Submit custom analysis tasks
            futures = [executor.submit(analyze_func, rule) for rule in rules]

            # Collect results
            for future in concurrent.futures.as_completed(futures):
                try:
                    result = future.result()
                    results.append(result)
                except Exception as e:
                    results.append({"error": str(e)})

        return results

    def _analyze_single_rule(self, rule: Rule) -> dict[str, Any]:
        """Analyze a single rule."""
        return self.rule_analyzer.analyze(rule)

    def _analyze_file_path(self, file_path: str) -> dict[str, Any]:
        """Analyze a file from path."""
        from yaraast.parser import Parser

        parser = Parser()
        with open(file_path) as f:
            content = f.read()

        yara_file = parser.parse(content)
        analysis = self.analyze_file(yara_file)
        analysis["file"] = file_path

        return analysis

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
        self._stats = {
            "rules_analyzed": 0,
            "total_time": 0.0,
            "errors": 0,
        }

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
        rules: list[Rule],
        max_workers: int | None = None,
    ) -> dict[str, Any]:
        """Analyze rule complexity in parallel.

        Args:
            rules: Rules to analyze
            max_workers: Override default max workers

        Returns:
            Complexity analysis results

        """
        max_workers = max_workers or self.optimize_worker_count(rules)

        # Analyze each rule
        analyses = self.analyze_rules(rules, max_workers)

        # Aggregate complexity metrics
        total_complexity = 0
        max_complexity = 0
        min_complexity = float("inf")

        for analysis in analyses:
            if "complexity" in analysis:
                complexity = analysis["complexity"]
                total_complexity += complexity
                max_complexity = max(max_complexity, complexity)
                min_complexity = min(min_complexity, complexity)

        avg_complexity = total_complexity / len(rules) if rules else 0

        return {
            "total_rules": len(rules),
            "total_complexity": total_complexity,
            "average_complexity": avg_complexity,
            "max_complexity": max_complexity,
            "min_complexity": min_complexity if min_complexity != float("inf") else 0,
            "analyses": analyses,
        }

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
        if not worker_counts:
            worker_counts = [1, 2, 4, 8, mp.cpu_count()]

        results = {}

        for workers in worker_counts:
            if workers > mp.cpu_count():
                continue

            start_time = time.time()
            self.analyze_rules(rules, max_workers=workers)
            elapsed = time.time() - start_time

            results[workers] = {
                "time": elapsed,
                "rules_per_second": len(rules) / elapsed if elapsed > 0 else 0,
            }

        return {
            "worker_performance": results,
            "optimal_workers": min(results, key=lambda k: results[k]["time"]),
            "rule_count": len(rules),
        }
