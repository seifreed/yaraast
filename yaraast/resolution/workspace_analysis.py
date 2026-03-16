"""Workspace analysis services."""

from __future__ import annotations

from concurrent.futures import ThreadPoolExecutor, as_completed
from threading import Lock
from typing import TYPE_CHECKING

from yaraast.analysis.rule_analyzer import RuleAnalyzer
from yaraast.resolution.workspace_models import FileAnalysisResult, WorkspaceReport

if TYPE_CHECKING:
    from yaraast.resolution.workspace import Workspace


class WorkspaceAnalyzer:
    """Analyzer for workspace files."""

    def __init__(self, workspace: Workspace) -> None:
        self.workspace = workspace
        self._report_lock = Lock()

    def analyze(
        self,
        parallel: bool = True,
        max_workers: int | None = None,
    ) -> WorkspaceReport:
        """Perform complete workspace analysis."""
        report = WorkspaceReport(
            files_analyzed=0,
            total_rules=0,
            total_includes=0,
            total_imports=0,
            dependency_graph=self.workspace.dependency_graph,
            file_results={},
        )

        if parallel and len(self.workspace.files) > 1:
            self._analyze_parallel(report, max_workers)
        else:
            self._analyze_sequential(report)

        self._calculate_statistics(report)
        self._check_global_issues(report)
        return report

    def _analyze_sequential(self, report: WorkspaceReport) -> None:
        """Analyze files sequentially."""
        for file_path, result in self.workspace.files.items():
            self._analyze_file(result, report)
            report.file_results[file_path] = result

    def _analyze_parallel(
        self,
        report: WorkspaceReport,
        max_workers: int | None = None,
    ) -> None:
        """Analyze files in parallel."""
        with ThreadPoolExecutor(max_workers=max_workers) as executor:
            future_to_file = {
                executor.submit(self._analyze_file, result, report): (file_path, result)
                for file_path, result in self.workspace.files.items()
            }

            for future in as_completed(future_to_file):
                file_path, result = future_to_file[future]
                try:
                    future.result()
                    report.file_results[file_path] = result
                except Exception as e:
                    result.errors.append(f"Analysis error: {e}")
                    report.file_results[file_path] = result

    def _analyze_file(self, result: FileAnalysisResult, report: WorkspaceReport) -> None:
        """Analyze a single file."""
        if not result.resolved:
            return
        ast = result.resolved.ast

        with self._report_lock:
            report.files_analyzed += 1
            report.total_rules += len(ast.rules)
            report.total_includes += len(ast.includes)
            report.total_imports += len(ast.imports)

        try:
            analyzer = RuleAnalyzer()
            analysis = analyzer.analyze(ast)
            string_analysis = analysis.get("string_analysis", {})

            unused_strings = {}
            undefined_strings = {}
            for rule_name, rule_data in string_analysis.items():
                if rule_data.get("unused"):
                    unused_strings[rule_name] = rule_data["unused"]
                if rule_data.get("undefined"):
                    undefined_strings[rule_name] = rule_data["undefined"]

            result.analysis_results = {
                "unused_strings": unused_strings,
                "undefined_strings": undefined_strings,
                "rule_dependencies": analysis.get("dependency_analysis", {}).get(
                    "dependencies", {}
                ),
                "complexity": analysis.get("quality_metrics", {}),
            }

            if unused_strings:
                for rule_name, strings in unused_strings.items():
                    for string in strings:
                        result.warnings.append(
                            f"Rule '{rule_name}': Unused string '{string}'",
                        )

            if undefined_strings:
                for rule_name, strings in undefined_strings.items():
                    for string in strings:
                        result.warnings.append(
                            f"Rule '{rule_name}': Undefined string '{string}'",
                        )

        except Exception as e:
            result.errors.append(f"Analysis error: {e}")

    def _calculate_statistics(self, report: WorkspaceReport) -> None:
        """Calculate workspace statistics."""
        report.statistics["file_count"] = report.files_analyzed
        report.statistics["rule_count"] = report.total_rules
        report.statistics["include_count"] = report.total_includes
        report.statistics["import_count"] = report.total_imports

        total_errors = sum(len(r.errors) for r in report.file_results.values())
        total_warnings = sum(len(r.warnings) for r in report.file_results.values())
        total_type_errors = sum(len(r.type_errors) for r in report.file_results.values())

        report.statistics["total_errors"] = total_errors
        report.statistics["total_warnings"] = total_warnings
        report.statistics["total_type_errors"] = total_type_errors

        graph_stats = report.dependency_graph.get_statistics()
        report.statistics.update(graph_stats)

        rule_names = {}
        for file_path, result in report.file_results.items():
            if result.resolved:
                for rule in result.resolved.ast.rules:
                    if rule.name not in rule_names:
                        rule_names[rule.name] = []
                    rule_names[rule.name].append(file_path)

        conflicts = {name: files for name, files in rule_names.items() if len(files) > 1}
        report.statistics["rule_name_conflicts"] = len(conflicts)
        report.statistics["conflicting_rules"] = conflicts

    def _check_global_issues(self, report: WorkspaceReport) -> None:
        """Check for workspace-wide issues."""
        cycles = report.dependency_graph.find_cycles()
        if cycles:
            for cycle in cycles:
                report.global_errors.append(
                    f"Dependency cycle detected: {' -> '.join(cycle)}",
                )

        for file_path, result in report.file_results.items():
            if result.resolved:
                for include in result.resolved.ast.includes:
                    resolved_names = {inc.path.name for inc in result.resolved.includes}
                    resolved_paths = {str(inc.path) for inc in result.resolved.includes}
                    include_path = include.path
                    if not (
                        include_path in resolved_names
                        or include_path in resolved_paths
                        or any(
                            str(inc.path).endswith(include_path) for inc in result.resolved.includes
                        )
                    ):
                        report.global_errors.append(
                            f"File '{file_path}': Cannot resolve include '{include.path}'",
                        )

        conflicts = report.statistics.get("conflicting_rules", {})
        for rule_name, files in conflicts.items():
            report.global_errors.append(
                f"Rule '{rule_name}' defined in multiple files: {', '.join(files)}",
            )
