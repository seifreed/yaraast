"""Workspace for analyzing multiple YARA files."""

from __future__ import annotations

from concurrent.futures import ThreadPoolExecutor, as_completed
from dataclasses import dataclass, field
from pathlib import Path

from yaraast.analysis.rule_analyzer import RuleAnalyzer
from yaraast.parser import Parser
from yaraast.resolution.dependency_graph import DependencyGraph
from yaraast.resolution.include_resolver import IncludeResolver, ResolvedFile
from yaraast.types.type_system import TypeValidator


@dataclass
class FileAnalysisResult:
    """Result of analyzing a single file."""

    path: Path
    resolved: ResolvedFile | None = None
    errors: list[str] = field(default_factory=list)
    warnings: list[str] = field(default_factory=list)
    type_errors: list[str] = field(default_factory=list)
    analysis_results: dict = field(default_factory=dict)


@dataclass
class WorkspaceReport:
    """Complete workspace analysis report."""

    files_analyzed: int
    total_rules: int
    total_includes: int
    total_imports: int
    dependency_graph: DependencyGraph
    file_results: dict[str, FileAnalysisResult]
    global_errors: list[str] = field(default_factory=list)
    statistics: dict = field(default_factory=dict)


class Workspace:
    """Workspace for managing multiple YARA files."""

    def __init__(
        self,
        root_path: str | None = None,
        search_paths: list[str] | None = None,
    ) -> None:
        """Initialize workspace.

        Args:
            root_path: Root directory of the workspace.
            search_paths: Additional search paths for includes.

        """
        self.root_path = Path(root_path) if root_path else Path.cwd()
        self.include_resolver = IncludeResolver(search_paths)
        self.files: dict[str, FileAnalysisResult] = {}
        self.dependency_graph = DependencyGraph()

    def add_file(self, file_path: str) -> FileAnalysisResult:
        """Add a single file to the workspace."""
        path = Path(file_path)
        if not path.is_absolute():
            path = self.root_path / path

        result = FileAnalysisResult(path=path)

        try:
            # Resolve file and includes
            resolved = self.include_resolver.resolve_file(str(path))
            result.resolved = resolved

            # Add to dependency graph
            self._add_to_dependency_graph(resolved)

        except FileNotFoundError as e:
            result.errors.append(f"File not found: {e}")
        except RecursionError as e:
            result.errors.append(f"Circular include: {e}")
        except Exception as e:
            result.errors.append(f"Parse error: {e}")

        self.files[str(path)] = result
        return result

    def add_directory(
        self,
        directory: str,
        pattern: str = "*.yar",
        recursive: bool = True,
    ) -> None:
        """Add all YARA files from a directory.

        Args:
            directory: Directory to scan.
            pattern: File pattern to match (supports glob).
            recursive: Whether to scan subdirectories.

        """
        dir_path = Path(directory)
        if not dir_path.is_absolute():
            dir_path = self.root_path / dir_path

        files = dir_path.rglob(pattern) if recursive else dir_path.glob(pattern)

        for file_path in files:
            if file_path.is_file():
                self.add_file(str(file_path))

    def _add_to_dependency_graph(self, resolved: ResolvedFile) -> None:
        """Add resolved file and its includes to dependency graph."""
        # Add main file
        self.dependency_graph.add_file(resolved.path, resolved.ast)

        # Add includes recursively
        for include in resolved.includes:
            self._add_to_dependency_graph(include)

    def analyze(
        self,
        parallel: bool = True,
        max_workers: int | None = None,
    ) -> WorkspaceReport:
        """Analyze all files in the workspace.

        Args:
            parallel: Whether to analyze files in parallel.
            max_workers: Maximum number of parallel workers.

        Returns:
            WorkspaceReport with complete analysis.

        """
        analyzer = WorkspaceAnalyzer(self)
        return analyzer.analyze(parallel, max_workers)

    def get_all_rules(self) -> list[tuple[str, str]]:
        """Get all rules with their file paths."""
        rules = []
        for file_path, result in self.files.items():
            if result.resolved:
                for rule in result.resolved.ast.rules:
                    rules.append((rule.name, file_path))
        return rules

    def find_rule(self, rule_name: str) -> tuple[str, any] | None:
        """Find a rule by name. Returns (file_path, rule) or None."""
        for file_path, result in self.files.items():
            if result.resolved:
                for rule in result.resolved.ast.rules:
                    if rule.name == rule_name:
                        return (file_path, rule)
        return None

    def get_file_dependencies(self, file_path: str) -> set[str]:
        """Get all files that this file depends on."""
        return self.dependency_graph.get_file_dependencies(file_path)

    def get_file_dependents(self, file_path: str) -> set[str]:
        """Get all files that depend on this file."""
        return self.dependency_graph.get_file_dependents(file_path)

    def get_all_files(self) -> list[str]:
        """Get all files in the workspace."""
        return list(self.files.keys())


class WorkspaceAnalyzer:
    """Analyzer for workspace files."""

    def __init__(self, workspace: Workspace) -> None:
        self.workspace = workspace
        self.parser = Parser()

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

        # Analyze files
        if parallel and len(self.workspace.files) > 1:
            self._analyze_parallel(report, max_workers)
        else:
            self._analyze_sequential(report)

        # Calculate statistics
        self._calculate_statistics(report)

        # Check for global issues
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

        report.files_analyzed += 1
        ast = result.resolved.ast

        # Count elements
        report.total_rules += len(ast.rules)
        report.total_includes += len(ast.includes)
        report.total_imports += len(ast.imports)

        # Type validation
        is_valid, type_errors = TypeValidator.validate(ast)
        if not is_valid:
            result.type_errors.extend(type_errors)

        # Rule analysis
        try:
            analyzer = RuleAnalyzer()
            analysis = analyzer.analyze(ast)
            result.analysis_results = {
                "unused_strings": analysis.get("unused_strings", []),
                "undefined_strings": analysis.get("undefined_strings", []),
                "rule_dependencies": analysis.get("dependencies", {}),
                "complexity": analysis.get("complexity_metrics", {}),
            }

            # Convert analysis results to warnings
            if analysis.get("unused_strings"):
                for rule_name, strings in analysis["unused_strings"].items():
                    for string in strings:
                        result.warnings.append(
                            f"Rule '{rule_name}': Unused string '{string}'",
                        )

            if analysis.get("undefined_strings"):
                for rule_name, strings in analysis["undefined_strings"].items():
                    for string in strings:
                        result.warnings.append(
                            f"Rule '{rule_name}': Undefined string '{string}'",
                        )

        except Exception as e:
            result.errors.append(f"Analysis error: {e}")

    def _calculate_statistics(self, report: WorkspaceReport) -> None:
        """Calculate workspace statistics."""
        # Basic counts
        report.statistics["file_count"] = report.files_analyzed
        report.statistics["rule_count"] = report.total_rules
        report.statistics["include_count"] = report.total_includes
        report.statistics["import_count"] = report.total_imports

        # Error counts
        total_errors = sum(len(r.errors) for r in report.file_results.values())
        total_warnings = sum(len(r.warnings) for r in report.file_results.values())
        total_type_errors = sum(len(r.type_errors) for r in report.file_results.values())

        report.statistics["total_errors"] = total_errors
        report.statistics["total_warnings"] = total_warnings
        report.statistics["total_type_errors"] = total_type_errors

        # Dependency graph stats
        graph_stats = report.dependency_graph.get_statistics()
        report.statistics.update(graph_stats)

        # Rule name conflicts
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
        # Check for dependency cycles
        cycles = report.dependency_graph.find_cycles()
        if cycles:
            for cycle in cycles:
                report.global_errors.append(
                    f"Dependency cycle detected: {' -> '.join(cycle)}",
                )

        # Check for missing includes
        for file_path, result in report.file_results.items():
            if result.resolved:
                for include in result.resolved.ast.includes:
                    # Check if include was resolved
                    if not any(inc.path.name == include.path for inc in result.resolved.includes):
                        report.global_errors.append(
                            f"File '{file_path}': Cannot resolve include '{include.path}'",
                        )

        # Check for duplicate rule names
        conflicts = report.statistics.get("conflicting_rules", {})
        for rule_name, files in conflicts.items():
            report.global_errors.append(
                f"Rule '{rule_name}' defined in multiple files: {', '.join(files)}",
            )
