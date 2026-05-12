"""Workspace facade for multi-file YARA analysis."""

from __future__ import annotations

from collections.abc import Iterable
from pathlib import Path
from typing import TYPE_CHECKING

from yaraast.resolution.dependency_graph import DependencyGraph
from yaraast.resolution.include_resolver import IncludeResolver, ResolvedFile
from yaraast.resolution.workspace_analysis import WorkspaceAnalyzer
from yaraast.resolution.workspace_models import FileAnalysisResult, WorkspaceReport

if TYPE_CHECKING:
    from yaraast.ast.rules import Rule

__all__ = [
    "FileAnalysisResult",
    "Workspace",
    "WorkspaceAnalyzer",
    "WorkspaceReport",
]

DEFAULT_YARA_FILE_PATTERNS = ("*.yar", "*.yara")


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
        pattern: str | Iterable[str] | None = None,
        recursive: bool = True,
    ) -> None:
        """Add all YARA files from a directory.

        Args:
            directory: Directory to scan.
            pattern: File pattern or patterns to match (supports glob).
            recursive: Whether to scan subdirectories.

        """
        dir_path = Path(directory)
        if not dir_path.is_absolute():
            dir_path = self.root_path / dir_path

        seen: set[Path] = set()
        for file_path in self._iter_directory_files(dir_path, pattern, recursive):
            if file_path.is_file():
                if file_path in seen:
                    continue
                seen.add(file_path)
                self.add_file(str(file_path))

    def _iter_directory_files(
        self,
        directory: Path,
        pattern: str | Iterable[str] | None,
        recursive: bool,
    ) -> Iterable[Path]:
        patterns = self._normalize_patterns(pattern)
        for file_pattern in patterns:
            yield from (
                directory.rglob(file_pattern) if recursive else directory.glob(file_pattern)
            )

    def _normalize_patterns(
        self,
        pattern: str | Iterable[str] | None,
    ) -> tuple[str, ...]:
        if pattern is None:
            return DEFAULT_YARA_FILE_PATTERNS
        if isinstance(pattern, str):
            return (pattern,)
        return tuple(pattern)

    def _add_to_dependency_graph(self, resolved: ResolvedFile) -> None:
        """Add resolved file and its includes to dependency graph."""
        # Add main file
        self.dependency_graph.add_file(
            resolved.path,
            resolved.ast,
            include_resolutions=resolved.include_path_map,
        )

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

    def find_rule(self, rule_name: str) -> tuple[str, Rule] | None:
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
