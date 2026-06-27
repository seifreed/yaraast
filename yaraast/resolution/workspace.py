"""Workspace facade for multi-file YARA analysis."""

from __future__ import annotations

from collections.abc import Iterator
import hashlib
from os import PathLike, fspath
from pathlib import Path
from typing import TYPE_CHECKING

from yaraast.errors import YaraASTError
from yaraast.parser.source import parse_yara_source
from yaraast.resolution.dependency_graph import DependencyGraph, require_rule_lookup_name
from yaraast.resolution.include_resolver import IncludeResolver, ResolvedFile
from yaraast.resolution.workspace_analysis import WorkspaceAnalyzer
from yaraast.resolution.workspace_models import FileAnalysisResult, WorkspaceReport
from yaraast.shared.file_patterns import FilePatterns, iter_matching_files
from yaraast.shared.path_safety import path_is_symlink, path_is_within_directory

if TYPE_CHECKING:
    from yaraast.ast.rules import Rule

__all__ = [
    "FileAnalysisResult",
    "Workspace",
    "WorkspaceAnalyzer",
    "WorkspaceReport",
]


def _path_access_error(path: Path) -> ValueError:
    msg = f"path could not be accessed: {path}"
    return ValueError(msg)


def _path_exists(path: Path) -> bool:
    try:
        return path.exists()
    except OSError as exc:
        raise _path_access_error(path) from exc


def _path_is_dir(path: Path) -> bool:
    try:
        return path.is_dir()
    except OSError as exc:
        raise _path_access_error(path) from exc


def _path_exists_and_not_dir(path: Path) -> bool:
    return _path_exists(path) and not _path_is_dir(path)


def _require_path_within_root(path: Path, root_path: Path, *, name: str) -> Path:
    if not path.is_absolute():
        path = root_path / path
    if not path_is_within_directory(path, root_path):
        msg = f"{name} must stay within root_path"
        raise ValueError(msg)
    return path


class Workspace:
    """Workspace for managing multiple YARA files."""

    def __init__(
        self,
        root_path: str | PathLike[str] | None = None,
        search_paths: list[str] | None = None,
    ) -> None:
        """Initialize workspace.

        Args:
            root_path: Root directory of the workspace.
            search_paths: Additional search paths for includes.

        """
        self.root_path = self._require_root_path(root_path)
        self.include_resolver = IncludeResolver(search_paths)
        self.files: dict[str, FileAnalysisResult] = {}
        self.dependency_graph = DependencyGraph()

    def _require_root_path(self, root_path: object) -> Path:
        if root_path is None:
            return Path.cwd()
        if isinstance(root_path, bool | bytes) or not isinstance(root_path, str | PathLike):
            msg = "root_path must be a path"
            raise TypeError(msg)
        raw_path = fspath(root_path)
        if not isinstance(raw_path, str):
            msg = "root_path must be a text path"
            raise TypeError(msg)
        if not raw_path.strip():
            msg = "root_path must not be empty"
            raise ValueError(msg)
        path = Path(raw_path)
        if _path_exists_and_not_dir(path):
            msg = "root_path must be a directory"
            raise ValueError(msg)
        if path_is_symlink(path):
            msg = "root_path must not be a symlink"
            raise ValueError(msg)
        return path

    def add_file(self, file_path: str | PathLike[str]) -> FileAnalysisResult:
        """Add a single file to the workspace."""
        return self._add_file(file_path, rebuild_graph=True)

    def _add_file(
        self, file_path: str | PathLike[str], *, rebuild_graph: bool
    ) -> FileAnalysisResult:
        """Add a file and optionally rebuild the workspace dependency graph."""
        path = self._require_workspace_path(file_path, name="file_path")
        path = _require_path_within_root(path, self.root_path, name="file_path")

        result = FileAnalysisResult(path=path)

        try:
            # Resolve file and includes
            resolved = self.include_resolver.resolve_file(str(path))
            result.resolved = resolved

        except FileNotFoundError as e:
            result.errors.append(f"File not found: {e}")
            if path.is_file():
                result.resolved = self._resolve_main_file_with_available_includes(path)
        except RecursionError as e:
            result.errors.append(f"Circular include: {e}")
        except (OSError, UnicodeDecodeError, ValueError, YaraASTError) as e:
            result.errors.append(f"Parse error: {e}")

        self.files[str(path)] = result
        if rebuild_graph:
            self._rebuild_dependency_graph()
        return result

    def _resolve_main_file_with_available_includes(self, path: Path) -> ResolvedFile:
        content = path.read_text(encoding="utf-8")
        ast = parse_yara_source(content)
        resolved = ResolvedFile(
            path=path.resolve(),
            content=content,
            ast=ast,
            checksum=hashlib.sha256(content.encode()).hexdigest(),
        )
        for include in ast.includes:
            try:
                included_file = self.include_resolver.resolve_file(
                    include.path,
                    base_path=path.parent,
                )
            except (FileNotFoundError, RecursionError, OSError, ValueError, YaraASTError):
                continue
            resolved.includes.append(included_file)
            resolved.include_path_map[include.path] = included_file.path
        return resolved

    def add_directory(
        self,
        directory: str | PathLike[str],
        pattern: FilePatterns = None,
        recursive: bool = True,
    ) -> None:
        """Add all YARA files from a directory.

        Args:
            directory: Directory to scan.
            pattern: File pattern or patterns to match (supports glob).
            recursive: Whether to scan subdirectories.

        """
        if not isinstance(recursive, bool):
            msg = "recursive must be a boolean"
            raise TypeError(msg)

        dir_path = self._require_workspace_path(directory, name="directory")
        dir_path = _require_path_within_root(dir_path, self.root_path, name="directory")

        for file_path in iter_matching_files(dir_path, pattern, recursive):
            self._add_file(str(file_path), rebuild_graph=False)
        self._rebuild_dependency_graph()

    def _require_workspace_path(self, value: object, *, name: str) -> Path:
        if isinstance(value, bool | bytes) or not isinstance(value, str | PathLike):
            msg = f"{name} must be a string or path-like object"
            raise TypeError(msg)
        raw_path = fspath(value)
        if not isinstance(raw_path, str):
            msg = f"{name} must be a string or path-like object"
            raise TypeError(msg)
        if not raw_path.strip():
            msg = f"{name} must not be empty"
            raise ValueError(msg)
        return Path(raw_path)

    def _rebuild_dependency_graph(self) -> None:
        """Rebuild dependency graph from the current successfully resolved files."""
        self.dependency_graph = DependencyGraph()
        for result in self.files.values():
            if result.resolved:
                self._add_to_dependency_graph(result.resolved)

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
        for file_path, resolved in self._iter_resolved_files():
            for rule in resolved.ast.rules:
                rules.append((rule.name, file_path))
        return rules

    def find_rule(self, rule_name: str) -> tuple[str, Rule] | None:
        """Find a rule by name. Returns (file_path, rule) or None."""
        rule_name = require_rule_lookup_name(rule_name)
        for file_path, resolved in self._iter_resolved_files():
            for rule in resolved.ast.rules:
                if rule.name == rule_name:
                    return (file_path, rule)
        return None

    def _iter_resolved_files(self) -> Iterator[tuple[str, ResolvedFile]]:
        """Iterate explicit workspace files and their resolved includes once."""
        seen: set[Path] = set()

        def walk(resolved: ResolvedFile, file_path: str) -> Iterator[tuple[str, ResolvedFile]]:
            if resolved.path in seen:
                return
            seen.add(resolved.path)
            yield file_path, resolved
            for included in resolved.includes:
                yield from walk(included, str(included.path))

        for file_path, result in self.files.items():
            if result.resolved:
                yield from walk(result.resolved, file_path)

    def get_file_dependencies(self, file_path: str) -> set[str]:
        """Get all files that this file depends on."""
        return self.dependency_graph.get_file_dependencies(file_path)

    def get_file_dependents(self, file_path: str) -> set[str]:
        """Get all files that depend on this file."""
        return self.dependency_graph.get_file_dependents(file_path)
