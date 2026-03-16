"""Workspace report models."""

from __future__ import annotations

from dataclasses import dataclass, field
from pathlib import Path

from yaraast.resolution.dependency_graph import DependencyGraph
from yaraast.resolution.include_resolver import ResolvedFile


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
