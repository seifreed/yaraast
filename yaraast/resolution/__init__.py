"""Multi-file resolution package."""

from .dependency_graph import DependencyGraph, DependencyNode
from .include_resolver import IncludeResolver
from .workspace import Workspace, WorkspaceAnalyzer
from .workspace_models import FileAnalysisResult, WorkspaceReport

__all__ = [
    "DependencyGraph",
    "DependencyNode",
    "FileAnalysisResult",
    "IncludeResolver",
    "Workspace",
    "WorkspaceAnalyzer",
    "WorkspaceReport",
]
