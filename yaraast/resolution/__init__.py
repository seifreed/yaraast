"""Multi-file resolution package."""

from .dependency_graph import DependencyGraph, DependencyNode
from .include_resolver import IncludeResolver
from .workspace import Workspace, WorkspaceAnalyzer

__all__ = [
    "DependencyGraph",
    "DependencyNode",
    "IncludeResolver",
    "Workspace",
    "WorkspaceAnalyzer",
]
