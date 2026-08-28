"""YARA AST - A Python library for parsing and manipulating YARA rules."""

from importlib.metadata import version

from yaraast import reporters
from yaraast.api import (
    ParsedDocument,
    SourceEdit,
    format_canonical,
    generate,
    parse,
    parse_file,
    rewrite_lossless,
)
from yaraast.diagnostics import Diagnostic, DiagnosticResult, Severity, SourceFix
from yaraast.limits import CancellationToken, ResourceLimits
from yaraast.plugins import DiagnosticProvider, PluginInfo
from yaraast.project import Project
from yaraast.project_config import ProjectConfig, Suppression
from yaraast.refactor import RefactorResult
from yaraast.targets import TargetProfile

__version__ = version("yaraast")

__all__ = [
    "CancellationToken",
    "Diagnostic",
    "DiagnosticProvider",
    "DiagnosticResult",
    "ParsedDocument",
    "PluginInfo",
    "Project",
    "ProjectConfig",
    "RefactorResult",
    "ResourceLimits",
    "Severity",
    "SourceEdit",
    "SourceFix",
    "Suppression",
    "TargetProfile",
    "__version__",
    "format_canonical",
    "generate",
    "parse",
    "parse_file",
    "reporters",
    "rewrite_lossless",
]
