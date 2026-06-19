"""Service wrappers around metrics subsystem workflows."""

from __future__ import annotations

from typing import Any

import click

from yaraast.ast.base import YaraFile
from yaraast.cli.utils import parse_yara_file as _parse_yara_file
from yaraast.errors import YaraASTError
from yaraast.metrics import (
    DependencyGraphGenerator,
    workflows as _workflows,
)
from yaraast.metrics.workflows import MetricsReportData

_DEFAULT_FACTORY = object()


__all__ = [
    "DependencyGraphGenerator",
    "MetricsReportData",
    "analyze_complexity",
    "determine_graph_output_path",
    "determine_pattern_output_path",
    "generate_dependency_graph_with_generator",
    "generate_html_tree_file",
    "generate_pattern_diagram_with_generator",
    "parse_yara_file",
]


def analyze_complexity(ast: YaraFile) -> Any:
    return _workflows.analyze_complexity(ast)


def determine_graph_output_path(yara_file: str, output: object, graph_type: str, fmt: str) -> str:
    return _workflows.determine_graph_output_path(yara_file, output, graph_type, fmt)


def generate_dependency_graph_with_generator(
    generator: Any,
    ast: YaraFile,
    graph_type: str,
    output_path: str,
    fmt: str,
    engine: str,
) -> tuple[str, Any]:
    return _workflows.generate_dependency_graph_with_generator(
        generator, ast, graph_type, output_path, fmt, engine
    )


def determine_pattern_output_path(
    yara_file: str, output: object, pattern_type: str, fmt: str
) -> str:
    return _workflows.determine_pattern_output_path(yara_file, output, pattern_type, fmt)


def generate_pattern_diagram_with_generator(
    generator: Any,
    ast: YaraFile,
    pattern_type: str,
    output_path: str,
    fmt: str,
) -> str:
    return _workflows.generate_pattern_diagram_with_generator(
        generator, ast, pattern_type, output_path, fmt
    )


def generate_html_tree_file(
    ast: YaraFile,
    output_path: str,
    title: str,
    interactive: bool,
    include_metadata: bool,
    default_collapsed: bool = False,
) -> str:
    return _workflows.generate_html_tree_file(
        ast, output_path, title, interactive, include_metadata, default_collapsed
    )


def parse_yara_file(yara_file: str) -> YaraFile:
    """Parse a YARA file into an AST.

    Surface syntax errors as a clean CLI error instead of an uncaught
    traceback so metrics subcommands exit non-zero with a readable message.
    """
    try:
        return _parse_yara_file(yara_file)
    except YaraASTError as exc:
        raise click.ClickException(f"Failed to parse {yara_file}: {exc}") from None
