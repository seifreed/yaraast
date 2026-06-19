"""Service wrappers around metrics subsystem workflows."""

from __future__ import annotations

from collections.abc import Sequence
from pathlib import Path
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
    "generate_dependency_graph",
    "generate_dependency_graph_with_generator",
    "generate_dependency_graphs",
    "generate_html_tree",
    "generate_html_tree_file",
    "generate_pattern_diagram_with_generator",
    "generate_pattern_diagrams",
    "parse_yara_file",
]


def analyze_complexity(ast: YaraFile) -> Any:
    return _workflows.analyze_complexity(ast)


def generate_dependency_graphs(
    ast: YaraFile,
    output_dir: Path,
    base_name: str,
    image_format: str,
    generator_factory: Any = _DEFAULT_FACTORY,
) -> Sequence[str]:
    factory = (
        DependencyGraphGenerator if generator_factory is _DEFAULT_FACTORY else generator_factory
    )
    return _workflows.generate_dependency_graphs(ast, output_dir, base_name, image_format, factory)


def generate_html_tree(
    ast: YaraFile,
    output_dir: Path,
    base_name: str,
    interactive: bool = True,
    generator_factory: Any = None,
) -> str:
    if generator_factory is None:
        return _workflows.generate_html_tree(ast, output_dir, base_name, interactive)
    return _workflows.generate_html_tree(ast, output_dir, base_name, interactive, generator_factory)


def generate_pattern_diagrams(
    ast: YaraFile,
    output_dir: Path,
    base_name: str,
    image_format: str,
    generator_factory: Any = None,
) -> Sequence[str]:
    if generator_factory is None:
        return _workflows.generate_pattern_diagrams(ast, output_dir, base_name, image_format)
    return _workflows.generate_pattern_diagrams(
        ast, output_dir, base_name, image_format, generator_factory
    )


def determine_graph_output_path(yara_file: str, output: object, graph_type: str, fmt: str) -> str:
    return _workflows.determine_graph_output_path(yara_file, output, graph_type, fmt)


def generate_dependency_graph(
    ast: YaraFile,
    graph_type: str,
    output_path: str,
    fmt: str,
    engine: str,
) -> tuple[str, Any]:
    if DependencyGraphGenerator is None:
        msg = "Graph visualization requires the 'graphviz' Python package."
        raise RuntimeError(msg)
    return _workflows.generate_dependency_graph(ast, graph_type, output_path, fmt, engine)


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
