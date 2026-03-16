"""Workspace CLI commands."""

from __future__ import annotations

from pathlib import Path

import click

from yaraast.cli.workspace_reporting import print_include_tree
from yaraast.cli.workspace_services import (
    analyze_workspace,
    format_workspace_graph,
    format_workspace_output,
)


@click.group()
def workspace() -> None:
    """Workspace commands for multi-file analysis."""


@workspace.command()
@click.argument("directory", type=click.Path(exists=True))
@click.option("--pattern", "-p", default="*.yar", help="File pattern to match")
@click.option(
    "--recursive/--no-recursive",
    "-r/-R",
    default=True,
    help="Scan subdirectories",
)
@click.option("--output", "-o", type=click.Path(), help="Output file for report")
@click.option(
    "--format",
    "-f",
    type=click.Choice(["json", "text", "dot"]),
    default="text",
    help="Output format",
)
@click.option("--parallel/--sequential", default=True, help="Analyze files in parallel")
def analyze(directory, pattern, recursive, output, format, parallel) -> None:
    """Analyze all YARA files in a directory."""
    click.echo(f"Analyzing directory: {directory}")

    ws, report = analyze_workspace(directory, pattern, recursive, parallel)
    click.echo(f"Found {len(ws.files)} YARA files")

    output_text = format_workspace_output(report, format)

    # Output
    if output:
        Path(output).write_text(output_text)
        click.echo(f"Report written to: {output}")
    else:
        click.echo(output_text)


@workspace.command()
@click.argument("file", type=click.Path(exists=True))
@click.option(
    "--search-path",
    "-I",
    multiple=True,
    help="Additional include search paths",
)
@click.option("--show-tree/--no-tree", default=True, help="Show include tree")
def resolve(file, search_path, show_tree) -> None:
    """Resolve all includes for a YARA file."""
    from yaraast.resolution import IncludeResolver

    click.echo(f"Resolving includes for: {file}")

    # Create resolver
    resolver = IncludeResolver(search_paths=list(search_path))

    try:
        # Resolve
        resolved = resolver.resolve_file(file)

        click.echo(f"Successfully resolved {len(resolved.includes)} includes")

        if show_tree:
            # Show include tree
            tree = resolver.get_include_tree(file)
            print_include_tree(tree)

        # Show all resolved files
        all_files = resolver.get_all_resolved_files()
        click.echo(f"\nTotal files in resolution cache: {len(all_files)}")
        for resolved_file in all_files:
            click.echo(f"  - {resolved_file.path}")

    except RecursionError as e:
        click.echo(f"Error: {e}", err=True)
        raise click.Abort from None


@workspace.command()
@click.argument("directory", type=click.Path(exists=True))
@click.option("--output", "-o", type=click.Path(), help="Output file for graph")
@click.option(
    "--format",
    "-f",
    type=click.Choice(["dot", "json"]),
    default="dot",
    help="Output format",
)
def graph(directory, output, format) -> None:
    """Generate dependency graph for YARA files."""
    click.echo(f"Building dependency graph for: {directory}")

    ws, report = analyze_workspace(directory, "*.yar", True, True)
    output_text = format_workspace_graph(report, format)

    # Output
    if output:
        Path(output).write_text(output_text)
        click.echo(f"Graph written to: {output}")
        if format == "dot":
            click.echo(f"Visualize with: dot -Tpng {output} -o graph.png")
    else:
        click.echo(output_text)
