"""Workspace CLI commands."""

from __future__ import annotations

import click

from yaraast.cli.utils import _require_file_path, write_text
from yaraast.cli.workspace_reporting import print_include_tree
from yaraast.cli.workspace_services import (
    analyze_workspace,
    format_workspace_graph,
    format_workspace_output,
)


def _validate_output_path(output: str | None) -> str | None:
    if output is None:
        return None
    try:
        output_path = _require_file_path(output)
    except (TypeError, ValueError) as exc:
        raise click.BadParameter(str(exc), param_hint="--output") from exc
    if output_path.exists() and output_path.is_dir():
        raise click.BadParameter("output path must not be a directory", param_hint="--output")
    return output


@click.group()
def workspace() -> None:
    """Workspace commands for multi-file analysis."""


@workspace.command()
@click.argument("directory", type=click.Path(exists=True, file_okay=False))
@click.option(
    "--pattern",
    "-p",
    default=None,
    help="File pattern to match; defaults to *.yar and *.yara",
)
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
    output = _validate_output_path(output)
    click.echo(f"Analyzing directory: {directory}")

    ws, report = analyze_workspace(directory, pattern, recursive, parallel)
    click.echo(f"Found {len(ws.files)} YARA files")

    output_text = format_workspace_output(report, format)

    # Output
    if output is not None:
        write_text(output, output_text)
        click.echo(f"Report written to: {output}")
    else:
        click.echo(output_text)


@workspace.command()
@click.argument("file", type=click.Path(exists=True, dir_okay=False))
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

    except (FileNotFoundError, RecursionError) as e:
        click.echo(f"Error: {e}", err=True)
        raise click.Abort() from None


@workspace.command()
@click.argument("directory", type=click.Path(exists=True, file_okay=False))
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
    output = _validate_output_path(output)
    click.echo(f"Building dependency graph for: {directory}")

    _ws, report = analyze_workspace(directory, None, True, True)
    output_text = format_workspace_graph(report, format)

    # Output
    if output is not None:
        write_text(output, output_text)
        click.echo(f"Graph written to: {output}")
        if format == "dot":
            click.echo(f"Visualize with: dot -Tpng {output} -o graph.png")
    else:
        click.echo(output_text)
