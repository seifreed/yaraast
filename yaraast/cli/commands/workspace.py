"""Workspace CLI commands."""

import json
from pathlib import Path

import click

from yaraast.resolution import Workspace


@click.group()
def workspace() -> None:
    """Workspace commands for multi-file analysis."""


def _format_json_output(report):
    """Format report as JSON."""
    output_data = {
        "statistics": report.statistics,
        "files": {
            path: {
                "errors": result.errors,
                "warnings": result.warnings,
                "type_errors": result.type_errors,
                "analysis": result.analysis_results,
            }
            for path, result in report.file_results.items()
        },
        "global_errors": report.global_errors,
    }
    return json.dumps(output_data, indent=2)


def _format_text_output(report):
    """Format report as text."""
    lines = []
    lines.append("Workspace Analysis Report")
    lines.append("=" * 50)
    lines.append(f"Files analyzed: {report.files_analyzed}")
    lines.append(f"Total rules: {report.total_rules}")
    lines.append(f"Total includes: {report.total_includes}")
    lines.append(f"Total imports: {report.total_imports}")
    lines.append("")

    if report.global_errors:
        lines.append("Global Errors:")
        for error in report.global_errors:
            lines.append(f"  - {error}")
        lines.append("")

    # File-specific issues
    for file_path, result in report.file_results.items():
        if result.errors or result.warnings or result.type_errors:
            lines.extend(_format_file_issues(file_path, result))

    # Statistics
    lines.append("Statistics:")
    lines.append(f"  Total errors: {report.statistics.get('total_errors', 0)}")
    lines.append(f"  Total warnings: {report.statistics.get('total_warnings', 0)}")
    lines.append(
        f"  Total type errors: {report.statistics.get('total_type_errors', 0)}",
    )
    lines.append(f"  Dependency cycles: {report.statistics.get('cycles', 0)}")
    lines.append(
        f"  Rule name conflicts: {report.statistics.get('rule_name_conflicts', 0)}",
    )

    return "\n".join(lines)


def _format_file_issues(file_path, result):
    """Format issues for a single file."""
    lines = [f"File: {file_path}"]

    if result.errors:
        lines.append("  Errors:")
        for error in result.errors:
            lines.append(f"    - {error}")

    if result.warnings:
        lines.append("  Warnings:")
        for warning in result.warnings:
            lines.append(f"    - {warning}")

    if result.type_errors:
        lines.append("  Type Errors:")
        for error in result.type_errors:
            lines.append(f"    - {error}")

    lines.append("")
    return lines


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

    # Create workspace
    ws = Workspace(root_path=directory)
    ws.add_directory(directory, pattern=pattern, recursive=recursive)

    click.echo(f"Found {len(ws.files)} YARA files")

    # Analyze
    report = ws.analyze(parallel=parallel)

    # Format output
    if format == "json":
        output_text = _format_json_output(report)
    elif format == "dot":
        output_text = report.dependency_graph.export_dot()
    else:  # text format
        output_text = _format_text_output(report)

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
            _print_tree(tree)

        # Show all resolved files
        all_files = resolver.get_all_resolved_files()
        click.echo(f"\nTotal files in resolution cache: {len(all_files)}")
        for resolved_file in all_files:
            click.echo(f"  - {resolved_file.path}")

    except FileNotFoundError as e:
        click.echo(f"Error: {e}", err=True)
        raise click.Abort from None
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

    # Create workspace
    ws = Workspace(root_path=directory)
    ws.add_directory(directory, recursive=True)

    # Analyze to build graph
    report = ws.analyze(parallel=True)

    # Generate output
    if format == "dot":
        output_text = report.dependency_graph.export_dot()
    else:  # json
        nodes = {}
        for key, node in report.dependency_graph.nodes.items():
            nodes[key] = {
                "type": node.type,
                "dependencies": list(node.dependencies),
                "dependents": list(node.dependents),
                "metadata": node.metadata,
            }
        output_text = json.dumps({"nodes": nodes}, indent=2)

    # Output
    if output:
        Path(output).write_text(output_text)
        click.echo(f"Graph written to: {output}")
        if format == "dot":
            click.echo(f"Visualize with: dot -Tpng {output} -o graph.png")
    else:
        click.echo(output_text)


def _print_tree(tree, indent=0) -> None:
    """Print include tree."""
    prefix = "  " * indent
    click.echo(f"{prefix}- {Path(tree['path']).name}")
    for include in tree["includes"]:
        _print_tree(include, indent + 1)
