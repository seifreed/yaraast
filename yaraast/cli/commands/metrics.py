"""CLI commands for metrics and visualization."""

from __future__ import annotations

from pathlib import Path

import click

from yaraast.cli.metrics_reporting import (
    _display_pattern_result,
    _display_pattern_statistics,
    _display_successful_graph_result,
    _display_text_fallback,
    _display_text_pattern_analysis,
    _emit_text_output,
    _format_complexity_output,
    _format_string_analysis_output,
    _output_string_analysis_results,
    build_report_summary,
    complexity_quality_message,
    display_report_completion,
    write_complexity_report_files,
    write_report_summary,
)
from yaraast.cli.metrics_services import (
    analyze_complexity,
    build_report,
    determine_graph_output_path,
    determine_pattern_output_path,
    generate_dependency_graph_with_generator,
    generate_html_tree_file,
    generate_pattern_diagram_with_generator,
    is_graphviz_error,
    parse_yara_file,
)
from yaraast.cli.metrics_string_services import _analyze_string_patterns
from yaraast.metrics import METRICS

try:
    from yaraast.metrics import DependencyGraphGenerator
except ModuleNotFoundError:
    DependencyGraphGenerator = None  # type: ignore[assignment]


@click.group()
def metrics() -> None:
    """Analyze and visualize YARA AST metrics."""


@metrics.command()
@click.argument("yara_file", type=click.Path(exists=True, dir_okay=False))
@click.option(
    "--output",
    "-o",
    type=click.Path(),
    help="Output file for metrics report",
)
@click.option(
    "--format",
    "-f",
    type=click.Choice(["json", "text"]),
    default="text",
    help="Output format",
)
@click.option(
    "--quality-gate",
    type=int,
    default=70,
    help="Quality gate threshold (0-100)",
)
def complexity(yara_file: str, output: str | None, format: str, quality_gate: int) -> None:
    """Analyze YARA rule complexity metrics."""
    ast = parse_yara_file(yara_file)

    metrics = analyze_complexity(ast)

    output_text = _format_complexity_output(metrics, format)
    _emit_text_output(output_text, output, "Complexity metrics written to")

    quality_score = metrics.get_quality_score()
    message, ok = complexity_quality_message(quality_score, quality_gate)
    if ok:
        click.echo(message)
    else:
        click.echo(message, err=True)
        raise SystemExit(1)


@metrics.command()
@click.argument("yara_file", type=click.Path(exists=True, dir_okay=False))
@click.option("--output", "-o", type=click.Path(), help="Output file path")
@click.option(
    "--format",
    "-f",
    type=click.Choice(["svg", "png", "pdf", "dot"]),
    default="svg",
    help="Output format",
)
@click.option(
    "--type",
    "-t",
    type=click.Choice(["full", "rules", "modules", "complexity"]),
    default="full",
    help="Graph type to generate",
)
@click.option(
    "--engine",
    type=click.Choice(["dot", "neato", "fdp", "circo"]),
    default="dot",
    help="GraphViz layout engine",
)
def graph(yara_file: str, output: str | None, format: str, type: str, engine: str) -> None:
    """Generate dependency graphs with GraphViz."""
    if DependencyGraphGenerator is None:
        raise click.ClickException(
            "Graph visualization requires the 'graphviz' Python package. "
            "Install it to enable graph generation."
        )
    ast = parse_yara_file(yara_file)
    output_path = determine_graph_output_path(yara_file, output, type, format)
    generator = METRICS.new_dependency_graph_generator()

    try:
        result_path, _generator = generate_dependency_graph_with_generator(
            generator,
            ast,
            type,
            output_path,
            format,
            engine,
        )
        _display_successful_graph_result(result_path, generator)
    except Exception as e:
        if is_graphviz_error(e):
            _display_text_fallback(yara_file, ast, generator)
        else:
            raise
    else:
        click.echo("Graph source:")
        click.echo(result_path)


def _is_graphviz_not_found_error(error: Exception) -> bool:
    """Backward-compatible wrapper for older tests."""
    return is_graphviz_error(error)


@metrics.command()
@click.argument("yara_file", type=click.Path(exists=True, dir_okay=False))
@click.option("--output", "-o", type=click.Path(), help="Output HTML file path")
@click.option(
    "--interactive",
    is_flag=True,
    help="Generate interactive HTML with search",
)
@click.option("--title", default="YARA AST Visualization", help="Page title")
@click.option("--no-metadata", is_flag=True, help="Exclude metadata from visualization")
@click.option("--collapsible", is_flag=True, help="Generate collapsible tree")
def tree(
    yara_file: str,
    output: str | None,
    interactive: bool,
    title: str,
    no_metadata: bool,
    collapsible: bool,
) -> None:
    """Generate HTML collapsible tree visualization."""
    ast = parse_yara_file(yara_file)
    if not output:
        base_name = Path(yara_file).stem
        suffix = "interactive" if interactive else "tree"
        output = f"{base_name}_{suffix}.html"

    generate_html_tree_file(
        ast,
        output,
        title,
        interactive=interactive,
        include_metadata=not no_metadata,
    )

    click.echo(f"HTML tree visualization generated: {output}")

    # Show file size
    if Path(output).exists():
        size = Path(output).stat().st_size
        click.echo(f"File size: {size:,} bytes")


@metrics.command()
@click.argument("yara_file", type=click.Path(exists=True, dir_okay=False))
@click.option("--output", "-o", type=click.Path(), help="Output file path")
@click.option(
    "--type",
    "-t",
    type=click.Choice(["flow", "complexity", "similarity", "hex"]),
    default="flow",
    help="Diagram type to generate",
)
@click.option(
    "--format",
    "-f",
    type=click.Choice(["svg", "png", "pdf", "dot"]),
    default="svg",
    help="Output format",
)
@click.option("--stats", is_flag=True, help="Show pattern statistics")
def patterns(yara_file: str, output: str | None, type: str, format: str, stats: bool) -> None:
    """Generate string pattern analysis diagrams."""
    ast = parse_yara_file(yara_file)
    generator = METRICS.new_string_diagram_generator()
    output_path = determine_pattern_output_path(yara_file, output, type, format)

    try:
        result_path = generate_pattern_diagram_with_generator(
            generator,
            ast,
            type,
            output_path,
            format,
        )
        _display_pattern_result(result_path)
    except Exception as e:
        if is_graphviz_error(e):
            _display_text_pattern_analysis(generator, ast)
        else:
            raise

    if stats:
        _display_pattern_statistics(generator)


@metrics.command()
@click.argument("yara_file", type=click.Path(exists=True, dir_okay=False))
@click.option(
    "--output-dir",
    "-d",
    type=click.Path(),
    help="Output directory for all reports",
)
@click.option(
    "--format",
    "-f",
    type=click.Choice(["svg", "png"]),
    default="svg",
    help="Image format for graphs",
)
def report(yara_file: str, output_dir: str | None, format: str) -> None:
    """Generate comprehensive metrics report with all visualizations."""
    ast = parse_yara_file(yara_file)

    # Setup output directory
    if not output_dir:
        output_dir = Path(yara_file).stem + "_metrics_report"

    output_path = Path(output_dir)
    output_path.mkdir(exist_ok=True)

    base_name = Path(yara_file).stem

    click.echo(f"Generating comprehensive metrics report in {output_path}/")

    click.echo("📊 Analyzing complexity...")
    report_data = build_report(ast, output_path, base_name, format)

    complexity_files = write_complexity_report_files(
        output_path,
        base_name,
        report_data.complexity_metrics,
    )

    click.echo("🕸️  Generating dependency graphs...")
    click.echo("🌳 Generating HTML tree...")
    click.echo("🧩 Generating pattern diagrams...")

    click.echo("📋 Creating summary report...")
    summary = build_report_summary(yara_file, report_data, complexity_files)
    write_report_summary(output_path, summary)
    display_report_completion(output_path, summary, report_data.complexity_metrics)


@metrics.command()
@click.argument("yara_file", type=click.Path(exists=True, dir_okay=False))
@click.option("--output", "-o", type=click.Path(), help="Output file path")
@click.option(
    "--format",
    "-f",
    type=click.Choice(["json", "text"]),
    default="text",
    help="Output format",
)
def strings(yara_file: str, output: str | None, format: str) -> None:
    """Analyze string patterns in YARA rules."""
    ast = parse_yara_file(yara_file)
    analysis = _analyze_string_patterns(ast)

    # Format and output results
    output_text = _format_string_analysis_output(analysis, format)
    _output_string_analysis_results(output_text, output)
