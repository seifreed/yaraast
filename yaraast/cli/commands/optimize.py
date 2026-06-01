"""Optimize YARA rules for better performance."""

from __future__ import annotations

from pathlib import Path

import click
from rich.console import Console

from yaraast.cli.optimize_reporting import (
    display_analysis,
    display_changes,
    display_dry_run,
    display_improvement,
    display_write_start,
    display_write_success,
)
from yaraast.cli.optimize_services import (
    analyze_performance,
    calculate_improvement,
    generate_code,
    optimize_ast,
    parse_yara_with_tolerance,
)
from yaraast.cli.utils import _require_file_path

console = Console()


def _validate_output_path(output_file: str | None) -> Path:
    try:
        output_path = _require_file_path(output_file)
    except (TypeError, ValueError) as exc:
        raise click.BadParameter(str(exc), param_hint="OUTPUT_FILE") from exc
    if output_path.exists() and output_path.is_dir():
        raise click.BadParameter(
            "output path must not be a directory",
            param_hint="OUTPUT_FILE",
        )
    return output_path


@click.command(name="optimize")
@click.argument("input_file", type=click.Path(exists=True, dir_okay=False, path_type=Path))
@click.argument("output_file", type=click.Path())
@click.option(
    "--dry-run",
    is_flag=True,
    help="Show what would be changed without writing the file",
)
@click.option(
    "--analyze",
    is_flag=True,
    help="Show performance analysis before and after optimization",
)
def optimize(input_file: Path, output_file: str, dry_run: bool, analyze: bool) -> None:
    """Optimize YARA rules for better performance.

    This command automatically optimizes YARA rules by:
    - Replacing long wildcard sequences with jumps
    - Removing unnecessary regex anchors
    - Suggesting improvements for problematic patterns
    """
    output_path = _validate_output_path(output_file)
    try:
        # Parse the YARA file
        with console.status("[cyan]Parsing YARA file..."):
            content = input_file.read_text(encoding="utf-8")
            ast, _, _ = parse_yara_with_tolerance(content)

        # Analyze performance before optimization
        if analyze:
            before = analyze_performance(ast)
            display_analysis(console, "Performance analysis before optimization", before)

        # Optimize the AST
        console.print(f"\n[cyan]Optimizing {len(ast.rules)} rules...[/cyan]")
        optimized_ast, changes = optimize_ast(ast)

        display_changes(console, changes)

        # Analyze performance after optimization
        if analyze:
            after = analyze_performance(optimized_ast)
            display_analysis(console, "Performance analysis after optimization", after)

            improvement = calculate_improvement(before, after)
            if improvement is not None:
                display_improvement(console, improvement)

        # Generate optimized code
        if not dry_run:
            display_write_start(console, output_path)
            optimized_code = generate_code(optimized_ast)
            output_path.write_text(optimized_code, encoding="utf-8")
            display_write_success(console, output_path)
        else:
            display_dry_run(console)

    except Exception as e:
        console.print(f"[red]❌ Error: {e}[/red]")
        raise click.Abort from e


# Export the command
optimize_cmd = optimize
