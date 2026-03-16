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

console = Console()


@click.command(name="optimize")
@click.argument("input_file", type=click.Path(exists=True, path_type=Path))
@click.argument("output_file", type=click.Path(path_type=Path))
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
def optimize(input_file: Path, output_file: Path, dry_run: bool, analyze: bool) -> None:
    """Optimize YARA rules for better performance.

    This command automatically optimizes YARA rules by:
    - Replacing long wildcard sequences with jumps
    - Removing unnecessary regex anchors
    - Suggesting improvements for problematic patterns
    """
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
            display_write_start(console, output_file)
            optimized_code = generate_code(optimized_ast)
            output_file.write_text(optimized_code, encoding="utf-8")
            display_write_success(console, output_file)
        else:
            display_dry_run(console)

    except Exception as e:
        console.print(f"[red]❌ Error: {e}[/red]")
        raise click.Abort from e


# Export the command
optimize_cmd = optimize
