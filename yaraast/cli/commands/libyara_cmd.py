"""CLI commands for LibYARA integration (compile, scan, optimize)."""

from __future__ import annotations

import click
from rich.console import Console

from yaraast.cli.libyara_handlers_common import run_or_abort
from yaraast.cli.libyara_reporting import (
    display_compilation_errors,
    display_compilation_stats,
    display_compilation_success,
    display_compiled_rules_saved,
    display_generated_source_preview,
    display_matches,
    display_optimization_hints,
    display_optimization_stats,
    display_optimize_results,
    display_scan_failure,
    display_scan_stats,
    display_scan_summary,
)
from yaraast.cli.libyara_services import (
    compile_yara,
    ensure_yara_available,
    optimize_yara,
    scan_yara,
)
from yaraast.cli.utils import _validate_output_path

console = Console()


@click.group()
def libyara() -> None:
    """LibYARA integration commands for compilation and scanning."""


# ==============================================================================
# Compile Command
# ==============================================================================


@libyara.command()
@click.argument("input_file", type=click.Path(exists=True, dir_okay=False))
@click.option("-o", "--output", type=click.Path(), help="Output compiled rules file")
@click.option("--optimize", is_flag=True, help="Enable AST optimizations")
@click.option("--debug", is_flag=True, help="Enable debug mode with source generation")
@click.option("--stats", is_flag=True, help="Show compilation statistics")
def compile(
    input_file: str,
    output: str | None,
    optimize: bool,
    debug: bool,
    stats: bool,
) -> None:
    """Compile YARA file using direct AST compilation."""
    output = _validate_output_path(output)
    run_or_abort(ensure_yara_available, console)
    result, compiler, _ast = run_or_abort(compile_yara, console, input_file, optimize, debug)

    if not result.success:
        display_compilation_errors(console, result.errors)
        raise click.Abort from None

    display_compilation_success(console)

    if result.optimized:
        display_optimization_stats(console, result)

    if stats:
        display_compilation_stats(console, result, compiler)

    if output and result.compiled_rules:
        result.compiled_rules.save(output)
        display_compiled_rules_saved(console, output)

    if debug and result.generated_source:
        display_generated_source_preview(console, result.generated_source)


# ==============================================================================
# Scan Command (Refactored into smaller methods)
# ==============================================================================


@libyara.command()
@click.argument("rules_file", type=click.Path(exists=True, dir_okay=False))
@click.argument("target", type=click.Path(exists=True, dir_okay=False))
@click.option("--optimize", is_flag=True, help="Use optimized AST compilation")
@click.option("--timeout", type=click.IntRange(min=1), help="Scan timeout in seconds")
@click.option("--fast", is_flag=True, help="Fast mode (stop on first match)")
@click.option("--stats", is_flag=True, help="Show scan statistics")
def scan(
    rules_file: str,
    target: str,
    optimize: bool,
    timeout: int | None,
    fast: bool,
    stats: bool,
) -> None:
    """Scan file using optimized AST-based matcher."""
    run_or_abort(ensure_yara_available, console)
    scan_result, matcher, compile_result = run_or_abort(
        scan_yara,
        console,
        rules_file,
        target,
        optimize,
        timeout,
        fast,
    )
    if scan_result is None:
        display_compilation_errors(console, compile_result.errors)
        raise click.Abort from None
    if scan_result["success"]:
        console.print("[green]Scan completed[/green]")
        matches = scan_result["matches"]
        display_scan_summary(console, scan_result, matches)
        display_matches(console, matches)
        display_optimization_hints(console, scan_result)
        if stats:
            display_scan_stats(console, matcher)
    else:
        display_scan_failure(console, scan_result)
        raise click.Abort from None


# ==============================================================================
# Optimize Command
# ==============================================================================


@libyara.command()
@click.argument("input_file", type=click.Path(exists=True, dir_okay=False))
@click.option("--show-optimizations", is_flag=True, help="Show applied optimizations")
def optimize(input_file: str, show_optimizations: bool) -> None:
    """Optimize YARA rules using AST analysis."""
    run_or_abort(ensure_yara_available, console)
    optimizer, optimized_code = run_or_abort(optimize_yara, console, input_file)
    display_optimize_results(console, optimizer, show_optimizations, optimized_code)
