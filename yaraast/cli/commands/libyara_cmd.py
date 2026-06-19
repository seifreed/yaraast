"""CLI commands for LibYARA integration (compile, scan, optimize)."""

from __future__ import annotations

import click
from rich.console import Console

from yaraast.cli.libyara_handlers_compile import handle_compile
from yaraast.cli.libyara_handlers_optimize import handle_optimize
from yaraast.cli.libyara_handlers_scan import handle_scan
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
    handle_compile(console, input_file, output, optimize, debug, stats)


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
    handle_scan(console, rules_file, target, optimize, timeout, fast, stats)


# ==============================================================================
# Optimize Command
# ==============================================================================


@libyara.command()
@click.argument("input_file", type=click.Path(exists=True, dir_okay=False))
@click.option("--show-optimizations", is_flag=True, help="Show applied optimizations")
def optimize(input_file: str, show_optimizations: bool) -> None:
    """Optimize YARA rules using AST analysis."""
    handle_optimize(console, input_file, show_optimizations)
