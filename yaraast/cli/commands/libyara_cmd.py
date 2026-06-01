"""CLI commands for LibYARA integration (compile, scan, optimize)."""

from __future__ import annotations

import click
from rich.console import Console

from yaraast.cli.libyara_handlers import handle_compile, handle_optimize, handle_scan
from yaraast.cli.utils import _require_file_path

console = Console()


@click.group()
def libyara() -> None:
    """LibYARA integration commands for compilation and scanning."""


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


# ==============================================================================
# Compile Command
# ==============================================================================


@libyara.command()
@click.argument("input_file", type=click.Path(exists=True))
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
@click.argument("rules_file", type=click.Path(exists=True))
@click.argument("target", type=click.Path(exists=True))
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
@click.argument("input_file", type=click.Path(exists=True))
@click.option("--show-optimizations", is_flag=True, help="Show applied optimizations")
def optimize(input_file: str, show_optimizations: bool) -> None:
    """Optimize YARA rules using AST analysis."""
    handle_optimize(console, input_file, show_optimizations)
