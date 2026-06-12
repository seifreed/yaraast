"""Reporting helpers for LibYARA CLI output."""

from __future__ import annotations

from typing import Any

from rich.markup import escape
from rich.syntax import Syntax


def display_missing_yara(console: Any) -> None:
    """Display missing yara-python message."""
    console.print("[red]yara-python is not installed[/red]")
    console.print("Install with: pip install yara-python")


def display_compilation_errors(console: Any, errors: list[Any]) -> None:
    """Display compilation errors."""
    console.print("[red]Compilation failed[/red]")
    for error in errors:
        console.print(f"[red]  - {escape(str(error))}[/red]")


def display_compilation_success(console: Any) -> None:
    """Display compilation success message."""
    console.print("[green]Compilation successful[/green]")


def display_optimization_stats(console: Any, result: Any) -> None:
    """Print optimization statistics."""
    console.print("[blue]Optimizations applied:[/blue]")
    if result.optimization_stats:
        opt_stats = result.optimization_stats
        console.print(f"  - Rules optimized: {opt_stats.rules_optimized}")
        console.print(f"  - Strings optimized: {opt_stats.strings_optimized}")
        console.print(f"  - Conditions simplified: {opt_stats.conditions_simplified}")
        console.print(f"  - Constants folded: {opt_stats.constant_folded}")


def display_compilation_stats(console: Any, result: Any, compiler: Any) -> None:
    """Print compilation statistics."""
    console.print("[blue]Compilation Stats:[/blue]")
    console.print(f"  - Compilation time: {result.compilation_time:.3f}s")
    console.print(f"  - AST nodes: {result.ast_node_count}")

    comp_stats = compiler.get_compilation_stats()
    console.print(f"  - Total compilations: {comp_stats['total_compilations']}")
    console.print(
        f"  - Success rate: {comp_stats['successful_compilations']}/{comp_stats['total_compilations']}",
    )


def display_compiled_rules_saved(console: Any, output: str) -> None:
    """Display saved compiled rules message."""
    console.print(f"[green]Compiled rules saved to {escape(output)}[/green]")


def display_generated_source_preview(console: Any, source: str) -> None:
    """Display generated source preview."""
    console.print("[dim]Generated source (first 200 chars):[/dim]")
    console.print(f"[dim]{escape(source[:200])}...[/dim]")


def display_scan_failure(console: Any, scan_result: dict[str, Any]) -> None:
    """Display scan failure details."""
    console.print(
        f"[red]Scan failed: {escape(str(scan_result.get('error', 'Unknown error')))}[/red]",
    )


def display_scan_summary(
    console: Any,
    scan_result: dict[str, Any],
    matches: list[dict[str, Any]],
) -> None:
    """Display scan summary information."""
    console.print("[blue]Results:[/blue]")
    console.print(f"  - Matches found: {len(matches)}")
    console.print(f"  - Scan time: {scan_result['scan_time']:.3f}s")
    console.print(f"  - Data size: {scan_result['data_size']} bytes")

    if scan_result.get("ast_enhanced"):
        console.print("  - AST-enhanced: Yes")
        console.print(f"  - Rule count: {scan_result['rule_count']}")


def display_matches(console: Any, matches: list[dict[str, Any]]) -> None:
    """Display individual match information."""
    if not matches:
        return

    console.print("\n[yellow]Matches:[/yellow]")
    for match in matches:
        _display_single_match(console, match)


def _display_single_match(console: Any, match: dict[str, Any]) -> None:
    """Display a single match with its details."""
    console.print(f"  [bold]{escape(str(match['rule']))}[/bold]")

    if match.get("tags"):
        tags = ", ".join(escape(str(tag)) for tag in match["tags"])
        console.print(f"     Tags: {tags}")

    if match.get("strings"):
        console.print(f"     Strings: {len(match['strings'])} found")

    if match.get("ast_context"):
        ctx = match["ast_context"]
        complexity = escape(str(ctx.get("condition_complexity", "N/A")))
        console.print(f"     Complexity: {complexity}")


def display_optimization_hints(console: Any, scan_result: dict[str, Any]) -> None:
    """Display optimization hints if available."""
    hints = scan_result.get("optimization_hints")
    if not hints:
        return

    console.print("\n[dim]Optimization Hints:[/dim]")
    for hint in hints:
        console.print(f"[dim]  - {escape(str(hint))}[/dim]")


def display_scan_stats(console: Any, matcher: Any) -> None:
    """Display scan statistics."""
    if not matcher:
        return

    matcher_stats = matcher.get_scan_stats()
    console.print("\n[blue]Scan Statistics:[/blue]")
    console.print(f"  - Total scans: {matcher_stats['total_scans']}")
    console.print(f"  - Success rate: {matcher_stats['success_rate']:.1%}")
    console.print(f"  - Average scan time: {matcher_stats['average_scan_time']:.3f}s")


def display_optimize_results(
    console: Any,
    optimizer: Any,
    show_optimizations: bool,
    optimized_code: str,
) -> None:
    """Display optimization results."""
    console.print("[green]Optimization completed[/green]")
    console.print("[blue]Optimization Stats:[/blue]")
    console.print(f"  - Rules optimized: {optimizer.stats.rules_optimized}")
    console.print(f"  - Strings optimized: {optimizer.stats.strings_optimized}")
    console.print(f"  - Conditions simplified: {optimizer.stats.conditions_simplified}")
    console.print(f"  - Constants folded: {optimizer.stats.constant_folded}")

    if show_optimizations and optimizer.optimizations_applied:
        console.print("\n[yellow]Applied Optimizations:[/yellow]")
        for opt in optimizer.optimizations_applied:
            console.print(f"  - {escape(str(opt))}")

    console.print("\n[dim]Optimized YARA code:[/dim]")
    syntax = Syntax(optimized_code, "yara", theme="monokai", line_numbers=True)
    console.print(syntax)


class LibYaraCommandError(Exception):
    """Internal error wrapper to trigger CLI abort."""


def handle_libyara_error(console: Any, error: Exception) -> None:
    """Handle libyara command errors uniformly."""
    if isinstance(error, RuntimeError):
        _handle_runtime_error(console, error)
        raise LibYaraCommandError
    if isinstance(error, ImportError):
        _handle_import_error(console, error)
        raise LibYaraCommandError

    console.print(f"[red]Error: {escape(str(error))}[/red]")
    raise LibYaraCommandError


def _handle_runtime_error(console: Any, error: RuntimeError) -> None:
    if str(error) == "yara-python is not installed":
        display_missing_yara(console)
    else:
        console.print(f"[red]{escape(str(error))}[/red]")


def _handle_import_error(console: Any, error: ImportError) -> None:
    console.print(f"[red]Import error: {escape(str(error))}[/red]")
