"""Reporting helpers for LibYARA CLI output."""

from __future__ import annotations

from rich.syntax import Syntax


def display_missing_yara(console) -> None:
    """Display missing yara-python message."""
    console.print("[red]yara-python is not installed[/red]")
    console.print("Install with: pip install yara-python")


def display_compilation_errors(console, errors: list) -> None:
    """Display compilation errors."""
    console.print("[red]Compilation failed[/red]")
    for error in errors:
        console.print(f"[red]  - {error}[/red]")


def display_compilation_success(console) -> None:
    """Display compilation success message."""
    console.print("[green]Compilation successful[/green]")


def display_optimization_stats(console, result) -> None:
    """Print optimization statistics."""
    console.print("[blue]Optimizations applied:[/blue]")
    if result.optimization_stats:
        opt_stats = result.optimization_stats
        console.print(f"  - Rules optimized: {opt_stats.rules_optimized}")
        console.print(f"  - Strings optimized: {opt_stats.strings_optimized}")
        console.print(f"  - Conditions simplified: {opt_stats.conditions_simplified}")
        console.print(f"  - Constants folded: {opt_stats.constant_folded}")


def display_compilation_stats(console, result, compiler) -> None:
    """Print compilation statistics."""
    console.print("[blue]Compilation Stats:[/blue]")
    console.print(f"  - Compilation time: {result.compilation_time:.3f}s")
    console.print(f"  - AST nodes: {result.ast_node_count}")

    comp_stats = compiler.get_compilation_stats()
    console.print(f"  - Total compilations: {comp_stats['total_compilations']}")
    console.print(
        f"  - Success rate: {comp_stats['successful_compilations']}/{comp_stats['total_compilations']}",
    )


def display_compiled_rules_saved(console, output: str) -> None:
    """Display saved compiled rules message."""
    console.print(f"[green]Compiled rules saved to {output}[/green]")


def display_generated_source_preview(console, source: str) -> None:
    """Display generated source preview."""
    console.print("[dim]Generated source (first 200 chars):[/dim]")
    console.print(f"[dim]{source[:200]}...[/dim]")


def display_scan_failure(console, scan_result: dict) -> None:
    """Display scan failure details."""
    console.print(
        f"[red]Scan failed: {scan_result.get('error', 'Unknown error')}[/red]",
    )


def display_scan_summary(console, scan_result: dict, matches: list) -> None:
    """Display scan summary information."""
    console.print("[blue]Results:[/blue]")
    console.print(f"  - Matches found: {len(matches)}")
    console.print(f"  - Scan time: {scan_result['scan_time']:.3f}s")
    console.print(f"  - Data size: {scan_result['data_size']} bytes")

    if scan_result.get("ast_enhanced"):
        console.print("  - AST-enhanced: Yes")
        console.print(f"  - Rule count: {scan_result['rule_count']}")


def display_matches(console, matches: list) -> None:
    """Display individual match information."""
    if not matches:
        return

    console.print("\n[yellow]Matches:[/yellow]")
    for match in matches:
        _display_single_match(console, match)


def _display_single_match(console, match: dict) -> None:
    """Display a single match with its details."""
    console.print(f"  [bold]{match['rule']}[/bold]")

    if match.get("tags"):
        console.print(f"     Tags: {', '.join(match['tags'])}")

    if match.get("strings"):
        console.print(f"     Strings: {len(match['strings'])} found")

    if match.get("ast_context"):
        ctx = match["ast_context"]
        console.print(f"     Complexity: {ctx.get('condition_complexity', 'N/A')}")


def display_optimization_hints(console, scan_result: dict) -> None:
    """Display optimization hints if available."""
    hints = scan_result.get("optimization_hints")
    if not hints:
        return

    console.print("\n[dim]Optimization Hints:[/dim]")
    for hint in hints:
        console.print(f"[dim]  - {hint}[/dim]")


def display_scan_stats(console, matcher) -> None:
    """Display scan statistics."""
    if not matcher:
        return

    matcher_stats = matcher.get_scan_stats()
    console.print("\n[blue]Scan Statistics:[/blue]")
    console.print(f"  - Total scans: {matcher_stats['total_scans']}")
    console.print(f"  - Success rate: {matcher_stats['success_rate']:.1%}")
    console.print(f"  - Average scan time: {matcher_stats['average_scan_time']:.3f}s")


def display_optimize_results(
    console, optimizer, show_optimizations: bool, optimized_code: str
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
            console.print(f"  - {opt}")

    console.print("\n[dim]Optimized YARA code:[/dim]")
    syntax = Syntax(optimized_code, "yara", theme="monokai", line_numbers=True)
    console.print(syntax)


class LibYaraCommandError(Exception):
    """Internal error wrapper to trigger CLI abort."""


def handle_libyara_error(console, error: Exception) -> None:
    """Handle libyara command errors uniformly."""
    from rich.markup import escape

    handlers = {
        RuntimeError: _handle_runtime_error,
        ImportError: _handle_import_error,
    }

    for exc_type, handler in handlers.items():
        if isinstance(error, exc_type):
            handler(console, error)
            raise LibYaraCommandError

    console.print(f"[red]Error: {escape(str(error))}[/red]")
    raise LibYaraCommandError


def _handle_runtime_error(console, error: RuntimeError) -> None:
    if str(error) == "yara-python is not installed":
        display_missing_yara(console)
    else:
        console.print(f"[red]{error}[/red]")


def _handle_import_error(console, error: ImportError) -> None:
    console.print(f"[red]Import error: {error}[/red]")
