"""Reporting helpers for optimize CLI output."""

from __future__ import annotations

from rich.console import Console

from yaraast.cli.optimize_services import OptimizationAnalysis


def display_parse_failure(console: Console) -> None:
    console.print("[red]❌ Failed to parse YARA file[/red]")


def display_analysis(console: Console, title: str, analysis: OptimizationAnalysis) -> None:
    console.print(f"\n[yellow]{title}:[/yellow]")
    console.print(f"  • Total issues: {analysis.total_issues}")
    console.print(f"  • Critical issues: {analysis.critical_issues}")


def display_changes(console: Console, changes: list[str]) -> None:
    console.print(f"\n[yellow]Applied {len(changes)} optimizations:[/yellow]")
    for change in changes[:10]:
        console.print(f"  • {change}")
    if len(changes) > 10:
        console.print(f"  ... and {len(changes) - 10} more")


def display_no_changes(console: Console) -> None:
    console.print(
        "\n[green]✅ No optimizations needed - rules are already optimal![/green]",
    )


def display_improvement(console: Console, improvement: float) -> None:
    console.print(
        f"\n[green]✅ Performance improved by {improvement:.1f}%[/green]",
    )


def display_write_start(console: Console, output_file) -> None:
    console.print(f"\n[cyan]Writing optimized rules to {output_file}...[/cyan]")


def display_write_success(console: Console, output_file) -> None:
    console.print(
        f"[green]✅ Optimized YARA file written to {output_file}[/green]",
    )


def display_dry_run(console: Console) -> None:
    console.print("\n[yellow]Dry run - no files were written[/yellow]")
