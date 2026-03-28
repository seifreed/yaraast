"""Reporting helpers for analyze CLI output."""

from __future__ import annotations

import sys
from typing import Any

from rich.console import Console
from rich.panel import Panel
from rich.table import Table

from yaraast.analysis.best_practices import AnalysisReport
from yaraast.analysis.optimization import OptimizationReport, OptimizationSuggestion
from yaraast.cli.analyze_services import _filter_suggestions, _get_level_style, _get_severity_counts

console = Console()


def display_best_practices_report(
    rule_file: str,
    report: AnalysisReport,
    verbose: bool,
    category: str,
) -> None:
    console.print(f"\n[bold]Best Practices Analysis:[/bold] {rule_file}\n")
    errors, warnings, info = _get_severity_counts(report)
    display_summary(errors, warnings, info)
    suggestions = _filter_suggestions(report.suggestions, category)
    display_issues(suggestions)
    if verbose:
        display_verbose_info(suggestions, report)
    handle_exit_code(errors, warnings, info, verbose)


def display_summary(errors: list[Any], warnings: list[Any], info: list[Any]) -> None:
    summary = Table(show_header=False, box=None)
    summary.add_row("✗ Errors:", f"[red]{len(errors)}[/red]")
    summary.add_row("⚠ Warnings:", f"[yellow]{len(warnings)}[/yellow]")
    summary.add_row("i Info:", f"[blue]{len(info)}[/blue]")
    console.print(Panel(summary, title="Summary", width=30))


def display_issues(suggestions: list[Any]) -> None:
    important = [s for s in suggestions if s.severity in ("error", "warning")]
    if important:
        console.print("\n[bold red]Issues:[/bold red]")
        for suggestion in important:
            console.print(f"  {suggestion.format()}")


def display_verbose_info(suggestions: list[Any], report: AnalysisReport) -> None:
    info_items = [s for s in suggestions if s.severity == "info"]
    if info_items:
        console.print("\n[bold blue]Suggestions:[/bold blue]")
        for suggestion in info_items:
            console.print(f"  {suggestion.format()}")
    if report.statistics:
        console.print("\n[dim]Statistics:[/dim]")
        for key, value in report.statistics.items():
            console.print(f"  {key}: {value}")


def handle_exit_code(
    errors: list[Any], warnings: list[Any], info: list[Any], verbose: bool
) -> None:
    if errors:
        sys.exit(2)
    if warnings and not verbose:
        console.print(f"\n[dim]Use -v to see {len(info)} additional suggestions[/dim]")
        sys.exit(1)
    console.print("\n[green]✓ No major issues found[/green]")
    sys.exit(0)


def display_optimization_report(rule_file: str, report: OptimizationReport, verbose: bool) -> None:
    console.print(f"\n[bold]Optimization Analysis:[/bold] {rule_file}\n")
    optimize_display_impact_summary(report)
    optimize_display_suggestions(report.suggestions, verbose)


def optimize_display_impact_summary(report: OptimizationReport) -> None:
    table = Table(title="Optimization Opportunities")
    table.add_column("Impact", style="cyan")
    table.add_column("Count", justify="right")
    if not report.statistics:
        report.statistics = {}
    if "by_impact" not in report.statistics:
        report.statistics["by_impact"] = {
            "high": sum(1 for s in report.suggestions if s.impact == "high"),
            "medium": sum(1 for s in report.suggestions if s.impact == "medium"),
            "low": sum(1 for s in report.suggestions if s.impact == "low"),
        }
    for level in ["high", "medium", "low"]:
        count = report.statistics["by_impact"].get(level, 0)
        style = {"high": "red", "medium": "yellow", "low": "green"}.get(level, "white")
        table.add_row(f"[{style}]{level.capitalize()}[/{style}]", str(count))
    console.print(table)


def optimize_display_suggestions(suggestions: list[Any], verbose: bool) -> None:
    for level in ["high", "medium", "low"]:
        level_suggestions = [s for s in suggestions if s.impact == level]
        if level_suggestions:
            display_suggestions_by_level(level_suggestions, level, verbose)


def display_suggestions_by_level(level_suggestions: list[Any], level: str, verbose: bool) -> None:
    style = _get_level_style(level)
    console.print(f"\n[bold {style}]{level.capitalize()} Impact:[/bold {style}]")
    for suggestion in level_suggestions:
        console.print(f"  {suggestion.format()}")
        if verbose:
            display_code_examples(suggestion)


def display_code_examples(suggestion: OptimizationSuggestion) -> None:
    if suggestion.code_before:
        console.print(f"    Before: [dim]{suggestion.code_before}[/dim]")
    if suggestion.code_after:
        console.print(f"    After:  [green]{suggestion.code_after}[/green]")
