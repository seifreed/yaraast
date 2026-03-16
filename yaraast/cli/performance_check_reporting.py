"""Reporting helpers for performance-check CLI output."""

from __future__ import annotations

from typing import Any

from rich.console import Console
from rich.table import Table

from yaraast.performance.string_analyzer import StringPerformanceIssue


def display_parse_failure(console: Console) -> None:
    console.print("[red]❌ Failed to parse YARA file[/red]")


def display_no_issues(console: Console) -> None:
    console.print("[green]✅ No performance issues found![/green]")


def display_issues(console: Console, issues: list[StringPerformanceIssue]) -> None:
    """Display performance issues in a table."""
    table = Table(
        title="Performance Issues",
        show_header=True,
        header_style="bold cyan",
    )

    table.add_column("Rule", style="yellow", no_wrap=True)
    table.add_column("String", style="cyan")
    table.add_column("Issue", style="white")
    table.add_column("Severity", style="red")
    table.add_column("Description", style="white", max_width=50)

    for issue in issues:
        severity_style = "red bold" if issue.severity == "critical" else "yellow"
        table.add_row(
            issue.rule_name,
            issue.string_id,
            issue.issue_type,
            f"[{severity_style}]{issue.severity}[/{severity_style}]",
            issue.description,
        )

    console.print(table)

    console.print("\n[cyan]Suggestions:[/cyan]")
    unique_suggestions = {i.suggestion for i in issues if i.suggestion}
    for suggestion in unique_suggestions:
        console.print(f"  • {suggestion}")


def display_summary(
    console: Console,
    issue_types: dict[str, dict[str, Any]],
    total_rules: int,
    issues: list[StringPerformanceIssue],
) -> None:
    """Display summary statistics."""
    table = Table(
        title="Performance Issue Summary",
        show_header=True,
        header_style="bold cyan",
    )

    table.add_column("Issue Type", style="yellow")
    table.add_column("Count", justify="right")
    table.add_column("Critical", justify="right", style="red")
    table.add_column("Affected Rules", justify="right")

    for issue_type, stats in sorted(
        issue_types.items(),
        key=lambda x: x[1]["count"],
        reverse=True,
    ):
        table.add_row(
            issue_type.replace("_", " ").title(),
            str(stats["count"]),
            str(stats["critical"]) if stats["critical"] > 0 else "-",
            str(len(stats["rules"])),
        )

    console.print(table)

    affected_rules = len({i.rule_name for i in issues})
    console.print("\n[cyan]Overall Statistics:[/cyan]")
    console.print(f"  • Total rules analyzed: {total_rules}")
    console.print(
        f"  • Rules with issues: {affected_rules} ({affected_rules / total_rules * 100:.1f}%)",
    )
    console.print(f"  • Total issues found: {len(issues)}")
    console.print(
        f"  • Critical issues: {sum(1 for i in issues if i.severity == 'critical')}",
    )


def display_issue_totals(console: Console, issues: list[StringPerformanceIssue]) -> None:
    console.print(f"\n[yellow]Found {len(issues)} performance issues[/yellow]")
    critical_count = sum(1 for i in issues if i.severity == "critical")
    if critical_count > 0:
        console.print(
            f"[red]⚠️  {critical_count} critical issues that may severely impact scanning speed[/red]",
        )
