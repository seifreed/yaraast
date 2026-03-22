"""Reporting helpers for AST diff CLI output."""

from __future__ import annotations

from pathlib import Path

from rich.console import Console

console = Console()


def display_no_changes(file1_path: Path, file2_path: Path) -> None:
    console.print(
        f"[green]No differences found between {file1_path.name} and {file2_path.name}[/green]",
    )


def display_diff_header(file1_path: Path, file2_path: Path) -> None:
    console.print(f"[blue]AST Diff: {file1_path.name} -> {file2_path.name}[/blue]")
    console.print("=" * 60)


def show_diff_summary(result) -> None:
    console.print("[yellow]Change Summary:[/yellow]")
    for change_type, count in result.change_summary.items():
        if count > 0:
            console.print(f"  - {change_type.replace('_', ' ').title()}: {count}")


def show_rule_changes(result) -> None:
    if result.added_rules:
        console.print(f"\n[green]+ Added Rules ({len(result.added_rules)}):[/green]")
        for rule in result.added_rules:
            console.print(f"  + {rule}")

    if result.removed_rules:
        console.print(f"\n[red]- Removed Rules ({len(result.removed_rules)}):[/red]")
        for rule in result.removed_rules:
            console.print(f"  - {rule}")

    if result.modified_rules:
        console.print(
            f"\n[yellow]Modified Rules ({len(result.modified_rules)}):[/yellow]",
        )
        for rule in result.modified_rules:
            console.print(f"  ~ {rule}")


def show_change_details(result, logical_only: bool, no_style: bool) -> None:
    if result.logical_changes:
        console.print(
            f"\n[red]Logical Changes ({len(result.logical_changes)}):[/red]",
        )
        for change in result.logical_changes:
            console.print(f"  - {change}")

    if result.structural_changes:
        console.print(
            f"\n[blue]Structural Changes ({len(result.structural_changes)}):[/blue]",
        )
        for change in result.structural_changes:
            console.print(f"  - {change}")

    if not logical_only and not no_style and result.style_only_changes:
        show_style_changes(result.style_only_changes)


def show_style_changes(style_changes: list) -> None:
    console.print(
        f"\n[dim]Style-Only Changes ({len(style_changes)}):[/dim]",
    )
    for change in style_changes[:10]:
        console.print(f"[dim]  - {change}[/dim]")
    if len(style_changes) > 10:
        console.print(
            f"[dim]  - ... and {len(style_changes) - 10} more style changes[/dim]",
        )


def show_change_significance(result) -> None:
    total_logical = len(result.added_rules) + len(result.removed_rules) + len(result.modified_rules)
    total_style = len(result.style_only_changes)

    if total_logical > 0:
        console.print(
            f"\n[yellow]This diff contains {total_logical} logical changes that affect rule behavior[/yellow]",
        )
    elif total_style > 0:
        console.print(
            f"\n[green]This diff contains only {total_style} style changes (no logic changes)[/green]",
        )
