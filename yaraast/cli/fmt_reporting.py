"""Reporting helpers for AST-based formatting command."""

from __future__ import annotations

from difflib import unified_diff
from pathlib import Path


def display_format_check(console, input_path: Path, needs_format: bool, issues: list) -> None:
    """Display format check status and issues."""
    if needs_format:
        console.print(f"[yellow]{input_path.name} needs formatting[/yellow]")
        if issues:
            display_format_issues(console, issues)
        return
    console.print(f"[green]{input_path.name} is already formatted[/green]")


def display_format_issues(console, issues: list) -> None:
    """Display formatting issues."""
    for issue in issues[:5]:
        console.print(f"[dim]  - {issue}[/dim]")
    if len(issues) > 5:
        console.print(f"[dim]  - ... and {len(issues) - 5} more issues[/dim]")


def display_format_diff(
    console,
    input_path: Path,
    original: str,
    formatted: str,
) -> None:
    """Show formatting diff."""
    if original.strip() == formatted.strip():
        console.print("[green]No formatting changes needed[/green]")
        return

    console.print(f"[blue]Formatting changes for {input_path.name}:[/blue]")

    diff_lines = unified_diff(
        original.splitlines(keepends=True),
        formatted.splitlines(keepends=True),
        fromfile=f"{input_path.name} (original)",
        tofile=f"{input_path.name} (formatted)",
        lineterm="",
    )

    _print_diff_lines(console, diff_lines)


def display_format_result(
    console,
    input_path: Path,
    output_path: Path,
    style: str,
) -> None:
    """Display format success output."""
    if output_path == input_path:
        console.print(f"[green]Formatted {input_path.name} ({style} style)[/green]")
    else:
        console.print(f"[green]Formatted file written to {output_path}[/green]")


def display_format_error(console, message: str) -> None:
    """Display formatting failure."""
    console.print(f"[red]{message}[/red]")


def _print_diff_lines(console, diff_lines) -> None:
    """Print diff lines with colors."""
    for line in diff_lines:
        if line.startswith(("+++", "---")):
            console.print(f"[bold]{line.rstrip()}[/bold]")
        elif line.startswith("@@"):
            console.print(f"[cyan]{line.rstrip()}[/cyan]")
        elif line.startswith("+"):
            console.print(f"[green]{line.rstrip()}[/green]")
        elif line.startswith("-"):
            console.print(f"[red]{line.rstrip()}[/red]")
        else:
            console.print(f"[dim]{line.rstrip()}[/dim]")
