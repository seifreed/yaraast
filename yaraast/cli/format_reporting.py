"""Reporting helpers for formatting CLI output."""

from __future__ import annotations

from pathlib import Path

from rich.console import Console
from rich.panel import Panel


def display_format_success(console: Console, output_file: str) -> None:
    console.print(f"Formatted YARA file written to {output_file}")


def display_validation_success(console: Console, input_file: str, stats: dict[str, int]) -> None:
    console.print(
        Panel(
            f"[green]Valid YARA file[/green]\n\n"
            f"Statistics:\n"
            f"  - Rules: {stats['rules']}\n"
            f"  - Imports: {stats['imports']}",
            title=f"Validation Result: {Path(input_file).name}",
            border_style="green",
        ),
    )


def display_validation_error(console: Console, input_file: str, error: Exception) -> None:
    console.print(
        Panel(
            f"[red]Invalid YARA file[/red]\n\nError: {error}",
            title=f"Validation Result: {Path(input_file).name}",
            border_style="red",
        ),
    )
