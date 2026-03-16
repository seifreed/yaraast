"""Reporting helpers for fluent CLI demos."""

from __future__ import annotations

from pathlib import Path

import click


def write_output(output: Path | None, code: str, success_message: str) -> None:
    """Write generated code to output or stdout."""
    if output:
        Path(output).write_text(code, encoding="utf-8")
        click.echo(success_message)
    else:
        click.echo(code)


def display_error(message: str) -> None:
    """Display an error message."""
    click.echo(message, err=True)
