"""Reporting helpers for fluent CLI demos."""

from __future__ import annotations

from pathlib import Path

import click

from yaraast.cli.utils import write_text


def write_output(output: str | Path | None, code: str, success_message: str) -> None:
    """Write generated code to output or stdout."""
    if output is not None:
        write_text(output, code)
        click.echo(success_message)
    else:
        click.echo(code)


def display_error(message: str) -> None:
    """Display an error message."""
    click.echo(message, err=True)
