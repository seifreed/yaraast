"""Check cache management commands."""

from __future__ import annotations

import json
from pathlib import Path

import click

from yaraast.check_cache import CheckCache


@click.group()
def cache() -> None:
    """Inspect or clear the local check cache."""


@cache.command()
@click.argument("path", type=click.Path(exists=True, file_okay=False, path_type=Path), default=".")
def info(path: Path) -> None:
    """Show cache metadata."""
    click.echo(json.dumps(CheckCache(path).info(), sort_keys=True))


@cache.command()
@click.argument("path", type=click.Path(exists=True, file_okay=False, path_type=Path), default=".")
def clear(path: Path) -> None:
    """Clear the local check cache."""
    CheckCache(path).clear()
    click.echo(f"Cache cleared: {path / '.yaraast' / 'check-cache.json'}")
