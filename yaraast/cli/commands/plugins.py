"""Plugin inspection commands."""

from __future__ import annotations

import click

from yaraast.plugins import discover_plugins, doctor_plugins, inspect_plugin


@click.group()
def plugins() -> None:
    """Inspect installed local plugins."""


@plugins.command("list")
def list_plugins() -> None:
    """List discovered plugin entry points."""
    for item in discover_plugins():
        click.echo(f"{item.name}\t{item.group}\t{item.value}")


@plugins.command("info")
@click.argument("name")
def info(name: str) -> None:
    """Show metadata and compatibility for one plugin."""
    item = inspect_plugin(name)
    click.echo(f"name: {item.name}")
    click.echo(f"group: {item.group}")
    click.echo(f"value: {item.value}")
    click.echo(f"api-version: {item.api_version or 'invalid'}")
    if item.error:
        click.echo(f"error: {item.error}")
        raise click.exceptions.Exit(1)


@plugins.command("doctor")
def doctor() -> None:
    """Validate every discovered plugin contract."""
    results = doctor_plugins()
    for item in results:
        status = "ok" if item.error is None else f"error: {item.error}"
        click.echo(f"{item.name}: {status}")
    if any(item.error for item in results):
        raise click.exceptions.Exit(1)
