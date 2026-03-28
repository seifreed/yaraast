"""CLI interface for YARA AST - Router and command delegation.

This module serves as the main CLI entry point, delegating to specific command modules.
The actual command implementations are in cli/commands/ subdirectory.
"""

import click

from yaraast.cli.command_registry import register_commands
from yaraast.version import YARAAST_VERSION

__all__ = ["cli"]


@click.group()
@click.version_option(version=YARAAST_VERSION, prog_name="yaraast")
def cli() -> None:
    """YARA AST - Parse and manipulate YARA rules."""


register_commands(cli)


if __name__ == "__main__":
    cli()
