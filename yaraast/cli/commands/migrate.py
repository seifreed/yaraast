"""YARA-family source migration command."""

from __future__ import annotations

from pathlib import Path

import click

from yaraast.cli.utils import read_text
from yaraast.refactor import migrate_source, write_refactor

_DIALECTS = {
    "yara-4.5.8": "yara",
    "yara-x-1.20.0": "yara-x",
    "yara": "yara",
    "yara-x": "yara-x",
}


@click.command()
@click.argument("input_file", type=click.Path(exists=True, dir_okay=False, path_type=Path))
@click.option("--from", "from_target", type=click.Choice(sorted(_DIALECTS)), required=True)
@click.option("--to", "to_target", type=click.Choice(sorted(_DIALECTS)), required=True)
@click.option("--check", "check_only", is_flag=True)
@click.option("--diff", "show_diff", is_flag=True)
@click.option("--write", "write_file", is_flag=True)
def migrate(
    input_file: Path,
    from_target: str,
    to_target: str,
    check_only: bool,
    show_diff: bool,
    write_file: bool,
) -> None:
    """Migrate one source file between YARA and YARA-X dialects."""
    result = migrate_source(read_text(input_file), _DIALECTS[from_target], _DIALECTS[to_target])
    if show_diff:
        click.echo(result.diff(str(input_file)), nl=False)
    if write_file:
        write_refactor(input_file, result)
    if check_only and result.changed:
        raise click.exceptions.Exit(1)
