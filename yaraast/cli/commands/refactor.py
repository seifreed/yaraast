"""Lossless refactoring commands."""

from __future__ import annotations

from pathlib import Path

import click

from yaraast.cli.utils import read_text
from yaraast.refactor import RefactorResult, rename_rule, rename_string, write_refactor


@click.group()
def refactor() -> None:
    """Apply safe source refactors."""


@refactor.command("rename-rule")
@click.argument("input_file", type=click.Path(exists=True, dir_okay=False, path_type=Path))
@click.argument("old_name")
@click.argument("new_name")
@click.option("--check", "check_only", is_flag=True)
@click.option("--diff", "show_diff", is_flag=True)
@click.option("--write", "write_file", is_flag=True)
def rename_rule_command(
    input_file: Path,
    old_name: str,
    new_name: str,
    check_only: bool,
    show_diff: bool,
    write_file: bool,
) -> None:
    """Rename a rule identifier in one source file."""
    _run(input_file, rename_rule(read_text(input_file), old_name, new_name), check_only, show_diff, write_file)


@refactor.command("rename-string")
@click.argument("input_file", type=click.Path(exists=True, dir_okay=False, path_type=Path))
@click.argument("old_name")
@click.argument("new_name")
@click.option("--check", "check_only", is_flag=True)
@click.option("--diff", "show_diff", is_flag=True)
@click.option("--write", "write_file", is_flag=True)
def rename_string_command(
    input_file: Path,
    old_name: str,
    new_name: str,
    check_only: bool,
    show_diff: bool,
    write_file: bool,
) -> None:
    """Rename a string identifier and its references."""
    _run(input_file, rename_string(read_text(input_file), old_name, new_name), check_only, show_diff, write_file)


def _run(
    path: Path,
    result: RefactorResult,
    check_only: bool,
    show_diff: bool,
    write_file: bool,
) -> None:
    if show_diff:
        click.echo(result.diff(str(path)), nl=False)
    if write_file:
        write_refactor(path, result)
    if check_only and result.changed:
        raise click.exceptions.Exit(1)
