"""Lossless refactoring commands."""

from __future__ import annotations

from pathlib import Path

import click

from yaraast.cli.utils import read_text
from yaraast.refactor import (
    RefactorResult,
    normalize_metadata,
    remove_unused_strings,
    rename_rule,
    rename_string,
    sort_imports,
    write_refactor,
)


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
    _run(
        input_file,
        rename_rule(read_text(input_file), old_name, new_name),
        check_only,
        show_diff,
        write_file,
    )


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
    _run(
        input_file,
        rename_string(read_text(input_file), old_name, new_name),
        check_only,
        show_diff,
        write_file,
    )


@refactor.command("remove-unused")
@click.argument("input_file", type=click.Path(exists=True, dir_okay=False, path_type=Path))
@click.option("--check", "check_only", is_flag=True)
@click.option("--diff", "show_diff", is_flag=True)
@click.option("--write", "write_file", is_flag=True)
def remove_unused_command(
    input_file: Path, check_only: bool, show_diff: bool, write_file: bool
) -> None:
    """Remove unused string definitions from one source file."""
    _run(
        input_file, remove_unused_strings(read_text(input_file)), check_only, show_diff, write_file
    )


@refactor.command("normalize-metadata")
@click.argument("input_file", type=click.Path(exists=True, dir_okay=False, path_type=Path))
@click.option("--check", "check_only", is_flag=True)
@click.option("--diff", "show_diff", is_flag=True)
@click.option("--write", "write_file", is_flag=True)
def normalize_metadata_command(
    input_file: Path, check_only: bool, show_diff: bool, write_file: bool
) -> None:
    """Sort simple metadata entries within each rule."""
    _run(input_file, normalize_metadata(read_text(input_file)), check_only, show_diff, write_file)


@refactor.command("sort-imports")
@click.argument("input_file", type=click.Path(exists=True, dir_okay=False, path_type=Path))
@click.option("--check", "check_only", is_flag=True)
@click.option("--diff", "show_diff", is_flag=True)
@click.option("--write", "write_file", is_flag=True)
def sort_imports_command(
    input_file: Path, check_only: bool, show_diff: bool, write_file: bool
) -> None:
    """Sort contiguous import statements."""
    _run(input_file, sort_imports(read_text(input_file)), check_only, show_diff, write_file)


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
