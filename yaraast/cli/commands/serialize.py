"""CLI commands for AST serialization."""

from __future__ import annotations

import click
from rich.console import Console

from yaraast.cli.serialize_command_services import (
    build_ast_info_payload,
    build_diff_output_path,
    diff_serialized,
    export_serialized,
    import_serialized,
    validate_serialized_error,
    validate_serialized_input,
)
from yaraast.cli.serialize_reporting import (
    display_diff_no_changes,
    display_diff_saved,
    display_export_result,
    display_import_result,
    display_info,
    display_validation_result,
    write_diff_output,
)

console = Console()


@click.group()
def serialize() -> None:
    """AST serialization commands for export/import and versioning."""


@serialize.command()
@click.argument("input_file", type=click.Path(exists=True))
@click.option("-o", "--output", type=click.Path(), help="Output file path")
@click.option(
    "-f",
    "--format",
    type=click.Choice(["json", "yaml", "protobuf"]),
    default="json",
    help="Serialization format",
)
@click.option("--minimal", is_flag=True, help="Minimal output (no metadata)")
@click.option("--pretty", is_flag=True, help="Pretty print output to console")
def export(input_file: str, output: str | None, format: str, minimal: bool, pretty: bool) -> None:
    """Export YARA AST to various serialization formats.

    Supports JSON, YAML, and Protobuf formats for AST persistence
    and interchange in CI/CD pipelines.

    Examples:
        yaraast serialize export rules.yar -f yaml -o rules.yaml
        yaraast serialize export rules.yar -f protobuf -o rules.pb
        yaraast serialize export rules.yar --pretty

    """
    try:
        with console.status(f"[bold green]Parsing {input_file}..."):
            result, stats = export_serialized(input_file, format, output, minimal)
        display_export_result(console, result, format, output, pretty, stats)

    except Exception as e:  # CLI error boundary
        console.print(f"[red]❌ Error: {e}[/red]")
        raise click.Abort from e


@serialize.command()
@click.argument("input_file", type=click.Path(exists=True))
@click.option(
    "-f",
    "--format",
    type=click.Choice(["json", "yaml", "protobuf"]),
    default="json",
    help="Input serialization format",
)
@click.option("-o", "--output", type=click.Path(), help="Output YARA file")
def import_ast(input_file: str, format: str, output: str | None) -> None:
    """Import AST from serialized format back to YARA code.

    Note: Full round-trip import is not yet implemented.
    This command validates the serialized format.

    Examples:
        yaraast serialize import rules.json -f json
        yaraast serialize import rules.yaml -f yaml

    """
    try:
        ast = import_serialized(input_file, format)

        display_import_result(console, input_file, format, ast, output)

    except Exception as e:  # CLI error boundary
        console.print(f"[red]❌ Error: {e}[/red]")
        raise click.Abort from e


@serialize.command()
@click.argument("old_file", type=click.Path(exists=True))
@click.argument("new_file", type=click.Path(exists=True))
@click.option("-o", "--output", type=click.Path(), help="Output diff file")
@click.option(
    "-f",
    "--format",
    type=click.Choice(["json", "yaml"]),
    default="json",
    help="Diff output format",
)
@click.option("--patch", is_flag=True, help="Create patch file")
@click.option("--stats", is_flag=True, help="Show detailed statistics")
def diff(
    old_file: str,
    new_file: str,
    output: str | None,
    format: str,
    patch: bool,
    stats: bool,
) -> None:
    """Compare two YARA files and show AST differences.

    Provides incremental versioning by analyzing structural changes
    between AST versions. Useful for CI/CD pipelines and change tracking.

    Examples:
        yaraast serialize diff old.yar new.yar
        yaraast serialize diff v1.yar v2.yar -o changes.json --patch
        yaraast serialize diff old.yar new.yar --stats

    """
    try:
        with console.status("[bold green]Parsing files..."):
            differ, diff_result, _ = diff_serialized(old_file, new_file, stats)

        if not diff_result.has_changes:
            display_diff_no_changes(console)
            return

        if output or patch:
            output_path = build_diff_output_path(old_file, new_file, output, format)

            if patch:
                differ.create_patch(diff_result, output_path)
                display_diff_saved(console, output_path, patch=True)
            else:
                diff_data = diff_result.to_dict()
                write_diff_output(output_path, format, diff_data)
                display_diff_saved(console, output_path, patch=False)

    except Exception as e:  # CLI error boundary
        console.print(f"[red]❌ Error: {e}[/red]")
        raise click.Abort from e


@serialize.command()
@click.argument("input_file", type=click.Path(exists=True))
@click.option(
    "-f",
    "--format",
    type=click.Choice(["json", "yaml", "protobuf"]),
    default="json",
    help="Serialization format to validate",
)
def validate(input_file: str, format: str) -> None:
    """Validate serialized AST format.

    Checks if the serialized file can be properly loaded and
    contains valid AST structure.

    Examples:
        yaraast serialize validate rules.json
        yaraast serialize validate rules.yaml -f yaml

    """
    try:
        ast, panel = validate_serialized_input(input_file, format)
        display_validation_result(
            console,
            panel,
        )
    except Exception as e:  # CLI error boundary
        display_validation_result(
            console,
            validate_serialized_error(input_file, format, e),
        )
        raise click.Abort from e


@serialize.command()
@click.argument("input_file", type=click.Path(exists=True))
def info(input_file: str) -> None:
    """Show information about a YARA file's AST structure.

    Provides detailed analysis of the AST without full serialization.
    Useful for understanding rule complexity and structure.

    Example:
        yaraast serialize info rules.yar
    """
    try:
        info_data = build_ast_info_payload(input_file)

        display_info(console, input_file, info_data)

    except Exception as e:  # CLI error boundary
        console.print(f"[red]❌ Error: {e}[/red]")
        raise click.Abort from e


if __name__ == "__main__":
    serialize()
