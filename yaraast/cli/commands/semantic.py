"""Semantic validation CLI command."""

from __future__ import annotations

import sys
from pathlib import Path

import click

from yaraast.cli.semantic_reporting import (
    display_processing_error,
    display_summary,
    display_text_results,
    display_validation_start,
    emit_json_results,
    write_output_file,
)
from yaraast.cli.semantic_services import (
    _create_file_result,
    _create_validation_context,
    _exit_with_appropriate_code,
    _process_file,
)


@click.command()
@click.argument("files", nargs=-1, type=click.Path(exists=True, path_type=Path))
@click.option(
    "--output",
    "-o",
    type=click.Path(path_type=Path),
    help="Output file for validation results (JSON format)",
)
@click.option(
    "--format",
    "-f",
    type=click.Choice(["text", "json"]),
    default="text",
    help="Output format",
)
@click.option(
    "--warnings/--no-warnings",
    default=True,
    help="Include warnings in output",
)
@click.option(
    "--suggestions/--no-suggestions",
    default=True,
    help="Include suggestions in output",
)
@click.option(
    "--strict",
    is_flag=True,
    help="Treat warnings as errors (exit with non-zero code)",
)
@click.option(
    "--quiet",
    "-q",
    is_flag=True,
    help="Only show errors and warnings, not success messages",
)
def semantic(
    files: tuple[Path, ...],
    output: Path | None,
    format: str,
    warnings: bool,
    suggestions: bool,
    strict: bool,
    quiet: bool,
) -> None:
    """Perform semantic validation on YARA files."""
    if not files:
        click.echo("Error: No files provided", err=True)
        sys.exit(1)

    validation_context = _create_validation_context()
    all_results = []
    total_errors = 0
    total_warnings = 0

    for file_path in files:
        try:
            display_validation_start(file_path, quiet)
            result = _process_file(
                file_path, validation_context["parser"], validation_context["validator"]
            )

            file_result = _create_file_result(file_path, result)
            all_results.append(file_result)

            total_errors += len(result.errors)
            total_warnings += len(result.warnings)

            if format == "text":
                display_text_results(file_path, result, warnings, suggestions, quiet)
        except Exception as e:
            display_processing_error(file_path, e)
            continue

    if not quiet and format == "text":
        display_summary(len(files), total_errors, total_warnings)

    if output:
        write_output_file(output, all_results, format)
    elif format == "json":
        emit_json_results(all_results)

    _exit_with_appropriate_code(total_errors, total_warnings, strict)
