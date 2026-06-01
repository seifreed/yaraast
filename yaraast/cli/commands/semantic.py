"""Semantic validation CLI command."""

from __future__ import annotations

from pathlib import Path
import sys

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
    _create_processing_error_result,
    _create_validation_context,
    _exit_with_appropriate_code,
    _process_file,
)
from yaraast.cli.utils import _require_file_path


@click.command()
@click.argument("files", nargs=-1, type=click.Path(exists=True, path_type=Path))
@click.option(
    "--output",
    "-o",
    type=click.Path(),
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
    output: str | None,
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

    output = _validate_output_path(output)
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
            all_results.append(_create_processing_error_result(file_path, e))
            total_errors += 1
            continue

    if not quiet and format == "text":
        display_summary(len(files), total_errors, total_warnings)

    if output:
        write_output_file(output, all_results, format)
    elif format == "json":
        emit_json_results(all_results)

    _exit_with_appropriate_code(total_errors, total_warnings, strict)


def _validate_output_path(output: str | None) -> str | None:
    if output is None:
        return None
    try:
        output_path = _require_file_path(output)
    except (TypeError, ValueError) as exc:
        raise click.BadParameter(str(exc), param_hint="--output") from exc
    if output_path.exists() and output_path.is_dir():
        raise click.BadParameter("output path must not be a directory", param_hint="--output")
    return output
