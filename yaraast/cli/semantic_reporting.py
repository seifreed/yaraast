"""Reporting helpers for semantic CLI output."""

from __future__ import annotations

from pathlib import Path
from typing import Any

import click

from yaraast.cli.utils import format_json, write_text


def display_validation_start(file_path: Path, quiet: bool) -> None:
    if not quiet:
        click.echo(f"Validating {file_path}...")


def display_parse_failure(file_path: Path) -> None:
    click.echo(f"Error: Failed to parse {file_path}", err=True)


def display_processing_error(file_path: Path, error: Exception) -> None:
    click.echo(f"Error processing {file_path}: {error}", err=True)


def display_text_results(
    file_path: Path,
    result: Any,
    show_warnings: bool,
    show_suggestions: bool,
    quiet: bool,
) -> None:
    if result.errors:
        for error in result.errors:
            click.echo(click.style(str(error), fg="red"), err=True)
            if show_suggestions and error.suggestion:
                click.echo(click.style(f"  Suggestion: {error.suggestion}", fg="blue"))

    if show_warnings and result.warnings:
        for warning in result.warnings:
            click.echo(click.style(str(warning), fg="yellow"))
            if show_suggestions and warning.suggestion:
                click.echo(
                    click.style(f"  Suggestion: {warning.suggestion}", fg="blue"),
                )

    if not quiet:
        if result.is_valid and not result.warnings:
            click.echo(click.style(f"✓ {file_path}: All checks passed", fg="green"))
        elif result.is_valid:
            click.echo(
                click.style(
                    f"✓ {file_path}: Valid with {len(result.warnings)} warnings",
                    fg="yellow",
                ),
            )
        else:
            click.echo(
                click.style(f"✗ {file_path}: {len(result.errors)} errors", fg="red"),
            )


def display_summary(total_files: int, total_errors: int, total_warnings: int) -> None:
    click.echo()
    click.echo(f"Validated {total_files} file(s)")

    if total_errors > 0:
        click.echo(click.style(f"Found {total_errors} errors", fg="red"))

    if total_warnings > 0:
        click.echo(click.style(f"Found {total_warnings} warnings", fg="yellow"))

    if total_errors == 0 and total_warnings == 0:
        click.echo(click.style("All files passed validation", fg="green"))


def write_output_file(output_path: Path, results: list[dict], format: str) -> None:
    if format == "json":
        write_text(output_path, format_json(results))
        return

    lines: list[str] = []
    for result in results:
        lines.append(f"File: {result['file']}")
        lines.append(f"Valid: {result['is_valid']}")
        lines.append(f"Errors: {len(result['errors'])}")
        lines.append(f"Warnings: {len(result['warnings'])}")

        for error in result["errors"]:
            lines.append(f"ERROR: {error['message']}")
            if error.get("location"):
                loc = error["location"]
                lines.append(
                    "  Location: "
                    f"{loc.get('file', 'unknown')}:{loc.get('line', 0)}:{loc.get('column', 0)}",
                )
            if error.get("suggestion"):
                lines.append(f"  Suggestion: {error['suggestion']}")

        for warning in result["warnings"]:
            lines.append(f"WARNING: {warning['message']}")
            if warning.get("location"):
                loc = warning["location"]
                lines.append(
                    "  Location: "
                    f"{loc.get('file', 'unknown')}:{loc.get('line', 0)}:{loc.get('column', 0)}",
                )
            if warning.get("suggestion"):
                lines.append(f"  Suggestion: {warning['suggestion']}")

        lines.append("")

    write_text(output_path, "\n".join(lines))


def emit_json_results(results: list[dict[str, Any]]) -> None:
    click.echo(format_json(results))
