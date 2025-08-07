"""Semantic validation CLI command."""

import json
import sys
from pathlib import Path

import click

try:
    from yaraast.parser import Parser
    from yaraast.types.semantic_validator import SemanticValidator, ValidationResult
except ImportError:
    # Fallback for running within the package
    from yaraast.types.semantic_validator import SemanticValidator, ValidationResult


def _process_file(file_path: Path, parser, validator, quiet: bool):
    """Process a single file and return results."""
    if not quiet:
        click.echo(f"Validating {file_path}...")

    # Parse the file
    with Path(file_path).open(encoding="utf-8") as f:
        content = f.read()

    ast = parser.parse(content)
    if not ast:
        click.echo(f"Error: Failed to parse {file_path}", err=True)
        return None

    # Set file location for better error reporting
    if hasattr(ast, "location") and ast.location:
        ast.location.file = str(file_path)

    # Validate semantics
    result = validator.validate(ast)

    # Add file path to all errors and warnings
    _add_file_to_issues(result.errors, file_path)
    _add_file_to_issues(result.warnings, file_path)

    return result


def _add_file_to_issues(issues, file_path: Path) -> None:
    """Add file path to all issues."""
    from yaraast.ast.base import Location

    for issue in issues:
        if issue.location:
            issue.location.file = str(file_path)
        else:
            issue.location = Location(line=1, column=1, file=str(file_path))


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
    """Perform semantic validation on YARA files.

    This command validates:
    - String identifier uniqueness per rule
    - Function existence in imported modules
    - Function arity and parameter types
    - Type compatibility and other semantic rules

    Examples:
        # Validate single file
        yaraast semantic rule.yar

        # Validate multiple files with JSON output
        yaraast semantic *.yar --format json --output results.json

        # Strict mode - treat warnings as errors
        yaraast semantic rule.yar --strict

        # Quiet mode - only show issues
        yaraast semantic rule.yar --quiet

    """
    if not files:
        click.echo("Error: No files provided", err=True)
        sys.exit(1)

    validation_context = _create_validation_context()
    all_results, total_errors, total_warnings = _process_all_files(
        files, validation_context, format, warnings, suggestions, quiet
    )

    _handle_output(all_results, total_errors, total_warnings, output, format, quiet, len(files))
    _exit_with_appropriate_code(total_errors, total_warnings, strict)


def _create_validation_context():
    """Create validation context with parser and validator."""
    return {"parser": Parser(), "validator": SemanticValidator()}


def _process_all_files(files, context, format, warnings, suggestions, quiet):
    """Process all files and collect results."""
    all_results = []
    total_errors = 0
    total_warnings = 0

    for file_path in files:
        try:
            result = _process_file(file_path, context["parser"], context["validator"], quiet)
            if result:
                file_result = _create_file_result(file_path, result)
                all_results.append(file_result)

                total_errors += len(result.errors)
                total_warnings += len(result.warnings)

                if format == "text":
                    _display_text_results(file_path, result, warnings, suggestions, quiet)
        except Exception as e:
            click.echo(f"Error processing {file_path}: {e}", err=True)
            continue

    return all_results, total_errors, total_warnings


def _create_file_result(file_path, result):
    """Create result dictionary for a file."""
    return {
        "file": str(file_path),
        "is_valid": result.is_valid,
        "errors": [error.to_dict() for error in result.errors],
        "warnings": [warning.to_dict() for warning in result.warnings],
        "total_issues": result.total_issues,
    }


def _handle_output(all_results, total_errors, total_warnings, output, format, quiet, file_count):
    """Handle various output options."""
    if not quiet and format == "text":
        _display_summary(file_count, total_errors, total_warnings)

    if output:
        _write_output_file(output, all_results, format)
    elif format == "json":
        click.echo(json.dumps(all_results, indent=2))


def _exit_with_appropriate_code(total_errors, total_warnings, strict):
    """Exit with appropriate code based on results."""
    exit_code = 0
    if total_errors > 0 or (strict and total_warnings > 0):
        exit_code = 1
    sys.exit(exit_code)


def _display_text_results(
    file_path: Path,
    result: ValidationResult,
    show_warnings: bool,
    show_suggestions: bool,
    quiet: bool,
) -> None:
    """Display validation results in text format."""
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


def _display_summary(total_files: int, total_errors: int, total_warnings: int) -> None:
    """Display validation summary."""
    click.echo()
    click.echo(f"Validated {total_files} file(s)")

    if total_errors > 0:
        click.echo(click.style(f"Found {total_errors} errors", fg="red"))

    if total_warnings > 0:
        click.echo(click.style(f"Found {total_warnings} warnings", fg="yellow"))

    if total_errors == 0 and total_warnings == 0:
        click.echo(click.style("All files passed validation", fg="green"))


def _write_output_file(output_path: Path, results: list[dict], format: str) -> None:
    """Write validation results to output file."""
    with Path(output_path).open("w", encoding="utf-8") as f:
        if format == "json":
            json.dump(results, f, indent=2)
        else:
            # Text format
            for result in results:
                f.write(f"File: {result['file']}\n")
                f.write(f"Valid: {result['is_valid']}\n")
                f.write(f"Errors: {len(result['errors'])}\n")
                f.write(f"Warnings: {len(result['warnings'])}\n")

                for error in result["errors"]:
                    f.write(f"ERROR: {error['message']}\n")
                    if error.get("location"):
                        loc = error["location"]
                        f.write(
                            f"  Location: {loc.get('file', 'unknown')}:{loc.get('line', 0)}:{loc.get('column', 0)}\n",
                        )
                    if error.get("suggestion"):
                        f.write(f"  Suggestion: {error['suggestion']}\n")

                for warning in result["warnings"]:
                    f.write(f"WARNING: {warning['message']}\n")
                    if warning.get("location"):
                        loc = warning["location"]
                        f.write(
                            f"  Location: {loc.get('file', 'unknown')}:{loc.get('line', 0)}:{loc.get('column', 0)}\n",
                        )
                    if warning.get("suggestion"):
                        f.write(f"  Suggestion: {warning['suggestion']}\n")

                f.write("\n")


if __name__ == "__main__":
    semantic()
