"""CLI command for cross-validation with libyara."""

import sys
from pathlib import Path

import click

from yaraast.libyara import YARA_AVAILABLE
from yaraast.libyara.cross_validator import CrossValidator
from yaraast.libyara.equivalence import EquivalenceTester
from yaraast.parser import Parser


@click.group()
def validate() -> None:
    """Cross-validation commands."""


def _parse_externals(external: tuple) -> dict:
    """Parse external variables from command line."""
    externals = {}
    for ext in external:
        if "=" not in ext:
            click.echo(f"Invalid external format: {ext}", err=True)
            click.echo("Use format: key=value", err=True)
            sys.exit(1)
        key, value = ext.split("=", 1)
        externals[key] = value
    return externals


def _display_cross_results(result, verbose: bool) -> None:
    """Display cross-validation results."""
    if result.valid:
        click.echo(click.style("✓ Validation PASSED", fg="green", bold=True))
    else:
        click.echo(click.style("✗ Validation FAILED", fg="red", bold=True))

    click.echo(f"\nRules tested: {result.rules_tested}")
    click.echo(f"Rules matched: {result.rules_matched} ({result.match_rate:.1f}%)")

    if verbose or not result.valid:
        if result.rules_differ:
            click.echo("\nDifferences found:")
            for diff in result.rules_differ:
                click.echo(f"  - {diff}")

        if result.errors:
            click.echo("\nErrors:")
            for error in result.errors:
                click.echo(f"  - {error}")

        click.echo("\nPerformance:")
        click.echo(f"  YaraAST evaluation: {result.yaraast_time:.3f}s")
        click.echo(f"  LibYARA compilation: {result.libyara_compile_time:.3f}s")
        click.echo(f"  LibYARA scanning: {result.libyara_scan_time:.3f}s")
        click.echo(f"  Total time: {result.total_time:.3f}s")


@validate.command()
@click.argument("rule_file", type=click.Path(exists=True))
@click.argument("test_file", type=click.Path(exists=True))
@click.option("-e", "--external", multiple=True, help="External variables (key=value)")
@click.option("-v", "--verbose", is_flag=True, help="Show detailed results")
def cross(rule_file: str, test_file: str, external: tuple, verbose: bool) -> None:
    """Cross-validate YARA rules between yaraast and libyara.

    Example:
        yaraast validate cross rules.yar malware.bin
        yaraast validate cross rules.yar sample.exe -e filename=sample.exe

    """
    if not YARA_AVAILABLE:
        click.echo("Error: yara-python is not installed.", err=True)
        click.echo("Install it with: pip install yara-python", err=True)
        sys.exit(1)

    # Parse externals
    externals = _parse_externals(external)

    # Parse rules
    try:
        with Path(rule_file).open() as f:
            rule_content = f.read()

        parser = Parser()
        ast = parser.parse(rule_content)
    except Exception as e:
        click.echo(f"Error parsing rules: {e}", err=True)
        sys.exit(1)

    # Read test data
    try:
        with Path(test_file).open("rb") as f:
            test_data = f.read()
    except Exception as e:
        click.echo(f"Error reading test file: {e}", err=True)
        sys.exit(1)

    # Validate
    validator = CrossValidator()
    result = validator.validate(ast, test_data, externals)

    # Display results
    _display_cross_results(result, verbose)

    sys.exit(0 if result.valid else 1)


def _read_test_data(test_data_path: str | None) -> bytes | None:
    """Read test data if provided."""
    if not test_data_path:
        return None

    try:
        with Path(test_data_path).open("rb") as f:
            return f.read()
    except Exception as e:
        click.echo(f"Error reading test data: {e}", err=True)
        sys.exit(1)


def _display_roundtrip_summary(result):
    """Display round-trip test summary."""
    if result.equivalent:
        click.echo(click.style("✓ Round-trip PASSED", fg="green", bold=True))
    else:
        click.echo(click.style("✗ Round-trip FAILED", fg="red", bold=True))

    # Show details
    def status(x):
        return click.style("✓", fg="green") if x else click.style("✗", fg="red")

    click.echo(f"\n{status(result.ast_equivalent)} AST equivalence")
    click.echo(f"{status(result.code_equivalent)} Code generation equivalence")
    click.echo(f"{status(result.original_compiles)} Original compiles with libyara")
    click.echo(
        f"{status(result.regenerated_compiles)} Regenerated compiles with libyara",
    )

    return status


def _display_differences(title: str, differences: list) -> None:
    """Display a list of differences."""
    if differences:
        click.echo(f"\n{title}:")
        for diff in differences:
            click.echo(f"  - {diff}")


def _display_code_comparison(result, verbose: bool) -> None:
    """Display original and regenerated code comparison."""
    if verbose and result.original_code:
        click.echo("\nOriginal code:")
        click.echo("-" * 40)
        click.echo(result.original_code)
        click.echo("-" * 40)

        if result.regenerated_code:
            click.echo("\nRegenerated code:")
            click.echo("-" * 40)
            click.echo(result.regenerated_code)
            click.echo("-" * 40)


def _display_roundtrip_details(result, status_fn, data, verbose: bool) -> None:
    """Display detailed round-trip results."""
    if data:
        click.echo(f"{status_fn(result.scan_equivalent)} Scan results match")
        click.echo(f"{status_fn(result.eval_equivalent)} Evaluation results match")

    if verbose or not result.equivalent:
        _display_differences("AST differences", result.ast_differences)
        _display_differences("Compilation errors", result.compilation_errors)
        _display_differences("Scan differences", result.scan_differences)
        _display_differences("Evaluation differences", result.eval_differences)
        _display_code_comparison(result, verbose)


@validate.command()
@click.argument("rule_file", type=click.Path(exists=True))
@click.option(
    "-d",
    "--test-data",
    type=click.Path(exists=True),
    help="Test data for scanning comparison",
)
@click.option("-v", "--verbose", is_flag=True, help="Show detailed results")
def roundtrip(rule_file: str, test_data: str | None, verbose: bool) -> None:
    """Test AST round-trip equivalence.

    Tests: AST → code → libyara → re-parse

    Example:
        yaraast validate roundtrip rules.yar
        yaraast validate roundtrip rules.yar -d malware.bin

    """
    if not YARA_AVAILABLE:
        click.echo("Error: yara-python is not installed.", err=True)
        click.echo("Install it with: pip install yara-python", err=True)
        sys.exit(1)

    # Read test data if provided
    data = _read_test_data(test_data)

    # Test round-trip
    tester = EquivalenceTester()
    result = tester.test_file_round_trip(rule_file, data)

    # Display results
    status_fn = _display_roundtrip_summary(result)
    _display_roundtrip_details(result, status_fn, data, verbose)

    sys.exit(0 if result.equivalent else 1)
