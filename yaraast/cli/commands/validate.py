"""CLI command for cross-validation with libyara."""

import sys

import click

from yaraast.libyara import YARA_AVAILABLE
from yaraast.libyara.cross_validator import CrossValidator
from yaraast.libyara.equivalence import EquivalenceTester
from yaraast.parser import Parser


@click.group()
def validate():
    """Cross-validation commands."""


@validate.command()
@click.argument("rule_file", type=click.Path(exists=True))
@click.argument("test_file", type=click.Path(exists=True))
@click.option("-e", "--external", multiple=True, help="External variables (key=value)")
@click.option("-v", "--verbose", is_flag=True, help="Show detailed results")
def cross(rule_file: str, test_file: str, external: tuple, verbose: bool):
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
    externals = {}
    for ext in external:
        if "=" not in ext:
            click.echo(f"Invalid external format: {ext}", err=True)
            click.echo("Use format: key=value", err=True)
            sys.exit(1)
        key, value = ext.split("=", 1)
        externals[key] = value

    # Parse rules
    try:
        with open(rule_file) as f:
            rule_content = f.read()

        parser = Parser()
        ast = parser.parse(rule_content)
    except Exception as e:
        click.echo(f"Error parsing rules: {e}", err=True)
        sys.exit(1)

    # Read test data
    try:
        with open(test_file, "rb") as f:
            test_data = f.read()
    except Exception as e:
        click.echo(f"Error reading test file: {e}", err=True)
        sys.exit(1)

    # Validate
    validator = CrossValidator()
    result = validator.validate(ast, test_data, externals)

    # Display results
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

    sys.exit(0 if result.valid else 1)


@validate.command()
@click.argument("rule_file", type=click.Path(exists=True))
@click.option(
    "-d", "--test-data", type=click.Path(exists=True), help="Test data for scanning comparison"
)
@click.option("-v", "--verbose", is_flag=True, help="Show detailed results")
def roundtrip(rule_file: str, test_data: str | None, verbose: bool):
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
    data = None
    if test_data:
        try:
            with open(test_data, "rb") as f:
                data = f.read()
        except Exception as e:
            click.echo(f"Error reading test data: {e}", err=True)
            sys.exit(1)

    # Test round-trip
    tester = EquivalenceTester()
    result = tester.test_file_round_trip(rule_file, data)

    # Display results
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
    click.echo(f"{status(result.regenerated_compiles)} Regenerated compiles with libyara")

    if data:
        click.echo(f"{status(result.scan_equivalent)} Scan results match")
        click.echo(f"{status(result.eval_equivalent)} Evaluation results match")

    if verbose or not result.equivalent:
        if result.ast_differences:
            click.echo("\nAST differences:")
            for diff in result.ast_differences:
                click.echo(f"  - {diff}")

        if result.compilation_errors:
            click.echo("\nCompilation errors:")
            for error in result.compilation_errors:
                click.echo(f"  - {error}")

        if result.scan_differences:
            click.echo("\nScan differences:")
            for diff in result.scan_differences:
                click.echo(f"  - {diff}")

        if result.eval_differences:
            click.echo("\nEvaluation differences:")
            for diff in result.eval_differences:
                click.echo(f"  - {diff}")

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

    sys.exit(0 if result.equivalent else 1)
