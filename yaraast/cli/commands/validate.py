"""CLI command for cross-validation with libyara."""

from __future__ import annotations

import sys
from pathlib import Path

import click

from yaraast.cli.utils import parse_yara_file
from yaraast.cli.validate_reporting import (
    display_cross_results,
    display_external_parse_error,
    display_roundtrip_details,
    display_roundtrip_summary,
    display_rule_file_invalid,
    display_rule_file_valid,
)
from yaraast.cli.validate_services import (
    cross_validate_rules,
    parse_externals,
    read_test_data,
    roundtrip_test,
    validate_rule_file,
)
from yaraast.errors import ValidationError
from yaraast.libyara import YARA_AVAILABLE


class ValidateGroup(click.Group):
    """Group that falls back to file validation when no subcommand matches."""

    def resolve_command(self, ctx: click.Context, args: list[str]):
        if args:
            cmd_name = args[0]
            cmd = self.get_command(ctx, cmd_name)
            if cmd is not None:
                return cmd_name, cmd, args[1:]
            default_cmd = self.get_command(ctx, "_file")
            return "_file", default_cmd, args
        return super().resolve_command(ctx, args)


@click.group(cls=ValidateGroup)
def validate() -> None:
    """Cross-validation commands."""


def _validate_rule_file(rule_file: str) -> int:
    """Basic validation for backward-compatible `validate <file>` usage."""
    try:
        ast, rules_count, imports_count, string_count = validate_rule_file(rule_file)
    except Exception as exc:
        display_rule_file_invalid(exc)
        return 1

    display_rule_file_valid(rules_count, imports_count, string_count)
    return 0


@validate.command(name="_file", hidden=True)
@click.argument("rule_file", type=click.Path(exists=True))
def _validate_file(rule_file: str) -> None:
    """Validate a YARA file."""
    code = _validate_rule_file(rule_file)
    if code != 0:
        raise SystemExit(code)


def _parse_externals(external: tuple[str, ...]) -> dict[str, str]:
    """Parse external variables from command line."""
    try:
        return parse_externals(external)
    except (ValueError, ValidationError) as exc:
        display_external_parse_error(exc)
        sys.exit(1)


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
    # Parse externals
    externals = _parse_externals(external)

    if not YARA_AVAILABLE:
        click.echo("Error: yara-python is not installed.", err=True)
        click.echo("Install it with: pip install yara-python", err=True)
        sys.exit(1)

    # Parse rules
    try:
        parse_yara_file(rule_file)
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
    result = cross_validate_rules(rule_file, test_data, externals)

    # Display results
    display_cross_results(result, verbose)

    sys.exit(0 if result.valid else 1)


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
    try:
        data = read_test_data(test_data)
    except (ValueError, ValidationError) as exc:
        click.echo(str(exc), err=True)
        sys.exit(1)

    # Test round-trip
    result = roundtrip_test(rule_file, data)

    # Display results
    status_fn = display_roundtrip_summary(result)
    display_roundtrip_details(result, status_fn, data, verbose)

    sys.exit(0 if result.equivalent else 1)
