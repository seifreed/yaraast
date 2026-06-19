"""CLI command for YARA rule validation and libyara round-trip testing."""

from __future__ import annotations

import sys

import click

from yaraast.cli.validate_reporting import (
    display_roundtrip_details,
    display_roundtrip_summary,
    display_rule_file_invalid,
    display_rule_file_valid,
)
from yaraast.cli.validate_services import (
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
            return "_file", _VALIDATE_FILE_COMMAND, args
        return super().resolve_command(ctx, args)


def _validate_rule_file(rule_file: str) -> int:
    """Basic validation for backward-compatible `validate <file>` usage."""
    try:
        _ast, rules_count, imports_count, string_count = validate_rule_file(rule_file)
    except Exception as exc:
        display_rule_file_invalid(exc)
        return 1

    display_rule_file_valid(rules_count, imports_count, string_count)
    return 0


def _invoke_validate_rule_file(rule_file: str) -> None:
    code = _validate_rule_file(rule_file)
    if code != 0:
        raise SystemExit(code)


_VALIDATE_FILE_COMMAND = click.Command(
    name="_file",
    callback=_invoke_validate_rule_file,
    params=[click.Argument(["rule_file"], type=click.Path(exists=True, dir_okay=False))],
    hidden=True,
)


@click.group(cls=ValidateGroup)
def validate() -> None:
    """YARA rule validation commands."""


@validate.command()
@click.argument("rule_file", type=click.Path(exists=True, dir_okay=False))
@click.option(
    "-d",
    "--test-data",
    type=click.Path(exists=True, dir_okay=False),
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
