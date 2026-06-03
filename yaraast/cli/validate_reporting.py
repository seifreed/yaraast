"""Reporting helpers for validate CLI output."""

from __future__ import annotations

from collections.abc import Callable
from typing import Any

import click


def display_rule_file_valid(rules_count: int, imports_count: int, string_count: int) -> None:
    click.echo("Valid YARA file.")
    click.echo(f"Rules: {rules_count}")
    click.echo(f"Imports: {imports_count}")
    click.echo(f"Strings: {string_count}")


def display_rule_file_invalid(error: Exception) -> None:
    click.echo(f"Invalid YARA file: {error}", err=True)


def display_roundtrip_summary(result: Any) -> Callable[[bool], str]:
    if result.equivalent:
        click.echo(click.style("✓ Round-trip PASSED", fg="green", bold=True))
    else:
        click.echo(click.style("✗ Round-trip FAILED", fg="red", bold=True))

    def status(x: bool) -> str:
        return click.style("✓", fg="green") if x else click.style("✗", fg="red")

    click.echo(f"\n{status(result.ast_equivalent)} AST equivalence")
    click.echo(f"{status(result.code_equivalent)} Code generation equivalence")
    click.echo(f"{status(result.original_compiles)} Original compiles with libyara")
    click.echo(
        f"{status(result.regenerated_compiles)} Regenerated compiles with libyara",
    )

    return status


def display_differences(title: str, differences: list[Any]) -> None:
    if differences:
        click.echo(f"\n{title}:")
        for diff in differences:
            click.echo(f"  - {diff}")


def display_code_comparison(result: Any, verbose: bool) -> None:
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


def display_roundtrip_details(
    result: Any,
    status_fn: Callable[[bool], str],
    data: bytes | None,
    verbose: bool,
) -> None:
    if data:
        click.echo(f"{status_fn(result.scan_equivalent)} Scan results match")

    if verbose or not result.equivalent:
        display_differences("AST differences", result.ast_differences)
        display_differences("Compilation errors", result.compilation_errors)
        display_differences("Scan differences", result.scan_differences)
        display_code_comparison(result, verbose)
