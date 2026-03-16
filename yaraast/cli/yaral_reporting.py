"""Reporting helpers for YARA-L CLI commands."""

from __future__ import annotations

from pathlib import Path
from typing import Any

import click

from yaraast.cli.utils import format_json


def display_validation_results(
    file: str,
    ast: Any,
    errors: list[Any],
    warnings: list[Any],
    strict: bool,
    output_json: bool,
) -> None:
    if output_json:
        _display_json_results(file, errors, warnings, strict)
    else:
        _display_text_results(ast, errors, warnings, strict)


def _display_json_results(file: str, errors: list[Any], warnings: list[Any], strict: bool) -> None:
    result = {
        "file": file,
        "errors": [
            {"severity": e.severity, "message": e.message, "section": e.section} for e in errors
        ],
        "warnings": [
            {"severity": w.severity, "message": w.message, "section": w.section} for w in warnings
        ],
        "valid": len(errors) == 0 and (not strict or len(warnings) == 0),
    }
    click.echo(format_json(result))


def _display_text_results(ast, errors, warnings, strict):
    if errors:
        click.echo("❌ Validation Errors:", err=True)
        for error in errors:
            click.echo(f"  • {error}", err=True)

    if warnings:
        click.echo("⚠️  Validation Warnings:")
        for warning in warnings:
            click.echo(f"  • {warning}")

    if not errors and (not strict or not warnings):
        click.echo(f"✅ YARA-L file is valid ({len(ast.rules)} rules)")
    else:
        click.echo(
            f"❌ YARA-L file has {len(errors)} errors and {len(warnings)} warnings",
            err=True,
        )
        if strict and warnings:
            raise click.Abort() from None


def write_output(output: str | None, code: str, success_message: str) -> None:
    if output:
        Path(output).write_text(code)
        click.echo(success_message)
    else:
        click.echo(code)


def display_parse_mode(enhanced: bool) -> None:
    click.echo("Using enhanced YARA-L parser..." if enhanced else "Using standard YARA-L parser...")


def display_parse_success(rule_count: int) -> None:
    click.echo(f"✅ Successfully parsed {rule_count} rules")


def display_generate_success(rule_count: int) -> None:
    click.echo(f"✅ Successfully generated code for {rule_count} rules")


def display_optimize_preview(stats) -> None:
    click.echo("🔍 Optimization Preview (dry run):")
    click.echo(f"  • Would optimize {stats.rules_optimized} rules")
    click.echo(f"  • Would simplify {stats.conditions_simplified} conditions")
    click.echo(f"  • Would optimize {stats.events_optimized} events")
    click.echo(f"  • Would remove {stats.redundant_checks_removed} redundant checks")
    click.echo(f"  • Would suggest {stats.indexes_suggested} indexes")


def display_optimize_stats(stats) -> None:
    click.echo("\n📊 Optimization Statistics:")
    click.echo(f"  • Rules optimized: {stats.rules_optimized}")
    click.echo(f"  • Conditions simplified: {stats.conditions_simplified}")
    click.echo(f"  • Events optimized: {stats.events_optimized}")
    click.echo(f"  • Redundant checks removed: {stats.redundant_checks_removed}")
    click.echo(f"  • Indexes suggested: {stats.indexes_suggested}")
    click.echo(f"  • Time windows optimized: {stats.time_windows_optimized}")


def display_semantic_compare(equal: bool) -> None:
    click.echo(
        "✅ Files are semantically equivalent" if equal else "❌ Files are semantically different"
    )


def display_structural_compare(differences: list[str]) -> None:
    if differences:
        click.echo("❌ Files have differences:")
        for diff in differences:
            click.echo(f"  • {diff}")
    else:
        click.echo("✅ Files have the same structure")


def display_info(examples: bool, fields: bool, functions: bool, validator) -> None:
    if examples:
        click.echo("📚 Example YARA-L Rules:\n")
        click.echo(
            """rule suspicious_login_attempts {
    meta:
        author = "security-team"
        description = "Detect multiple failed login attempts"
        severity = "medium"

    events:
        $login.metadata.event_type = "USER_LOGIN"
        $login.security_result.action = "BLOCK"
        $login.principal.user = $user

    match:
        $user over 5m

    condition:
        #login > 5

    outcome:
        $risk_score = 50 + (#login * 10)
        $affected_user = $user
        $login_count = count($login)
}"""
        )

    if fields:
        click.echo("📋 Valid UDM Field Namespaces:\n")
        for namespace, fields_list in validator.VALID_UDM_FIELDS.items():
            click.echo(f"  {namespace}:")
            for field in fields_list[:5]:
                click.echo(f"    • {field}")
            if len(fields_list) > 5:
                click.echo(f"    ... and {len(fields_list) - 5} more")

    if functions:
        click.echo("🔧 Available Aggregation Functions:\n")
        functions = [
            ("count", "Count number of events"),
            ("count_distinct", "Count unique values"),
            ("sum", "Sum numeric values"),
            ("avg", "Calculate average"),
            ("min", "Find minimum value"),
            ("max", "Find maximum value"),
            ("array", "Collect values into array"),
            ("array_distinct", "Collect unique values into array"),
            ("string_concat", "Concatenate string values"),
        ]
        for func, desc in functions:
            click.echo(f"  • {func}(): {desc}")

    if not any([examples, fields, functions]):
        click.echo("YARA-L Support Status:")
        click.echo("  ✅ Basic rule parsing")
        click.echo("  ✅ Event patterns and UDM fields")
        click.echo("  ✅ Time windows and correlation")
        click.echo("  ✅ Aggregation functions")
        click.echo("  ✅ Conditional expressions")
        click.echo("  ✅ Semantic validation")
        click.echo("  ✅ Query optimization")
        click.echo("  ✅ Code generation")
        click.echo("\nUse --examples, --fields, or --functions for more details.")
