"""CLI commands for AST-based analysis."""

from __future__ import annotations

from pathlib import Path

import click

from yaraast.cli.analyze_reporting import (
    display_best_practices_report,
    display_issues,
    display_optimization_report,
    display_summary,
)
from yaraast.cli.analyze_services import (
    _analyze_best_practices,
    _analyze_optimizations,
    _best_report_to_dict,
    _get_severity_counts,
    _opt_report_to_dict,
    _parse_rule_file,
)
from yaraast.cli.utils import format_json


@click.group()
def analyze() -> None:
    """AST-based analysis commands."""


@analyze.command()
@click.argument("rule_file", type=click.Path(exists=True))
@click.option(
    "-f",
    "--format",
    "output_format",
    type=click.Choice(["text", "json"]),
    default="text",
    help="Output format",
)
@click.option("-o", "--output", type=click.Path(), help="Output file path")
def full(rule_file: str, output_format: str, output: str | None) -> None:
    """Run full analysis (best practices + optimization)."""
    try:
        ast = _parse_rule_file(rule_file)
        best_report = _analyze_best_practices(ast)
        opt_report = _analyze_optimizations(ast)

        if output_format == "json":
            result = {
                "best_practices": _best_report_to_dict(best_report),
                "optimization": _opt_report_to_dict(opt_report),
            }
            json_output = format_json(result)
            if output:
                Path(output).write_text(json_output)
            else:
                click.echo(json_output)
            return

        display_summary(*_get_severity_counts(best_report))
        display_issues(best_report.suggestions)
        display_optimization_report(rule_file, opt_report, verbose=False)

    except Exception as e:
        click.echo(f"Error: {e}", err=True)
        raise click.Abort from e


@analyze.command()
@click.argument("rule_file", type=click.Path(exists=True))
@click.option("-v", "--verbose", is_flag=True, help="Show all suggestions")
@click.option(
    "-c",
    "--category",
    type=click.Choice(["style", "optimization", "structure", "all"]),
    default="all",
    help="Filter by category",
)
def best_practices(rule_file: str, verbose: bool, category: str) -> None:
    """Analyze YARA rules for best practices using AST.

    This is not a full linter but an AST-based analyzer that identifies
    patterns and suggests improvements based on the rule structure.

    Example:
        yaraast analyze best-practices rules.yar
        yaraast analyze best-practices rules.yar -c style

    """
    try:
        ast = _parse_rule_file(rule_file)
        report = _analyze_best_practices(ast)
        display_best_practices_report(rule_file, report, verbose, category)
    except Exception as e:
        click.echo(f"Error: {e}", err=True)
        raise click.Abort from e


@analyze.command(name="optimize")
@click.argument("rule_file", type=click.Path(exists=True))
@click.option("-v", "--verbose", is_flag=True, help="Show all optimization suggestions")
@click.option(
    "-f",
    "--format",
    "output_format",
    type=click.Choice(["text", "json"]),
    default="text",
    help="Output format",
)
@click.option("-o", "--output", type=click.Path(), help="Output file path")
def optimize(rule_file: str, verbose: bool, output_format: str, output: str | None) -> None:
    """Analyze optimization opportunities for YARA rules."""
    try:
        ast = _parse_rule_file(rule_file)
        report = _analyze_optimizations(ast)

        if output_format == "json":
            payload = _opt_report_to_dict(report)
            text = format_json(payload)
            if output:
                Path(output).write_text(text, encoding="utf-8")
            else:
                click.echo(text)
            return

        display_optimization_report(rule_file, report, verbose)
    except Exception as e:
        click.echo(f"Error: {e}", err=True)
        raise click.Abort from e
