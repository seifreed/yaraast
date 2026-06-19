"""CLI commands for AST-based analysis."""

from __future__ import annotations

import click

from yaraast.analysis.best_practices import BestPracticesAnalyzer
from yaraast.analysis.optimization import OptimizationAnalyzer
from yaraast.cli.analyze_reporting import (
    display_best_practices_report,
    display_issues,
    display_optimization_report,
    display_summary,
)
from yaraast.cli.analyze_services import _get_severity_counts
from yaraast.cli.utils import _validate_output_path, format_json, parse_yara_file, write_text


@click.group()
def analyze() -> None:
    """AST-based analysis commands."""


@analyze.command()
@click.argument("rule_file", type=click.Path(exists=True, dir_okay=False))
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
    output = _validate_output_path(output)
    try:
        ast = parse_yara_file(rule_file)
        best_report = BestPracticesAnalyzer().analyze(ast)
        opt_report = OptimizationAnalyzer().analyze(ast)

        if output_format == "json":
            result = {
                "best_practices": {
                    "statistics": best_report.statistics,
                    "suggestions": [
                        {
                            "rule": suggestion.rule_name,
                            "category": suggestion.category,
                            "severity": suggestion.severity,
                            "message": suggestion.message,
                            "location": suggestion.location,
                        }
                        for suggestion in best_report.suggestions
                    ],
                },
                "optimization": {
                    "statistics": opt_report.statistics,
                    "heuristic": getattr(opt_report, "is_heuristic", True),
                    "suggestions": [
                        {
                            "rule": suggestion.rule_name,
                            "type": suggestion.optimization_type,
                            "impact": suggestion.impact,
                            "description": suggestion.description,
                            "code_before": suggestion.code_before,
                            "code_after": suggestion.code_after,
                        }
                        for suggestion in opt_report.suggestions
                    ],
                },
            }
            json_output = format_json(result)
            if output is not None:
                write_text(output, json_output)
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
@click.argument("rule_file", type=click.Path(exists=True, dir_okay=False))
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
        ast = parse_yara_file(rule_file)
        report = BestPracticesAnalyzer().analyze(ast)
        display_best_practices_report(rule_file, report, verbose, category)
    except Exception as e:
        click.echo(f"Error: {e}", err=True)
        raise click.Abort from e


@analyze.command(name="optimize")
@click.argument("rule_file", type=click.Path(exists=True, dir_okay=False))
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
    output = _validate_output_path(output)
    try:
        ast = parse_yara_file(rule_file)
        report = OptimizationAnalyzer().analyze(ast)

        if output_format == "json":
            payload = {
                "statistics": report.statistics,
                "heuristic": getattr(report, "is_heuristic", True),
                "suggestions": [
                    {
                        "rule": suggestion.rule_name,
                        "type": suggestion.optimization_type,
                        "impact": suggestion.impact,
                        "description": suggestion.description,
                        "code_before": suggestion.code_before,
                        "code_after": suggestion.code_after,
                    }
                    for suggestion in report.suggestions
                ],
            }
            text = format_json(payload)
            if output is not None:
                write_text(output, text)
            else:
                click.echo(text)
            return

        display_optimization_report(rule_file, report, verbose)
    except Exception as e:
        click.echo(f"Error: {e}", err=True)
        raise click.Abort from e
