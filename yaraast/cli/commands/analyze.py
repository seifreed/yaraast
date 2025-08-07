"""CLI commands for AST-based analysis."""

import sys
from pathlib import Path

import click
from rich.console import Console
from rich.panel import Panel
from rich.table import Table

from yaraast.analysis import BestPracticesAnalyzer, OptimizationAnalyzer
from yaraast.parser import Parser

console = Console()


@click.group()
def analyze() -> None:
    """AST-based analysis commands."""


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
        _display_best_practices_report(rule_file, report, verbose, category)
    except Exception as e:
        console.print(f"[red]Error:[/red] {e}", style="bold")
        sys.exit(1)


def _parse_rule_file(rule_file: str):
    """Parse a YARA rule file."""
    with Path(rule_file).open() as f:
        content = f.read()
    parser = Parser()
    return parser.parse(content)


def _analyze_best_practices(ast):
    """Analyze AST for best practices."""
    analyzer = BestPracticesAnalyzer()
    return analyzer.analyze(ast)


def _display_best_practices_report(
    rule_file: str,
    report,
    verbose: bool,
    category: str,
) -> None:
    """Display best practices report."""
    console.print(f"\n[bold]Best Practices Analysis:[/bold] {rule_file}\n")

    errors, warnings, info = _get_severity_counts(report)
    _display_summary(errors, warnings, info)

    suggestions = _filter_suggestions(report.suggestions, category)
    _display_issues(suggestions)

    if verbose:
        _display_verbose_info(suggestions, report)

    _handle_exit_code(errors, warnings, info, verbose)


def _get_severity_counts(report):
    """Get counts by severity."""
    errors = report.get_by_severity("error")
    warnings = report.get_by_severity("warning")
    info = report.get_by_severity("info")
    return errors, warnings, info


def _display_summary(errors, warnings, info) -> None:
    """Display summary table."""
    summary = Table(show_header=False, box=None)
    summary.add_row("✗ Errors:", f"[red]{len(errors)}[/red]")
    summary.add_row("⚠ Warnings:", f"[yellow]{len(warnings)}[/yellow]")
    summary.add_row("i Info:", f"[blue]{len(info)}[/blue]")
    console.print(Panel(summary, title="Summary", width=30))


def _filter_suggestions(suggestions, category):
    """Filter suggestions by category."""
    if category != "all":
        return [s for s in suggestions if s.category == category]
    return suggestions


def _display_issues(suggestions) -> None:
    """Display errors and warnings."""
    important = [s for s in suggestions if s.severity in ("error", "warning")]
    if important:
        console.print("\n[bold red]Issues:[/bold red]")
        for suggestion in important:
            console.print(f"  {suggestion.format()}")


def _display_verbose_info(suggestions, report) -> None:
    """Display verbose information."""
    info_items = [s for s in suggestions if s.severity == "info"]
    if info_items:
        console.print("\n[bold blue]Suggestions:[/bold blue]")
        for suggestion in info_items:
            console.print(f"  {suggestion.format()}")

    if report.statistics:
        console.print("\n[dim]Statistics:[/dim]")
        for key, value in report.statistics.items():
            console.print(f"  {key}: {value}")


def _handle_exit_code(errors, warnings, info, verbose) -> None:
    """Handle exit code based on results."""
    if errors:
        sys.exit(2)
    elif warnings and not verbose:
        console.print(f"\n[dim]Use -v to see {len(info)} additional suggestions[/dim]")
        sys.exit(1)
    else:
        console.print("\n[green]✓ No major issues found[/green]")
        sys.exit(0)


def _optimize_display_impact_summary(report) -> None:
    """Display impact summary table."""
    table = Table(title="Optimization Opportunities")
    table.add_column("Impact", style="cyan")
    table.add_column("Count", justify="right")

    # Ensure statistics are populated
    if not report.statistics:
        report.statistics = {}
    if "by_impact" not in report.statistics:
        report.statistics["by_impact"] = {
            "high": sum(1 for s in report.suggestions if s.impact == "high"),
            "medium": sum(1 for s in report.suggestions if s.impact == "medium"),
            "low": sum(1 for s in report.suggestions if s.impact == "low"),
        }

    for level in ["high", "medium", "low"]:
        count = report.statistics["by_impact"].get(level, 0)
        style = {"high": "red", "medium": "yellow", "low": "green"}.get(level, "white")
        table.add_row(f"[{style}]{level.capitalize()}[/{style}]", str(count))

    console.print(table)


def _optimize_display_suggestions(suggestions, verbose) -> None:
    """Display optimization suggestions by impact level."""
    for level in ["high", "medium", "low"]:
        level_suggestions = [s for s in suggestions if s.impact == level]
        if level_suggestions:
            _display_suggestions_by_level(level_suggestions, level, verbose)


def _display_suggestions_by_level(level_suggestions, level, verbose) -> None:
    """Display suggestions for a specific impact level."""
    style = _get_level_style(level)
    console.print(f"\n[bold {style}]{level.capitalize()} Impact:[/bold {style}]")

    for suggestion in level_suggestions:
        console.print(f"  {suggestion.format()}")
        if verbose:
            _display_code_examples(suggestion)


def _get_level_style(level: str) -> str:
    """Get console style for impact level."""
    return {"high": "red", "medium": "yellow", "low": "blue"}.get(level, "white")


def _display_code_examples(suggestion) -> None:
    """Display before/after code examples if available."""
    if suggestion.code_before or suggestion.code_after:
        if suggestion.code_before:
            console.print(f"    Before: [dim]{suggestion.code_before}[/dim]")
        if suggestion.code_after:
            console.print(f"    After:  [green]{suggestion.code_after}[/green]")


@analyze.command()
@click.argument("rule_file", type=click.Path(exists=True))
@click.option("-v", "--verbose", is_flag=True, help="Show all optimizations")
@click.option(
    "-i",
    "--impact",
    type=click.Choice(["low", "medium", "high", "all"]),
    default="all",
    help="Filter by impact level",
)
def optimize(rule_file: str, verbose: bool, impact: str) -> None:
    """Analyze YARA rules for optimization opportunities.

    Uses AST analysis to identify patterns that could be optimized,
    including redundant strings, complex conditions, and more.

    Example:
        yaraast analyze optimize rules.yar
        yaraast analyze optimize rules.yar -i high

    """
    try:
        ast = _parse_rule_file(rule_file)
        analyzer = OptimizationAnalyzer()
        report = analyzer.analyze(ast)

        console.print(f"\n[bold]Optimization Analysis:[/bold] {rule_file}\n")
        _optimize_display_impact_summary(report)

        suggestions = report.suggestions
        if impact != "all":
            suggestions = [s for s in suggestions if s.impact == impact]

        _optimize_display_suggestions(suggestions, verbose)

        if verbose and report.statistics:
            console.print("\n[dim]Analysis Statistics:[/dim]")
            console.print(
                f"  Total suggestions: {report.statistics['total_suggestions']}",
            )

        # Exit based on results
        if report.high_impact_count > 0:
            console.print(
                f"\n[yellow]⚠ Found {report.high_impact_count} high-impact optimization opportunities[/yellow]",
            )
            sys.exit(1)
        elif len(report.suggestions) > 0:
            console.print(
                f"\n[blue]i Found {len(report.suggestions)} optimization suggestions[/blue]",
            )
            sys.exit(0)
        else:
            console.print("\n[green]✓ No optimization opportunities found[/green]")
            sys.exit(0)
    except Exception as e:
        console.print(f"[red]Error:[/red] {e}", style="bold")
        sys.exit(1)


@analyze.command()
@click.argument("rule_file", type=click.Path(exists=True))
@click.option("-o", "--output", type=click.Path(), help="Save report to file")
@click.option(
    "-f",
    "--format",
    type=click.Choice(["text", "json"]),
    default="text",
    help="Output format",
)
def _generate_json_report(rule_file, bp_report, opt_report):
    """Generate JSON format report."""
    return {
        "file": rule_file,
        "best_practices": {
            "suggestions": [
                {
                    "rule": s.rule_name,
                    "category": s.category,
                    "severity": s.severity,
                    "message": s.message,
                    "location": s.location,
                }
                for s in bp_report.suggestions
            ],
            "statistics": bp_report.statistics,
        },
        "optimizations": {
            "suggestions": [
                {
                    "rule": s.rule_name,
                    "type": s.optimization_type,
                    "impact": s.impact,
                    "description": s.description,
                }
                for s in opt_report.suggestions
            ],
            "statistics": opt_report.statistics,
        },
    }


def _generate_text_report(rule_file, bp_report, opt_report):
    """Generate text format report."""
    lines = []
    lines.append(f"AST Analysis Report: {rule_file}")
    lines.append("=" * 50)

    _add_best_practices_section(lines, bp_report)
    _add_optimizations_section(lines, opt_report)
    _add_summary_section(lines, bp_report, opt_report)

    return "\n".join(lines)


def _add_best_practices_section(lines, bp_report) -> None:
    """Add best practices section to report."""
    lines.append("\nBEST PRACTICES")
    lines.append("-" * 20)

    for severity in ["error", "warning", "info"]:
        items = bp_report.get_by_severity(severity)
        if items:
            lines.append(f"\n{severity.upper()}S ({len(items)}):")
            for s in items:
                lines.append(f"  {s.format()}")


def _add_optimizations_section(lines, opt_report) -> None:
    """Add optimizations section to report."""
    lines.append("\n\nOPTIMIZATIONS")
    lines.append("-" * 20)

    for impact_level in ["high", "medium", "low"]:
        items = [s for s in opt_report.suggestions if s.impact == impact_level]
        if items:
            lines.append(f"\n{impact_level.upper()} IMPACT ({len(items)}):")
            for s in items:
                lines.append(f"  {s.format()}")


def _add_summary_section(lines, bp_report, opt_report) -> None:
    """Add summary section to report."""
    lines.append("\n\nSUMMARY")
    lines.append("-" * 20)
    lines.append(
        f"Total issues: {len(bp_report.get_by_severity('error')) + len(bp_report.get_by_severity('warning'))}",
    )
    lines.append(
        f"Total suggestions: {len(bp_report.suggestions) + len(opt_report.suggestions)}",
    )


def full(rule_file: str, output: str, format: str) -> None:
    """Run full AST-based analysis (best practices + optimizations).

    Combines both best practices checking and optimization analysis
    into a comprehensive report.

    Example:
        yaraast analyze full rules.yar
        yaraast analyze full rules.yar -o report.txt

    """
    try:
        ast = _parse_rule_file(rule_file)

        bp_analyzer = BestPracticesAnalyzer()
        bp_report = bp_analyzer.analyze(ast)

        opt_analyzer = OptimizationAnalyzer()
        opt_report = opt_analyzer.analyze(ast)

        if format == "json":
            import json

            report_data = _generate_json_report(rule_file, bp_report, opt_report)

            if output:
                with Path(output).open("w") as f:
                    json.dump(report_data, f, indent=2)
                console.print(f"[green]Report saved to {output}[/green]")
            else:
                console.print(json.dumps(report_data, indent=2))
        else:
            report_text = _generate_text_report(rule_file, bp_report, opt_report)

            if output:
                with Path(output).open("w") as f:
                    f.write(report_text)
                console.print(f"[green]Report saved to {output}[/green]")
            else:
                console.print(report_text)

        # Exit code based on issues
        has_errors = len(bp_report.get_by_severity("error")) > 0
        has_high_impact = opt_report.high_impact_count > 0

        if has_errors:
            sys.exit(2)
        elif has_high_impact:
            sys.exit(1)
        else:
            sys.exit(0)
    except Exception as e:
        console.print(f"[red]Error:[/red] {e}", style="bold")
        sys.exit(1)
