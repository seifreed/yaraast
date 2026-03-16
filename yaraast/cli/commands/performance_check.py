"""Performance analysis command for YARA rules."""

from __future__ import annotations

from pathlib import Path

import click
from rich.console import Console
from rich.progress import track

from yaraast.cli.performance_check_reporting import (
    display_issue_totals,
    display_issues,
    display_no_issues,
    display_summary,
)
from yaraast.cli.performance_check_services import (
    analyze_rule_issues,
    filter_issues,
    parse_performance_file,
    summarize_issues,
)

console = Console()


@click.command(name="performance-check")
@click.argument("input_file", type=click.Path(exists=True, path_type=Path))
@click.option(
    "--severity",
    type=click.Choice(["all", "warning", "critical"]),
    default="all",
    help="Minimum severity level to show",
)
@click.option(
    "--limit",
    type=int,
    default=None,
    help="Limit number of issues to show",
)
@click.option(
    "--summary",
    is_flag=True,
    help="Show only summary statistics",
)
def performance_check(input_file: Path, severity: str, limit: int, summary: bool) -> None:
    """Analyze YARA rules for performance issues.

    This command identifies potential performance problems in YARA rules such as:
    - Hex strings with too many wildcards
    - Very short strings that match frequently
    - Problematic regex patterns
    - Strings that can slow down scanning
    """
    try:
        with console.status("[cyan]Parsing YARA file..."):
            ast = parse_performance_file(input_file)

        # Analyze all rules
        all_issues = []

        console.print(
            f"\n[cyan]Analyzing {len(ast.rules)} rules for performance issues...[/cyan]\n",
        )

        for rule in track(ast.rules, description="Analyzing rules"):
            issues = analyze_rule_issues(rule)
            all_issues.extend(issues)

        all_issues = filter_issues(all_issues, severity, limit)

        # Display results
        if not all_issues:
            display_no_issues(console)
            return

        if summary:
            issue_types = summarize_issues(all_issues)
            display_summary(console, issue_types, len(ast.rules), all_issues)
        else:
            display_issues(console, all_issues)

        display_issue_totals(console, all_issues)

    except Exception as e:
        console.print(f"[red]❌ Error: {e}[/red]")
        raise click.Abort from e


# Export the command
performance_check_cmd = performance_check
