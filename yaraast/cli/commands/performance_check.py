"""Performance analysis command for YARA rules."""

from pathlib import Path

import click
from rich.console import Console
from rich.progress import track
from rich.table import Table

from yaraast.parser.error_tolerant_parser import ErrorTolerantParser
from yaraast.performance.string_analyzer import StringPerformanceIssue, analyze_rule_performance

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
        # Parse the YARA file
        with console.status("[cyan]Parsing YARA file..."):
            content = input_file.read_text()
            parser = ErrorTolerantParser()
            ast, _, _ = parser.parse_with_errors(content)

        if not ast:
            console.print("[red]❌ Failed to parse YARA file[/red]")
            raise click.Abort

        # Analyze all rules
        all_issues: list[StringPerformanceIssue] = []

        console.print(
            f"\n[cyan]Analyzing {len(ast.rules)} rules for performance issues...[/cyan]\n",
        )

        for rule in track(ast.rules, description="Analyzing rules"):
            issues = analyze_rule_performance(rule)
            all_issues.extend(issues)

        # Filter by severity
        if severity == "warning":
            all_issues = [i for i in all_issues if i.severity == "warning"]
        elif severity == "critical":
            all_issues = [i for i in all_issues if i.severity == "critical"]

        # Apply limit
        if limit:
            all_issues = all_issues[:limit]

        # Display results
        if not all_issues:
            console.print("[green]✅ No performance issues found![/green]")
            return

        if summary:
            # Show summary statistics
            display_summary(all_issues, len(ast.rules))
        else:
            # Show detailed issues
            display_issues(all_issues)

        # Show statistics
        console.print(f"\n[yellow]Found {len(all_issues)} performance issues[/yellow]")

        critical_count = sum(1 for i in all_issues if i.severity == "critical")
        if critical_count > 0:
            console.print(
                f"[red]⚠️  {critical_count} critical issues that may severely impact scanning speed[/red]",
            )

    except Exception as e:
        console.print(f"[red]❌ Error: {e}[/red]")
        raise click.Abort from e


def display_issues(issues: list[StringPerformanceIssue]) -> None:
    """Display performance issues in a table."""
    table = Table(
        title="Performance Issues",
        show_header=True,
        header_style="bold cyan",
    )

    table.add_column("Rule", style="yellow", no_wrap=True)
    table.add_column("String", style="cyan")
    table.add_column("Issue", style="white")
    table.add_column("Severity", style="red")
    table.add_column("Description", style="white", max_width=50)

    for issue in issues:
        severity_style = "red bold" if issue.severity == "critical" else "yellow"
        table.add_row(
            issue.rule_name,
            issue.string_id,
            issue.issue_type,
            f"[{severity_style}]{issue.severity}[/{severity_style}]",
            issue.description,
        )

    console.print(table)

    # Show suggestions
    console.print("\n[cyan]Suggestions:[/cyan]")
    unique_suggestions = {i.suggestion for i in issues if i.suggestion}
    for suggestion in unique_suggestions:
        console.print(f"  • {suggestion}")


def display_summary(issues: list[StringPerformanceIssue], total_rules: int) -> None:
    """Display summary statistics."""
    # Group by issue type
    issue_types = {}
    for issue in issues:
        if issue.issue_type not in issue_types:
            issue_types[issue.issue_type] = {"count": 0, "critical": 0, "rules": set()}
        issue_types[issue.issue_type]["count"] += 1
        if issue.severity == "critical":
            issue_types[issue.issue_type]["critical"] += 1
        issue_types[issue.issue_type]["rules"].add(issue.rule_name)

    # Create summary table
    table = Table(
        title="Performance Issue Summary",
        show_header=True,
        header_style="bold cyan",
    )

    table.add_column("Issue Type", style="yellow")
    table.add_column("Count", justify="right")
    table.add_column("Critical", justify="right", style="red")
    table.add_column("Affected Rules", justify="right")

    for issue_type, stats in sorted(
        issue_types.items(),
        key=lambda x: x[1]["count"],
        reverse=True,
    ):
        table.add_row(
            issue_type.replace("_", " ").title(),
            str(stats["count"]),
            str(stats["critical"]) if stats["critical"] > 0 else "-",
            str(len(stats["rules"])),
        )

    console.print(table)

    # Overall statistics
    affected_rules = len({i.rule_name for i in issues})
    console.print("\n[cyan]Overall Statistics:[/cyan]")
    console.print(f"  • Total rules analyzed: {total_rules}")
    console.print(
        f"  • Rules with issues: {affected_rules} ({affected_rules / total_rules * 100:.1f}%)",
    )
    console.print(f"  • Total issues found: {len(issues)}")
    console.print(
        f"  • Critical issues: {sum(1 for i in issues if i.severity == 'critical')}",
    )


# Export the command
performance_check_cmd = performance_check
