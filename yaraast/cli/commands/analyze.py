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
def analyze():
    """AST-based analysis commands."""
    pass


@analyze.command()
@click.argument('rule_file', type=click.Path(exists=True))
@click.option('-v', '--verbose', is_flag=True, help='Show all suggestions')
@click.option('-c', '--category',
              type=click.Choice(['style', 'optimization', 'structure', 'all']),
              default='all', help='Filter by category')
def best_practices(rule_file: str, verbose: bool, category: str):
    """Analyze YARA rules for best practices using AST.

    This is not a full linter but an AST-based analyzer that identifies
    patterns and suggests improvements based on the rule structure.

    Example:
        yaraast analyze best-practices rules.yar
        yaraast analyze best-practices rules.yar -c style
    """
    try:
        # Parse rules
        with open(rule_file, 'r') as f:
            content = f.read()

        parser = Parser()
        ast = parser.parse(content)

        # Analyze
        analyzer = BestPracticesAnalyzer()
        report = analyzer.analyze(ast)

        # Display results
        console.print(f"\n[bold]Best Practices Analysis:[/bold] {rule_file}\n")

        # Summary
        errors = report.get_by_severity('error')
        warnings = report.get_by_severity('warning')
        info = report.get_by_severity('info')

        summary = Table(show_header=False, box=None)
        summary.add_row("✗ Errors:", f"[red]{len(errors)}[/red]")
        summary.add_row("⚠ Warnings:", f"[yellow]{len(warnings)}[/yellow]")
        summary.add_row("ℹ Info:", f"[blue]{len(info)}[/blue]")
        console.print(Panel(summary, title="Summary", width=30))

        # Filter suggestions
        suggestions = report.suggestions
        if category != 'all':
            suggestions = [s for s in suggestions if s.category == category]

        # Show errors and warnings always
        important = [s for s in suggestions if s.severity in ('error', 'warning')]
        if important:
            console.print("\n[bold red]Issues:[/bold red]")
            for suggestion in important:
                console.print(f"  {suggestion.format()}")

        # Show info only in verbose mode
        if verbose:
            info_items = [s for s in suggestions if s.severity == 'info']
            if info_items:
                console.print("\n[bold blue]Suggestions:[/bold blue]")
                for suggestion in info_items:
                    console.print(f"  {suggestion.format()}")

        # Statistics
        if verbose and report.statistics:
            console.print(f"\n[dim]Statistics:[/dim]")
            for key, value in report.statistics.items():
                console.print(f"  {key}: {value}")

        # Exit code based on errors/warnings
        if errors:
            sys.exit(2)
        elif warnings and not verbose:
            console.print(f"\n[dim]Use -v to see {len(info)} additional suggestions[/dim]")
            sys.exit(1)
        else:
            console.print("\n[green]✓ No major issues found[/green]")
            sys.exit(0)

    except Exception as e:
        console.print(f"[red]Error:[/red] {e}", style="bold")
        sys.exit(1)


@analyze.command()
@click.argument('rule_file', type=click.Path(exists=True))
@click.option('-v', '--verbose', is_flag=True, help='Show all optimizations')
@click.option('-i', '--impact',
              type=click.Choice(['low', 'medium', 'high', 'all']),
              default='all', help='Filter by impact level')
def optimize(rule_file: str, verbose: bool, impact: str):
    """Analyze YARA rules for optimization opportunities.

    Uses AST analysis to identify patterns that could be optimized,
    including redundant strings, complex conditions, and more.

    Example:
        yaraast analyze optimize rules.yar
        yaraast analyze optimize rules.yar -i high
    """
    try:
        # Parse rules
        with open(rule_file, 'r') as f:
            content = f.read()

        parser = Parser()
        ast = parser.parse(content)

        # Analyze
        analyzer = OptimizationAnalyzer()
        report = analyzer.analyze(ast)

        # Display results
        console.print(f"\n[bold]Optimization Analysis:[/bold] {rule_file}\n")

        # Summary by impact
        table = Table(title="Optimization Opportunities")
        table.add_column("Impact", style="cyan")
        table.add_column("Count", justify="right")

        for level in ['high', 'medium', 'low']:
            count = report.statistics['by_impact'].get(level, 0)
            style = {'high': 'red', 'medium': 'yellow', 'low': 'green'}.get(level, 'white')
            table.add_row(
                f"[{style}]{level.capitalize()}[/{style}]",
                str(count)
            )

        console.print(table)

        # Filter suggestions
        suggestions = report.suggestions
        if impact != 'all':
            suggestions = [s for s in suggestions if s.impact == impact]

        # Group by impact
        for level in ['high', 'medium', 'low']:
            level_suggestions = [s for s in suggestions if s.impact == level]
            if level_suggestions:
                style = {'high': 'red', 'medium': 'yellow', 'low': 'blue'}.get(level, 'white')
                console.print(f"\n[bold {style}]{level.capitalize()} Impact:[/bold {style}]")

                for suggestion in level_suggestions:
                    console.print(f"  {suggestion.format()}")

                    # Show code examples in verbose mode
                    if verbose and (suggestion.code_before or suggestion.code_after):
                        if suggestion.code_before:
                            console.print(f"    Before: [dim]{suggestion.code_before}[/dim]")
                        if suggestion.code_after:
                            console.print(f"    After:  [green]{suggestion.code_after}[/green]")

        # Additional statistics
        if verbose and report.statistics:
            console.print(f"\n[dim]Analysis Statistics:[/dim]")
            console.print(f"  Total suggestions: {report.statistics['total_suggestions']}")

        # Summary
        if report.high_impact_count > 0:
            console.print(f"\n[yellow]⚠ Found {report.high_impact_count} high-impact optimization opportunities[/yellow]")
            sys.exit(1)
        elif len(report.suggestions) > 0:
            console.print(f"\n[blue]ℹ Found {len(report.suggestions)} optimization suggestions[/blue]")
            sys.exit(0)
        else:
            console.print("\n[green]✓ No optimization opportunities found[/green]")
            sys.exit(0)

    except Exception as e:
        console.print(f"[red]Error:[/red] {e}", style="bold")
        sys.exit(1)


@analyze.command()
@click.argument('rule_file', type=click.Path(exists=True))
@click.option('-o', '--output', type=click.Path(), help='Save report to file')
@click.option('-f', '--format',
              type=click.Choice(['text', 'json']),
              default='text', help='Output format')
def full(rule_file: str, output: str, format: str):
    """Run full AST-based analysis (best practices + optimizations).

    Combines both best practices checking and optimization analysis
    into a comprehensive report.

    Example:
        yaraast analyze full rules.yar
        yaraast analyze full rules.yar -o report.txt
    """
    try:
        # Parse rules
        with open(rule_file, 'r') as f:
            content = f.read()

        parser = Parser()
        ast = parser.parse(content)

        # Run both analyzers
        bp_analyzer = BestPracticesAnalyzer()
        bp_report = bp_analyzer.analyze(ast)

        opt_analyzer = OptimizationAnalyzer()
        opt_report = opt_analyzer.analyze(ast)

        if format == 'json':
            import json
            report_data = {
                'file': rule_file,
                'best_practices': {
                    'suggestions': [
                        {
                            'rule': s.rule_name,
                            'category': s.category,
                            'severity': s.severity,
                            'message': s.message,
                            'location': s.location
                        }
                        for s in bp_report.suggestions
                    ],
                    'statistics': bp_report.statistics
                },
                'optimizations': {
                    'suggestions': [
                        {
                            'rule': s.rule_name,
                            'type': s.optimization_type,
                            'impact': s.impact,
                            'description': s.description
                        }
                        for s in opt_report.suggestions
                    ],
                    'statistics': opt_report.statistics
                }
            }

            if output:
                with open(output, 'w') as f:
                    json.dump(report_data, f, indent=2)
                console.print(f"[green]Report saved to {output}[/green]")
            else:
                console.print(json.dumps(report_data, indent=2))

        else:  # text format
            # Build text report
            lines = []
            lines.append(f"AST Analysis Report: {rule_file}")
            lines.append("=" * 50)

            # Best practices section
            lines.append("\nBEST PRACTICES")
            lines.append("-" * 20)

            for severity in ['error', 'warning', 'info']:
                items = bp_report.get_by_severity(severity)
                if items:
                    lines.append(f"\n{severity.upper()}S ({len(items)}):")
                    for s in items:
                        lines.append(f"  {s.format()}")

            # Optimization section
            lines.append("\n\nOPTIMIZATIONS")
            lines.append("-" * 20)

            for impact_level in ['high', 'medium', 'low']:
                items = [s for s in opt_report.suggestions if s.impact == impact_level]
                if items:
                    lines.append(f"\n{impact_level.upper()} IMPACT ({len(items)}):")
                    for s in items:
                        lines.append(f"  {s.format()}")

            # Summary
            lines.append("\n\nSUMMARY")
            lines.append("-" * 20)
            lines.append(f"Total issues: {len(bp_report.get_by_severity('error')) + len(bp_report.get_by_severity('warning'))}")
            lines.append(f"Total suggestions: {len(bp_report.suggestions) + len(opt_report.suggestions)}")

            report_text = "\n".join(lines)

            if output:
                with open(output, 'w') as f:
                    f.write(report_text)
                console.print(f"[green]Report saved to {output}[/green]")
            else:
                console.print(report_text)

        # Exit code based on issues
        has_errors = len(bp_report.get_by_severity('error')) > 0
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
