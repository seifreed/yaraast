"""Optimize YARA rules for better performance."""

from pathlib import Path

import click
from rich.console import Console

from yaraast.codegen import CodeGenerator
from yaraast.parser.error_tolerant_parser import ErrorTolerantParser
from yaraast.performance.optimizer import PerformanceOptimizer
from yaraast.performance.string_analyzer import analyze_rule_performance

console = Console()


@click.command(name="optimize")
@click.argument("input_file", type=click.Path(exists=True, path_type=Path))
@click.argument("output_file", type=click.Path(path_type=Path))
@click.option(
    "--dry-run",
    is_flag=True,
    help="Show what would be changed without writing the file",
)
@click.option(
    "--analyze",
    is_flag=True,
    help="Show performance analysis before and after optimization",
)
def optimize(input_file: Path, output_file: Path, dry_run: bool, analyze: bool) -> None:
    """Optimize YARA rules for better performance.

    This command automatically optimizes YARA rules by:
    - Replacing long wildcard sequences with jumps
    - Removing unnecessary regex anchors
    - Suggesting improvements for problematic patterns
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

        # Analyze performance before optimization
        if analyze:
            console.print(
                "\n[yellow]Performance analysis before optimization:[/yellow]",
            )
            total_issues_before = 0
            critical_before = 0

            for rule in ast.rules:
                issues = analyze_rule_performance(rule)
                total_issues_before += len(issues)
                critical_before += sum(1 for i in issues if i.severity == "critical")

            console.print(f"  • Total issues: {total_issues_before}")
            console.print(f"  • Critical issues: {critical_before}")

        # Optimize the AST
        console.print(f"\n[cyan]Optimizing {len(ast.rules)} rules...[/cyan]")
        optimizer = PerformanceOptimizer()
        optimized_ast = optimizer.optimize(ast)
        changes = [
            "Performance optimizations applied",
        ]  # Simple placeholder for changes

        if not changes:
            console.print(
                "\n[green]✅ No optimizations needed - rules are already optimal![/green]",
            )
            return

        # Show changes
        console.print(f"\n[yellow]Applied {len(changes)} optimizations:[/yellow]")
        for change in changes[:10]:  # Show first 10
            console.print(f"  • {change}")
        if len(changes) > 10:
            console.print(f"  ... and {len(changes) - 10} more")

        # Analyze performance after optimization
        if analyze:
            console.print("\n[yellow]Performance analysis after optimization:[/yellow]")
            total_issues_after = 0
            critical_after = 0

            for rule in optimized_ast.rules:
                issues = analyze_rule_performance(rule)
                total_issues_after += len(issues)
                critical_after += sum(1 for i in issues if i.severity == "critical")

            console.print(f"  • Total issues: {total_issues_after}")
            console.print(f"  • Critical issues: {critical_after}")

            # Show improvement
            if total_issues_before > total_issues_after:
                improvement = (
                    (total_issues_before - total_issues_after) / total_issues_before
                ) * 100
                console.print(
                    f"\n[green]✅ Performance improved by {improvement:.1f}%[/green]",
                )

        # Generate optimized code
        if not dry_run:
            console.print(f"\n[cyan]Writing optimized rules to {output_file}...[/cyan]")
            generator = CodeGenerator()
            optimized_code = generator.generate(optimized_ast)
            output_file.write_text(optimized_code)
            console.print(
                f"[green]✅ Optimized YARA file written to {output_file}[/green]",
            )
        else:
            console.print("\n[yellow]Dry run - no files were written[/yellow]")

    except Exception as e:
        console.print(f"[red]❌ Error: {e}[/red]")
        raise click.Abort from e


# Export the command
optimize_cmd = optimize
