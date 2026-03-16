"""Display helpers for serialize CLI."""

from __future__ import annotations

from typing import Any

from rich.console import Console
from rich.panel import Panel
from rich.table import Table

from yaraast.serialization.ast_diff import DiffType

console = Console()


def _display_protobuf_stats(stats: dict[str, Any]) -> None:
    """Display Protobuf serialization statistics."""
    table = Table(title="Protobuf Serialization Stats")
    table.add_column("Metric", style="cyan")
    table.add_column("Value", style="green")

    table.add_row("Binary Size", f"{stats['binary_size_bytes']:,} bytes")
    table.add_row("Text Size", f"{stats['text_size_bytes']:,} bytes")
    table.add_row("Compression Ratio", f"{stats['compression_ratio']:.2f}x")
    table.add_row("Rules Count", str(stats["rules_count"]))
    table.add_row("Imports Count", str(stats["imports_count"]))

    console.print(table)


def _display_diff_summary(diff_result: Any) -> None:
    """Display difference summary table."""
    table = Table(title="AST Differences Summary")
    table.add_column("Change Type", style="cyan")
    table.add_column("Count", style="green", justify="right")

    summary = diff_result.change_summary
    for change_type, count in summary.items():
        if count > 0:
            icon = {
                "added": "+",
                "removed": "-",
                "modified": "📝",
                "moved": "↔️",
                "unchanged": "✅",
            }.get(change_type, "•")
            table.add_row(f"{icon} {change_type.title()}", str(count))

    console.print(table)


def _display_detailed_changes(diff_result: Any) -> None:
    """Display detailed changes if not too many."""
    if len(diff_result.differences) <= 20:
        console.print("\n[bold]Detailed Changes:[/bold]")
        for diff_node in diff_result.differences:
            icon = {
                DiffType.ADDED: "[green]+[/green]",
                DiffType.REMOVED: "[red]-[/red]",
                DiffType.MODIFIED: "[yellow]📝[/yellow]",
                DiffType.MOVED: "[blue]↔️[/blue]",
            }.get(diff_node.diff_type, "•")

            console.print(f"  {icon} {diff_node.path} ({diff_node.node_type})")
            if diff_node.diff_type == DiffType.MODIFIED:
                console.print(f"    [dim]Old:[/dim] {diff_node.old_value}")
                console.print(f"    [dim]New:[/dim] {diff_node.new_value}")
    else:
        console.print(
            f"\n[dim]Use --output to save detailed changes ({len(diff_result.differences)} total)[/dim]",
        )


def _display_diff_statistics(diff_result: Any) -> None:
    """Display comparison statistics."""
    stats_table = Table(title="Comparison Statistics")
    stats_table.add_column("Metric", style="cyan")
    stats_table.add_column("Old", style="red", justify="right")
    stats_table.add_column("New", style="green", justify="right")

    stats_table.add_row(
        "Rules",
        str(diff_result.statistics["old_rules_count"]),
        str(diff_result.statistics["new_rules_count"]),
    )
    stats_table.add_row(
        "Imports",
        str(diff_result.statistics["old_imports_count"]),
        str(diff_result.statistics["new_imports_count"]),
    )
    stats_table.add_row("AST Hash", diff_result.old_ast_hash, diff_result.new_ast_hash)

    console.print(stats_table)


def build_validation_panel(
    input_file: str,
    format: str,
    ast: Any | None,
    error: Exception | None,
) -> Panel:
    if error is None and ast is not None:
        return Panel(
            f"[green]✅ Valid {format.upper()} serialization[/green]\n\n"
            f"📊 Structure:\n"
            f"  • Rules: {len(ast.rules)}\n"
            f"  • Imports: {len(ast.imports)}\n"
            f"  • Includes: {len(ast.includes)}",
            title=f"Validation Result: {input_file}",
            border_style="green",
        )

    error_text = str(error) if error else "Unknown error"
    return Panel(
        f"[red]❌ Invalid {format.upper()} serialization[/red]\n\nError: {error_text}",
        title=f"Validation Result: {input_file}",
        border_style="red",
    )
