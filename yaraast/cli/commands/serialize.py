"""CLI commands for AST serialization."""

import sys
from pathlib import Path

import click
from rich.console import Console
from rich.panel import Panel
from rich.syntax import Syntax
from rich.table import Table

from yaraast.parser import Parser
from yaraast.serialization import (
    AstDiff,
    DiffType,
    JsonSerializer,
    ProtobufSerializer,
    YamlSerializer,
)

console = Console()


@click.group()
def serialize() -> None:
    """AST serialization commands for export/import and versioning."""


def _export_json(ast, output: str, minimal: bool, pretty: bool) -> None:
    """Export AST to JSON format."""
    serializer = JsonSerializer(include_metadata=not minimal)
    result = serializer.serialize(ast, output)
    if pretty and not output:
        syntax = Syntax(result, "json", theme="monokai", line_numbers=True)
        console.print(syntax)


def _export_yaml(ast, output: str, minimal: bool, pretty: bool) -> None:
    """Export AST to YAML format."""
    serializer = YamlSerializer(include_metadata=not minimal)
    if minimal:
        result = serializer.serialize_minimal(ast, output)
    else:
        result = serializer.serialize(ast, output)
    if pretty and not output:
        syntax = Syntax(result, "yaml", theme="monokai", line_numbers=True)
        console.print(syntax)


def _export_protobuf(ast, output: str, minimal: bool, pretty: bool) -> None:
    """Export AST to Protobuf format."""
    serializer = ProtobufSerializer(include_metadata=not minimal)

    if output and output.endswith(".txt"):
        # Text format for debugging
        result = serializer.serialize_text(ast, output)
        if pretty:
            console.print(result)
    else:
        # Binary format
        serializer.serialize(ast, output)
        stats = serializer.get_serialization_stats(ast)
        _display_protobuf_stats(stats)


def _display_protobuf_stats(stats: dict) -> None:
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


@serialize.command()
@click.argument("input_file", type=click.Path(exists=True))
@click.option("-o", "--output", type=click.Path(), help="Output file path")
@click.option(
    "-f",
    "--format",
    type=click.Choice(["json", "yaml", "protobuf"]),
    default="json",
    help="Serialization format",
)
@click.option("--minimal", is_flag=True, help="Minimal output (no metadata)")
@click.option("--pretty", is_flag=True, help="Pretty print output to console")
def export(input_file: str, output: str, format: str, minimal: bool, pretty: bool) -> None:
    """Export YARA AST to various serialization formats.

    Supports JSON, YAML, and Protobuf formats for AST persistence
    and interchange in CI/CD pipelines.

    Examples:
        yaraast serialize export rules.yar -f yaml -o rules.yaml
        yaraast serialize export rules.yar -f protobuf -o rules.pb
        yaraast serialize export rules.yar --pretty

    """
    try:
        # Parse YARA file
        with console.status(f"[bold green]Parsing {input_file}..."):
            with Path(input_file).open() as f:
                content = f.read()

            parser = Parser()
            ast = parser.parse(content)

        # Choose serializer
        if format == "json":
            _export_json(ast, output, minimal, pretty)
        elif format == "yaml":
            _export_yaml(ast, output, minimal, pretty)
        elif format == "protobuf":
            _export_protobuf(ast, output, minimal, pretty)

        if output:
            console.print(f"✅ AST exported to {output} ({format} format)")
        elif not pretty:
            console.print("✅ AST serialized successfully")

    except Exception as e:
        console.print(f"[red]❌ Error: {e}[/red]")
        sys.exit(1)


@serialize.command()
@click.argument("input_file", type=click.Path(exists=True))
@click.option(
    "-f",
    "--format",
    type=click.Choice(["json", "yaml", "protobuf"]),
    default="json",
    help="Input serialization format",
)
@click.option("-o", "--output", type=click.Path(), help="Output YARA file")
def import_ast(input_file: str, format: str, output: str) -> None:
    """Import AST from serialized format back to YARA code.

    Note: Full round-trip import is not yet implemented.
    This command validates the serialized format.

    Examples:
        yaraast serialize import rules.json -f json
        yaraast serialize import rules.yaml -f yaml

    """
    try:
        # Choose serializer
        if format == "json":
            serializer = JsonSerializer()
            ast = serializer.deserialize(input_path=input_file)
        elif format == "yaml":
            serializer = YamlSerializer()
            ast = serializer.deserialize(input_path=input_file)
        elif format == "protobuf":
            serializer = ProtobufSerializer()
            ast = serializer.deserialize(input_path=input_file)

        console.print(f"✅ AST imported from {input_file} ({format} format)")
        console.print(f"📊 Rules: {len(ast.rules)}, Imports: {len(ast.imports)}")

        if output:
            # Would generate YARA code here
            console.print("⚠️  Code generation not yet implemented")

    except Exception as e:
        console.print(f"[red]❌ Error: {e}[/red]")
        sys.exit(1)


def _display_diff_summary(diff_result) -> None:
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


def _display_detailed_changes(diff_result) -> None:
    """Display detailed changes if not too many."""
    if len(diff_result.differences) <= 20:  # Show details for small diffs
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


def _display_diff_statistics(diff_result) -> None:
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


@serialize.command()
@click.argument("old_file", type=click.Path(exists=True))
@click.argument("new_file", type=click.Path(exists=True))
@click.option("-o", "--output", type=click.Path(), help="Output diff file")
@click.option(
    "-f",
    "--format",
    type=click.Choice(["json", "yaml"]),
    default="json",
    help="Diff output format",
)
@click.option("--patch", is_flag=True, help="Create patch file")
@click.option("--stats", is_flag=True, help="Show detailed statistics")
def diff(
    old_file: str,
    new_file: str,
    output: str,
    format: str,
    patch: bool,
    stats: bool,
) -> None:
    """Compare two YARA files and show AST differences.

    Provides incremental versioning by analyzing structural changes
    between AST versions. Useful for CI/CD pipelines and change tracking.

    Examples:
        yaraast serialize diff old.yar new.yar
        yaraast serialize diff v1.yar v2.yar -o changes.json --patch
        yaraast serialize diff old.yar new.yar --stats

    """
    try:
        # Parse both files
        with console.status("[bold green]Parsing files..."):
            parser = Parser()

            with Path(old_file).open() as f:
                old_ast = parser.parse(f.read())

            with Path(new_file).open() as f:
                new_ast = parser.parse(f.read())

        # Compare ASTs
        with console.status("[bold green]Comparing ASTs..."):
            differ = AstDiff()
            diff_result = differ.compare(old_ast, new_ast)

        # Display results
        if not diff_result.has_changes:
            console.print("✅ No differences found - ASTs are identical")
            return

        _display_diff_summary(diff_result)
        _display_detailed_changes(diff_result)

        if stats:
            _display_diff_statistics(diff_result)

        # Save output
        if output or patch:
            output_path = output or f"diff_{Path(old_file).stem}_to_{Path(new_file).stem}.{format}"

            if patch:
                differ.create_patch(diff_result, output_path)
                console.print(f"✅ Patch file created: {output_path}")
            else:
                diff_data = diff_result.to_dict()

                if format == "json":
                    import json

                    with Path(output_path).open("w") as f:
                        json.dump(diff_data, f, indent=2)
                elif format == "yaml":
                    import yaml

                    with Path(output_path).open("w") as f:
                        yaml.dump(diff_data, f, default_flow_style=False, indent=2)

                console.print(f"✅ Diff saved to: {output_path}")

    except Exception as e:
        console.print(f"[red]❌ Error: {e}[/red]")
        sys.exit(1)


@serialize.command()
@click.argument("input_file", type=click.Path(exists=True))
@click.option(
    "-f",
    "--format",
    type=click.Choice(["json", "yaml", "protobuf"]),
    default="json",
    help="Serialization format to validate",
)
def validate(input_file: str, format: str) -> None:
    """Validate serialized AST format.

    Checks if the serialized file can be properly loaded and
    contains valid AST structure.

    Examples:
        yaraast serialize validate rules.json
        yaraast serialize validate rules.yaml -f yaml

    """
    try:
        if format == "json":
            serializer = JsonSerializer()
            ast = serializer.deserialize(input_path=input_file)
        elif format == "yaml":
            serializer = YamlSerializer()
            ast = serializer.deserialize(input_path=input_file)
        elif format == "protobuf":
            serializer = ProtobufSerializer()
            ast = serializer.deserialize(input_path=input_file)

        console.print(
            Panel(
                f"[green]✅ Valid {format.upper()} serialization[/green]\n\n"
                f"📊 Structure:\n"
                f"  • Rules: {len(ast.rules)}\n"
                f"  • Imports: {len(ast.imports)}\n"
                f"  • Includes: {len(ast.includes)}",
                title=f"Validation Result: {Path(input_file).name}",
                border_style="green",
            ),
        )

    except Exception as e:
        console.print(
            Panel(
                f"[red]❌ Invalid {format.upper()} serialization[/red]\n\nError: {e}",
                title=f"Validation Result: {Path(input_file).name}",
                border_style="red",
            ),
        )
        sys.exit(1)


@serialize.command()
@click.argument("input_file", type=click.Path(exists=True))
def info(input_file: str) -> None:
    """Show information about a YARA file's AST structure.

    Provides detailed analysis of the AST without full serialization.
    Useful for understanding rule complexity and structure.

    Example:
        yaraast serialize info rules.yar

    """
    try:
        # Parse file
        with Path(input_file).open() as f:
            content = f.read()

        parser = Parser()
        ast = parser.parse(content)

        # Basic info
        info_table = Table(title=f"AST Information: {Path(input_file).name}")
        info_table.add_column("Component", style="cyan")
        info_table.add_column("Count", style="green", justify="right")
        info_table.add_column("Details", style="dim")

        info_table.add_row(
            "Rules",
            str(len(ast.rules)),
            ", ".join(rule.name for rule in ast.rules[:3]) + ("..." if len(ast.rules) > 3 else ""),
        )
        info_table.add_row(
            "Imports",
            str(len(ast.imports)),
            ", ".join(imp.module for imp in ast.imports),
        )
        info_table.add_row(
            "Includes",
            str(len(ast.includes)),
            ", ".join(inc.path for inc in ast.includes),
        )

        console.print(info_table)

        # Rule details
        if ast.rules:
            rule_table = Table(title="Rule Analysis")
            rule_table.add_column("Rule", style="cyan")
            rule_table.add_column("Strings", justify="right")
            rule_table.add_column("Tags", justify="right")
            rule_table.add_column("Meta", justify="right")
            rule_table.add_column("Modifiers", style="dim")

            for rule in ast.rules[:10]:  # Show first 10 rules
                rule_table.add_row(
                    rule.name,
                    str(len(rule.strings)),
                    str(len(rule.tags)),
                    str(len(rule.meta)),
                    ", ".join(rule.modifiers) if rule.modifiers else "none",
                )

            if len(ast.rules) > 10:
                dim_ellipsis = "[dim]...[/dim]"
                rule_table.add_row(
                    dim_ellipsis,
                    dim_ellipsis,
                    dim_ellipsis,
                    dim_ellipsis,
                    dim_ellipsis,
                )

            console.print(rule_table)

        # Hash info
        from yaraast.serialization.ast_diff import AstHasher

        hasher = AstHasher()
        ast_hash = hasher.hash_ast(ast)

        console.print(f"\n[dim]AST Hash: {ast_hash}[/dim]")

    except Exception as e:
        console.print(f"[red]❌ Error: {e}[/red]")
        sys.exit(1)
