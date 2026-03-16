"""Reporting helpers for serialize CLI output."""

from __future__ import annotations

from pathlib import Path
from typing import Any

from rich.console import Console
from rich.syntax import Syntax
from rich.table import Table

from yaraast.cli.utils import format_json, write_text


def display_export_result(
    console: Console,
    result: str | None,
    fmt: str,
    output: str | None,
    pretty: bool,
    stats: dict | None,
) -> None:
    if pretty and result and not output:
        syntax = Syntax(result, fmt, theme="monokai", line_numbers=True)
        console.print(syntax)
    if stats:
        from yaraast.cli.serialize_display_services import _display_protobuf_stats

        _display_protobuf_stats(stats)

    if output:
        console.print(f"✅ AST exported to {output} ({fmt} format)")
    elif not pretty:
        console.print("✅ AST serialized successfully")


def display_import_result(
    console: Console, input_file: str, fmt: str, ast: Any, output: str | None
) -> None:
    console.print(f"✅ AST imported from {input_file} ({fmt} format)")
    console.print(f"📊 Rules: {len(ast.rules)}, Imports: {len(ast.imports)}")
    if output:
        console.print("⚠️  Code generation not yet implemented")


def display_diff_no_changes(console: Console) -> None:
    console.print("✅ No differences found - ASTs are identical")


def write_diff_output(output_path: str, fmt: str, diff_data: dict) -> None:
    if fmt == "json":
        write_text(output_path, format_json(diff_data, ensure_ascii=False))
    else:
        import yaml

        write_text(
            output_path,
            yaml.safe_dump(
                diff_data,
                default_flow_style=False,
                sort_keys=False,
            ),
        )


def display_diff_saved(console: Console, output_path: str, patch: bool) -> None:
    if patch:
        console.print(f"✅ Patch file created: {output_path}")
    else:
        console.print(f"✅ Diff saved to: {output_path}")


def display_validation_result(console: Console, panel) -> None:
    console.print(panel)


def display_info(console: Console, input_file: str, info_data: dict[str, Any]) -> None:
    info_table = Table(title=f"AST Information: {Path(input_file).name}")
    info_table.add_column("Component", style="cyan")
    info_table.add_column("Count", style="green", justify="right")
    info_table.add_column("Details", style="dim")

    rule_details = ", ".join(info_data["rule_samples"])
    if info_data["rule_count"] > 3:
        rule_details += "..."
    info_table.add_row("Rules", str(info_data["rule_count"]), rule_details)
    info_table.add_row(
        "Imports", str(info_data["import_count"]), ", ".join(info_data["import_list"])
    )
    info_table.add_row(
        "Includes",
        str(info_data["include_count"]),
        ", ".join(info_data["include_list"]),
    )

    console.print(info_table)

    if info_data["rule_details"]:
        rule_table = Table(title="Rule Analysis")
        rule_table.add_column("Rule", style="cyan")
        rule_table.add_column("Strings", justify="right")
        rule_table.add_column("Tags", justify="right")
        rule_table.add_column("Meta", justify="right")
        rule_table.add_column("Modifiers", style="dim")

        for rule in info_data["rule_details"]:
            rule_table.add_row(
                rule["name"],
                str(rule["strings"]),
                str(rule["tags"]),
                str(rule["meta"]),
                rule["modifiers"],
            )

        if info_data["has_more_rules"]:
            rule_table.add_row(
                "[dim]...[/dim]",
                "[dim]...[/dim]",
                "[dim]...[/dim]",
                "[dim]...[/dim]",
                "[dim]...[/dim]",
            )

        console.print(rule_table)

    console.print(f"\n[dim]AST Hash: {info_data['ast_hash']}[/dim]")
