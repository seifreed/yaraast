"""Reporting helpers for serialize CLI output."""

from __future__ import annotations

from os import PathLike, fspath
from pathlib import Path
from typing import Any

from rich.console import Console
from rich.markup import escape
from rich.syntax import Syntax
from rich.table import Table

from yaraast.cli.utils import _path_exists_and_is_dir, format_json, write_text

_DIFF_OUTPUT_FORMATS = frozenset({"json", "yaml"})


def _has_output_path(output: object, name: str = "output") -> bool:
    if output is None:
        return False
    if isinstance(output, bool) or not isinstance(output, str | PathLike):
        msg = f"{name} path must be a file path"
        raise TypeError(msg)
    raw_path = fspath(output)
    if not isinstance(raw_path, str):
        msg = f"{name} path must be a file path"
        raise TypeError(msg)
    if not raw_path.strip():
        msg = f"{name} path must not be empty"
        raise ValueError(msg)
    output_path = Path(raw_path)
    if _path_exists_and_is_dir(output_path):
        msg = f"{name} path must not be a directory"
        raise ValueError(msg)
    return True


def display_export_result(
    console: Console,
    result: str | None,
    fmt: str,
    output: str | None,
    pretty: bool,
    stats: dict | None,
) -> None:
    has_output = _has_output_path(output)
    if pretty and result and not has_output:
        syntax = Syntax(result, fmt, theme="monokai", line_numbers=True)
        console.print(syntax)
    if stats:
        from yaraast.cli.serialize_display_services import _display_protobuf_stats

        _display_protobuf_stats(stats)

    if has_output:
        console.print(f"✅ AST exported to {escape(str(output))} ({escape(fmt)} format)")
    elif not pretty:
        console.print("✅ AST serialized successfully")


def display_import_result(
    console: Console, input_file: str, fmt: str, ast: Any, output: str | None
) -> None:
    console.print(f"✅ AST imported from {escape(input_file)} ({escape(fmt)} format)")
    console.print(f"📊 Rules: {len(ast.rules)}, Imports: {len(ast.imports)}")
    if _has_output_path(output):
        console.print(f"✅ YARA code written to {escape(str(output))}")


def display_diff_no_changes(console: Console) -> None:
    console.print("✅ No differences found - ASTs are identical")


def _require_diff_output_format(fmt: object) -> str:
    if not isinstance(fmt, str):
        raise TypeError("diff output format must be a string")
    if fmt not in _DIFF_OUTPUT_FORMATS:
        valid = ", ".join(sorted(_DIFF_OUTPUT_FORMATS))
        raise ValueError(f"diff output format must be one of: {valid}")
    return fmt


def write_diff_output(output_path: str, fmt: object, diff_data: dict) -> None:
    fmt = _require_diff_output_format(fmt)
    if fmt == "json":
        write_text(output_path, format_json(diff_data, ensure_ascii=False))
        return

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
        console.print(f"✅ Patch file created: {escape(output_path)}")
    else:
        console.print(f"✅ Diff saved to: {escape(output_path)}")


def display_validation_result(console: Console, panel) -> None:
    console.print(panel)


def display_info(console: Console, input_file: str, info_data: dict[str, Any]) -> None:
    info_table = Table(title=f"AST Information: {escape(Path(input_file).name)}")
    info_table.add_column("Component", style="cyan")
    info_table.add_column("Count", style="green", justify="right")
    info_table.add_column("Details", style="dim")

    rule_details = ", ".join(escape(str(rule)) for rule in info_data["rule_samples"])
    if info_data["rule_count"] > 3:
        rule_details += "..."
    info_table.add_row("Rules", str(info_data["rule_count"]), rule_details)
    info_table.add_row(
        "Imports",
        str(info_data["import_count"]),
        ", ".join(escape(str(item)) for item in info_data["import_list"]),
    )
    info_table.add_row(
        "Includes",
        str(info_data["include_count"]),
        ", ".join(escape(str(item)) for item in info_data["include_list"]),
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
                escape(str(rule["name"])),
                str(rule["strings"]),
                str(rule["tags"]),
                str(rule["meta"]),
                escape(str(rule["modifiers"])),
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

    console.print(f"\n[dim]AST Hash: {escape(str(info_data['ast_hash']))}[/dim]")
