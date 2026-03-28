"""Command-level helpers for serialize CLI (no IO)."""

from __future__ import annotations

from pathlib import Path
from typing import Any

from yaraast.cli.serialize_display_services import (
    _display_detailed_changes,
    _display_diff_statistics,
    _display_diff_summary,
    build_validation_panel,
)
from yaraast.cli.serialize_services import (
    build_ast_info,
    compare_yara_files,
    export_ast,
    import_ast as import_ast_service,
    parse_yara_file,
    validate_serialized,
)


def export_serialized(
    input_file: str,
    format: str,
    output: str | None,
    minimal: bool,
) -> tuple[Any, Any]:
    ast = parse_yara_file(input_file)
    result, stats = export_ast(ast, format, output, minimal)
    return result, stats


def import_serialized(input_file: str, format: str) -> Any:
    return import_ast_service(input_file, format)


def diff_serialized(
    old_file: str,
    new_file: str,
    stats: bool,
) -> tuple[Any, Any, str | None]:
    differ, diff_result = compare_yara_files(old_file, new_file)

    if not diff_result.has_changes:
        return differ, diff_result, None

    _display_diff_summary(diff_result)
    _display_detailed_changes(diff_result)

    if stats:
        _display_diff_statistics(diff_result)

    return differ, diff_result, None


def build_diff_output_path(old_file: str, new_file: str, output: str | None, format: str) -> str:
    return output or f"diff_{Path(old_file).stem}_to_{Path(new_file).stem}.{format}"


def validate_serialized_input(input_file: str, format: str) -> tuple[Any, Any]:
    ast = validate_serialized(input_file, format)
    panel = build_validation_panel(Path(input_file).name, format, ast, None)
    return ast, panel


def validate_serialized_error(input_file: str, format: str, error: Exception) -> Any:
    return build_validation_panel(Path(input_file).name, format, None, error)


def build_ast_info_payload(input_file: str) -> Any:
    ast = parse_yara_file(input_file)
    return build_ast_info(ast)
