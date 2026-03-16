"""Workspace CLI services (logic without IO)."""

from __future__ import annotations

from typing import Any

from yaraast.cli.utils import format_json
from yaraast.resolution.workspace import Workspace


def analyze_workspace(
    directory: str,
    pattern: str,
    recursive: bool,
    parallel: bool,
) -> tuple[Workspace, Any]:
    ws = Workspace(root_path=directory)
    ws.add_directory(directory, pattern=pattern, recursive=recursive)
    report = ws.analyze(parallel=parallel)
    return ws, report


def format_workspace_report_json(report: Any) -> str:
    output_data = {
        "statistics": report.statistics,
        "files": {
            path: {
                "errors": result.errors,
                "warnings": result.warnings,
                "type_errors": result.type_errors,
                "analysis": result.analysis_results,
            }
            for path, result in report.file_results.items()
        },
        "global_errors": report.global_errors,
    }
    return format_json(output_data)


def format_workspace_report_text(report: Any) -> str:
    lines: list[str] = []
    lines.append("Workspace Analysis Report")
    lines.append("=" * 50)
    lines.append(f"Files analyzed: {report.files_analyzed}")
    lines.append(f"Total rules: {report.total_rules}")
    lines.append(f"Total includes: {report.total_includes}")
    lines.append(f"Total imports: {report.total_imports}")
    lines.append("")

    if report.global_errors:
        lines.append("Global Errors:")
        for error in report.global_errors:
            lines.append(f"  - {error}")
        lines.append("")

    for file_path, result in report.file_results.items():
        if result.errors or result.warnings or result.type_errors:
            lines.extend(_format_file_issues(file_path, result))

    lines.append("Statistics:")
    lines.append(f"  Total errors: {report.statistics.get('total_errors', 0)}")
    lines.append(f"  Total warnings: {report.statistics.get('total_warnings', 0)}")
    lines.append(
        f"  Total type errors: {report.statistics.get('total_type_errors', 0)}",
    )
    lines.append(f"  Dependency cycles: {report.statistics.get('cycles', 0)}")
    lines.append(
        f"  Rule name conflicts: {report.statistics.get('rule_name_conflicts', 0)}",
    )

    return "\n".join(lines)


def _format_file_issues(file_path: str, result: Any) -> list[str]:
    lines: list[str] = [f"File: {file_path}"]

    if result.errors:
        lines.append("  Errors:")
        for error in result.errors:
            lines.append(f"    - {error}")

    if result.warnings:
        lines.append("  Warnings:")
        for warning in result.warnings:
            lines.append(f"    - {warning}")

    if result.type_errors:
        lines.append("  Type Errors:")
        for error in result.type_errors:
            lines.append(f"    - {error}")

    lines.append("")
    return lines


def format_workspace_graph(report: Any, fmt: str) -> str:
    if fmt == "dot":
        return report.dependency_graph.export_dot()

    nodes = {}
    for key, node in report.dependency_graph.nodes.items():
        nodes[key] = {
            "type": node.type,
            "dependencies": list(node.dependencies),
            "dependents": list(node.dependents),
            "metadata": node.metadata,
        }
    return format_json({"nodes": nodes})


def format_workspace_output(report: Any, fmt: str) -> str:
    """Format workspace report for a given output format."""
    if fmt == "json":
        return format_workspace_report_json(report)
    if fmt == "dot":
        return format_workspace_graph(report, "dot")
    return format_workspace_report_text(report)
