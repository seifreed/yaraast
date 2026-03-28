"""Complexity-specific reporting helpers for CLI metrics."""

from __future__ import annotations

from pathlib import Path

import click

from yaraast.cli.metrics_services import build_complexity_payload
from yaraast.cli.utils import format_json
from yaraast.metrics.complexity_model import ComplexityMetrics


def format_complexity_text(metrics: ComplexityMetrics) -> str:
    lines: list[str] = []
    lines.extend(_format_overview_section(metrics))
    lines.extend(_format_rules_section(metrics))
    lines.extend(_format_quality_section(metrics))
    return "\n".join(lines)


def _format_overview_section(metrics: ComplexityMetrics) -> list[str]:
    """Format the overview table with file, rule, string, condition, and pattern metrics."""
    return [
        "YARA Rule Complexity Analysis",
        "=" * 35,
        "",
        f"📊 Overall Quality Score: {metrics.get_quality_score():.1f}/100 (Grade: {metrics.get_complexity_grade()})",
        "",
        "📁 File Metrics:",
        f"  Total Rules: {metrics.total_rules}",
        f"  Total Imports: {metrics.total_imports}",
        f"  Total Includes: {metrics.total_includes}",
        "",
        "📋 Rule Metrics:",
        f"  Rules with strings: {metrics.rules_with_strings}",
        f"  Rules with meta: {metrics.rules_with_meta}",
        f"  Rules with tags: {metrics.rules_with_tags}",
        f"  Private rules: {metrics.private_rules}",
        f"  Global rules: {metrics.global_rules}",
        "",
        "🧵 String Metrics:",
        f"  Total strings: {metrics.total_strings}",
        f"  Plain strings: {metrics.plain_strings}",
        f"  Hex strings: {metrics.hex_strings}",
        f"  Regex strings: {metrics.regex_strings}",
        f"  Strings with modifiers: {metrics.strings_with_modifiers}",
        "",
        "🔄 Condition Complexity:",
        f"  Max condition depth: {metrics.max_condition_depth}",
        f"  Avg condition depth: {metrics.avg_condition_depth:.2f}",
        f"  Binary operations: {metrics.total_binary_ops}",
        f"  Unary operations: {metrics.total_unary_ops}",
        f"  For expressions: {metrics.for_expressions}",
        f"  For-of expressions: {metrics.for_of_expressions}",
        f"  Of expressions: {metrics.of_expressions}",
        "",
        "🎯 Pattern Complexity:",
        f"  Hex wildcards: {metrics.hex_wildcards}",
        f"  Hex jumps: {metrics.hex_jumps}",
        f"  Hex alternatives: {metrics.hex_alternatives}",
        f"  Regex groups: {metrics.regex_groups}",
        f"  Regex quantifiers: {metrics.regex_quantifiers}",
        "",
    ]


def _format_rules_section(metrics: ComplexityMetrics) -> list[str]:
    """Format per-rule details: cyclomatic complexity, complex rules, unused strings."""
    lines: list[str] = []
    if metrics.cyclomatic_complexity:
        lines.extend(
            [
                "🧮 Cyclomatic Complexity by Rule:",
                *[f"  {r}: {c}" for r, c in metrics.cyclomatic_complexity.items()],
                "",
            ]
        )
    if metrics.complex_rules:
        lines.extend(
            [
                "⚠️  Rules Exceeding Heuristic Complexity Thresholds:",
                *[f"  - {r}" for r in metrics.complex_rules],
                "",
            ]
        )
    if metrics.unused_strings:
        lines.extend(
            [
                "🔍 Unused Strings:",
                *[f"  - {string_ref}" for string_ref in metrics.unused_strings[:10]],
                (
                    ""
                    if len(metrics.unused_strings) <= 10
                    else f"  ... and {len(metrics.unused_strings) - 10} more"
                ),
                "",
            ],
        )
    return lines


def _format_quality_section(metrics: ComplexityMetrics) -> list[str]:
    """Format the quality score section with module usage."""
    lines: list[str] = []
    if metrics.module_usage:
        lines.extend(
            [
                "📦 Module Usage:",
                *[f"  {m}: {u} times" for m, u in metrics.module_usage.items()],
                "",
            ]
        )
    return lines


def format_complexity_output(metrics: ComplexityMetrics, fmt: str) -> str:
    return (
        format_json(build_complexity_payload(metrics))
        if fmt == "json"
        else format_complexity_text(metrics)
    )


def complexity_quality_message(quality_score: float, quality_gate: int) -> tuple[str, bool]:
    if quality_score < quality_gate:
        return f"\n⚠️  Quality gate warning: {quality_score:.1f} < {quality_gate}", False
    return f"\n✅ Quality gate passed: {quality_score:.1f} >= {quality_gate}", True


def emit_text_output(text: str, output: str | None, success_message: str) -> None:
    if output:
        Path(output).write_text(text, encoding="utf-8")
        click.echo(f"{success_message} {output}")
    else:
        click.echo(text)
