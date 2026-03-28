"""Reporting helpers for CLI metrics output."""

from __future__ import annotations

from pathlib import Path
from typing import Any

import click

from yaraast.ast.base import YaraFile
from yaraast.ast.strings import HexString, PlainString, RegexString
from yaraast.cli.metrics_reporting_complexity import (
    complexity_quality_message,
    emit_text_output as _emit_text_output,
    format_complexity_output as _format_complexity_output,
    format_complexity_text as _format_complexity_text,
)
from yaraast.cli.metrics_reporting_display import (
    display_graph_statistics as _display_graph_statistics,
    display_graphviz_installation_help as _display_graphviz_installation_help,
    display_graphviz_installation_instructions as _display_graphviz_installation_instructions,
    display_module_usage as _display_module_usage,
    display_rule_dependencies as _display_rule_dependencies,
    display_successful_graph_result as _display_successful_graph_result,
    display_text_fallback as _display_text_fallback,
    display_text_statistics as _display_text_statistics,
    graphviz_fallback_message as _graphviz_fallback_message,
)
from yaraast.cli.metrics_services import MetricsReportData
from yaraast.cli.utils import format_json

StringDef = PlainString | HexString | RegexString

__all__ = [
    "_display_graph_statistics",
    "_display_graphviz_installation_help",
    "_display_module_usage",
    "_display_pattern_result",
    "_display_pattern_statistics",
    "_display_rule_dependencies",
    "_display_successful_graph_result",
    "_display_text_fallback",
    "_display_text_pattern_analysis",
    "_display_text_statistics",
    "_emit_text_output",
    "_format_complexity_output",
    "_format_complexity_text",
    "_format_string_analysis_output",
    "_format_strings_text",
    "_get_text_graph",
    "_graphviz_fallback_message",
    "_output_string_analysis_results",
    "build_report_summary",
    "complexity_quality_message",
    "display_report_completion",
    "write_complexity_report_files",
    "write_report_summary",
]


def _display_pattern_result(result_path: str) -> None:
    """Display the result of pattern generation."""
    if isinstance(result_path, str) and Path(result_path).exists():
        click.echo(f"Pattern diagram generated: {result_path}")
    else:
        click.echo("Diagram source:")
        click.echo(result_path)


def _display_plain_string(string_def: StringDef) -> None:
    """Display plain string information."""
    value_str = string_def.value
    display_value = f'"{value_str[:30]}..."' if len(str(value_str)) > 30 else f'"{value_str}"'
    click.echo(f"  📝 {string_def.identifier}: {display_value}")


def _display_hex_string(string_def: StringDef) -> None:
    """Display hex string information."""
    token_count = len(string_def.tokens)
    click.echo(f"  🔢 {string_def.identifier}: HEX pattern ({token_count} tokens)")


def _display_regex_string(string_def: StringDef) -> None:
    """Display regex string information."""
    click.echo(f"  🔍 {string_def.identifier}: /{string_def.regex}/")


def _display_pattern_summary(counts: dict[str, int]) -> None:
    """Display pattern count summary."""
    total = counts["plain"] + counts["hex"] + counts["regex"]
    click.echo("\n📈 Summary:")
    click.echo(f"  Total strings: {total}")
    click.echo(f"  Plain strings: {counts['plain']}")
    click.echo(f"  Hex patterns: {counts['hex']}")
    click.echo(f"  Regex patterns: {counts['regex']}")


def _analyze_pattern_counts(ast: YaraFile) -> dict[str, int]:
    """Analyze and display pattern counts by type."""
    counts = {"plain": 0, "hex": 0, "regex": 0}

    for rule in ast.rules:
        if rule.strings:
            click.echo(f"\n📁 Rule: {rule.name}")
            for string_def in rule.strings:
                if hasattr(string_def, "value"):
                    counts["plain"] += 1
                    _display_plain_string(string_def)
                elif hasattr(string_def, "tokens"):
                    counts["hex"] += 1
                    _display_hex_string(string_def)
                elif hasattr(string_def, "regex"):
                    counts["regex"] += 1
                    _display_regex_string(string_def)

    return counts


def _display_text_pattern_analysis(
    generator: Any, ast: YaraFile
) -> None:  # generator typing: protocol-compatible
    """Display text-based pattern analysis when GraphViz is not available."""
    click.echo(_graphviz_fallback_message("text analysis"))

    generator._analyze_patterns(ast)
    click.echo("📊 String Pattern Analysis (Text Mode):")
    click.echo("=" * 50)

    counts = _analyze_pattern_counts(ast)
    _display_pattern_summary(counts)
    _display_graphviz_installation_instructions()


def _display_pattern_statistics(generator: Any) -> None:  # generator typing: protocol-compatible
    """Display pattern statistics if available."""
    try:
        pattern_stats = generator.get_pattern_statistics()
        if pattern_stats:
            click.echo("\n📊 Pattern Statistics:")
            click.echo(f"  Total patterns: {pattern_stats['total_patterns']}")
            click.echo(f"  By type: {pattern_stats['by_type']}")
            click.echo(f"  Complexity distribution: {pattern_stats['complexity_distribution']}")

            if pattern_stats.get("pattern_lengths"):
                lengths = pattern_stats["pattern_lengths"]
                click.echo(
                    f"  Length stats: min={lengths['min']}, max={lengths['max']}, avg={lengths['avg']:.1f}",
                )
    except (ValueError, TypeError, AttributeError):
        pass


def _format_string_analysis_output(analysis: dict[str, Any], format: str) -> str:
    """Format analysis results for output."""
    if format == "json":
        return format_json(analysis)
    return _format_strings_text(analysis)


def _format_strings_text(analysis: dict) -> str:
    """Format string analysis results as text."""
    lines = [
        "YARA String Analysis",
        "=" * 25,
        "",
        f"Total strings: {analysis['total_strings']}",
        "",
        "Type Distribution:",
        f"  Plain: {analysis['type_distribution']['plain']}",
        f"  Hex: {analysis['type_distribution']['hex']}",
        f"  Regex: {analysis['type_distribution']['regex']}",
        "",
        "Length Statistics:",
        f"  Min: {analysis['length_stats']['min']}",
        f"  Max: {analysis['length_stats']['max']}",
        f"  Average: {analysis['length_stats']['avg']:.1f}",
        "",
    ]

    if analysis["modifiers"]:
        lines.extend(
            [
                "Modifiers:",
                *[f"  {mod}: {count}" for mod, count in analysis["modifiers"].items()],
                "",
            ],
        )

    if analysis["patterns"]["short_strings"] > 0:
        lines.append(f"Short strings (<4 chars): {analysis['patterns']['short_strings']}")

    if analysis["patterns"]["hex_patterns"] > 0:
        lines.append(f"Hex patterns: {analysis['patterns']['hex_patterns']}")

    return "\n".join(lines)


def _output_string_analysis_results(output_text: str, output: str | None) -> None:
    """Output string analysis results to file or console."""
    if output:
        Path(output).write_text(output_text, encoding="utf-8")
        click.echo(f"String analysis written to {output}")
    else:
        click.echo(output_text)


def _get_text_graph(stats: dict[str, Any], dependencies: dict[str, list[str]]) -> str:
    """Format dependency graph as text."""
    lines = [
        "Dependency Analysis",
        "=" * 19,
        "",
        f"Total rules: {stats['total_rules']}",
        f"Total imports: {stats['total_imports']}",
        f"Rules with strings: {stats['rules_with_strings']}",
        f"Rules using modules: {stats['rules_using_modules']}",
        "",
    ]

    if dependencies:
        lines.extend(
            [
                "Rule Dependencies:",
                *[f"  {rule} → {', '.join(deps)}" for rule, deps in dependencies.items() if deps],
            ],
        )

    return "\n".join(lines)


def write_complexity_report_files(
    output_path: Path,
    base_name: str,
    complexity_metrics: Any,
) -> list[str]:
    json_name = f"{base_name}_complexity.json"
    text_name = f"{base_name}_complexity.txt"

    (output_path / json_name).write_text(
        _format_complexity_output(complexity_metrics, "json"),
        encoding="utf-8",
    )
    (output_path / text_name).write_text(
        _format_complexity_output(complexity_metrics, "text"),
        encoding="utf-8",
    )

    return [json_name, text_name]


def build_report_summary(
    yara_file: str,
    report_data: MetricsReportData,
    extra_files: list[str],
) -> dict[str, Any]:
    return {
        "file": yara_file,
        "generated_files": report_data.generated_files + extra_files,
        "metrics": {
            "heuristic": True,
            "analysis_kind": "heuristic",
            "quality_score": report_data.complexity_metrics.get_quality_score(),
            "quality_grade": report_data.complexity_metrics.get_complexity_grade(),
            "total_rules": report_data.complexity_metrics.total_rules,
            "total_strings": report_data.complexity_metrics.total_strings,
            "max_condition_depth": report_data.complexity_metrics.max_condition_depth,
            "complex_rules": report_data.complexity_metrics.complex_rules,
        },
    }


def write_report_summary(output_path: Path, summary: dict[str, Any]) -> None:
    (output_path / "summary.json").write_text(
        format_json(summary),
        encoding="utf-8",
    )


def display_report_completion(
    output_path: Path,
    summary: dict[str, Any],
    complexity_metrics: Any,
) -> None:
    click.echo(f"\n✅ Comprehensive report generated in {output_path}/")
    click.echo(
        f"📊 Quality Score: {complexity_metrics.get_quality_score():.1f} "
        f"(Grade: {complexity_metrics.get_complexity_grade()})",
    )
    click.echo(f"📁 Generated {len(summary['generated_files'])} files")
