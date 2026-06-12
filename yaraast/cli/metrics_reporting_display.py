"""Display-oriented helpers for CLI metrics reporting."""

from __future__ import annotations

from pathlib import Path
from typing import Any

import click

from yaraast.ast.base import YaraFile


def path_exists_for_display(path: str) -> bool:
    try:
        return Path(path).exists()
    except OSError:
        return False


def path_size_for_display(path: str) -> int | None:
    try:
        return Path(path).stat().st_size if path_exists_for_display(path) else None
    except OSError:
        return None


def graphviz_fallback_message(output_kind: str) -> str:
    return f"⚠️ Graphviz not installed. Generating {output_kind} instead...\n"


def display_graphviz_installation_instructions() -> None:
    click.echo("\n💡 To generate visual diagrams, install Graphviz:")
    click.echo("  macOS: brew install graphviz")
    click.echo("  Ubuntu: apt-get install graphviz")
    click.echo("  Windows: https://graphviz.org/download/")


def display_graphviz_installation_help() -> None:
    display_graphviz_installation_instructions()


def display_graph_statistics(generator: Any) -> None:
    stats = generator.get_dependency_stats()
    click.echo("\n📊 Graph Statistics:")
    click.echo(f"  Rules: {stats['total_rules']}")
    click.echo(f"  Imports: {stats['total_imports']}")
    click.echo(f"  Rules with strings: {stats['rules_with_strings']}")
    click.echo(f"  Rules using modules: {stats['rules_using_modules']}")


def display_successful_graph_result(result_path: str, generator: Any) -> None:
    if isinstance(result_path, str) and path_exists_for_display(result_path):
        click.echo(f"Dependency graph generated: {result_path}")
        if generator is not None:
            display_graph_statistics(generator)


def display_text_statistics(yara_file: str, stats: dict[str, Any]) -> None:
    click.echo("📊 Dependency Analysis (Text Mode):")
    click.echo("=" * 50)
    click.echo(f"\n📁 File: {yara_file}")
    click.echo(f"  Total Rules: {stats['total_rules']}")
    click.echo(f"  Total Imports: {stats['total_imports']}")
    click.echo(f"  Rules with strings: {stats['rules_with_strings']}")
    click.echo(f"  Rules using modules: {stats['rules_using_modules']}")


def display_rule_dependencies(generator: Any) -> None:
    if generator.dependencies:
        click.echo("\n🔗 Rule Dependencies:")
        for rule, deps in sorted(generator.dependencies.items()):
            if deps:
                click.echo(f"  {rule} → {', '.join(sorted(deps))}")


def display_module_usage(generator: Any) -> None:
    if generator.module_references:
        click.echo("\n📦 Module Usage:")
        for rule, modules in sorted(generator.module_references.items()):
            if modules:
                click.echo(f"  {rule} uses: {', '.join(sorted(modules))}")


def display_text_fallback(
    yara_file: str, ast: YaraFile, generator: Any
) -> None:  # generator typing: protocol-compatible
    click.echo(graphviz_fallback_message("text representation"))
    generator.visit(ast)
    stats = generator.get_dependency_stats()
    display_text_statistics(yara_file, stats)
    display_rule_dependencies(generator)
    display_module_usage(generator)
    display_graphviz_installation_help()
