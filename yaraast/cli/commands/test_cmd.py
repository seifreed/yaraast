"""Rule fixture test command."""

from __future__ import annotations

import json
from pathlib import Path

import click

from yaraast.cli.utils import write_text
from yaraast.reporters import _xml_escape
from yaraast.rule_testing import (
    RuleTestManifest,
    RuleTestResult,
    discover_manifests,
    discover_rule_sources,
    run_manifests,
    select_changed_manifests,
)


@click.command(name="test")
@click.argument("path", type=click.Path(exists=True, path_type=Path))
@click.option("--rules", "rules_path", type=click.Path(exists=True, path_type=Path))
@click.option("--engine", "engine_names", multiple=True, help="Engine name")
@click.option(
    "--format",
    "output_format",
    type=click.Choice(["text", "json", "junit"]),
    default="text",
    show_default=True,
)
@click.option("--output", "output_path", type=click.Path(path_type=Path))
@click.option("--coverage", is_flag=True, help="Include rule coverage in text output")
@click.option("--changed-from", help="Only test changed rules and their manifests")
def test(
    path: Path,
    rules_path: Path | None,
    engine_names: tuple[str, ...],
    output_format: str,
    output_path: Path | None,
    coverage: bool,
    changed_from: str | None,
) -> None:
    """Run local positive and negative rule fixtures."""
    manifests = tuple(RuleTestManifest.load(item) for item in discover_manifests(path))
    project_root = path if path.is_dir() else path.parent
    if changed_from is not None:
        manifests = select_changed_manifests(manifests, project_root, changed_from)
    source_root = rules_path or project_root
    sources = discover_rule_sources(source_root)
    selected_engines = engine_names or ("libyara", "yara-x")
    from yaraast.conformance.engines import LibyaraEngine, YaraXEngine

    engines = tuple(
        item for item in (LibyaraEngine(), YaraXEngine()) if item.name in selected_engines
    )
    result = run_manifests(manifests, sources, engines=engines)
    if output_format == "json":
        rendered = json.dumps(result.to_dict(), indent=2, sort_keys=True) + "\n"
    elif output_format == "junit":
        rendered = _junit_output(result)
    else:
        lines = [
            f"{len(manifests)} rules tested",
            f"{len(result.passed)} fixtures passed",
            f"{len(result.failed)} fixtures failed",
            f"{len(result.skipped)} fixtures skipped",
        ]
        if coverage:
            stats = result.coverage()
            lines.extend(
                [
                    f"Positive coverage: {stats['positive']}/{stats['rules']}",
                    f"Negative coverage: {stats['negative']}/{stats['rules']}",
                ]
            )
        rendered = "\n".join(lines) + "\n"
    if output_path is None:
        click.echo(rendered, nl=False)
    else:
        write_text(output_path, rendered)
    if result.failed:
        raise click.exceptions.Exit(1)


def _junit_output(result: RuleTestResult) -> str:
    parts = [
        "<testsuite",
        ' name="yaraast"',
        f' tests="{len(result.fixtures)}"',
        f' failures="{len(result.failed)}"',
        f' skipped="{len(result.skipped)}">',
    ]
    for fixture in result.fixtures:
        parts.extend(
            (
                "<testcase",
                f' classname="{_xml_escape(fixture.engine, attribute=True)}"',
                f' name="{_xml_escape(f"{fixture.kind}:{fixture.path}", attribute=True)}">',
            )
        )
        if fixture.skipped:
            parts.append("<skipped />")
        elif not fixture.passed:
            message = fixture.error or "mismatch"
            text = fixture.error or "fixture did not match expected rules"
            parts.append(
                f'<failure message="{_xml_escape(message, attribute=True)}">{_xml_escape(text)}</failure>'
            )
        parts.append("</testcase>")
    parts.append("</testsuite>\n")
    return "".join(parts)
