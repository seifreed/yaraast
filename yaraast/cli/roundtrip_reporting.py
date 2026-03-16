"""Reporting helpers for roundtrip CLI output."""

from __future__ import annotations

from pathlib import Path
from typing import Any

import click


def _display_test_success(input_file: Path, result: dict[str, Any], format: str) -> None:
    """Display successful test results."""
    click.echo(f"✅ Round-trip test PASSED for {input_file}")
    click.echo(f"   Format: {format.upper()}")
    click.echo(f"   Original rules: {result['metadata']['original_rule_count']}")
    click.echo(
        f"   Reconstructed rules: {result['metadata']['reconstructed_rule_count']}",
    )


def _display_test_failure(input_file: Path, result: dict[str, Any], verbose: bool) -> None:
    """Display failed test results."""
    click.echo(f"❌ Round-trip test FAILED for {input_file}")
    click.echo(f"   Differences found: {len(result['differences'])}")

    if verbose:
        click.echo("\nDifferences:")
        for diff in result["differences"]:
            click.echo(f"   • {diff}")


def _display_verbose_source(result: dict[str, Any]) -> None:
    """Display verbose source comparison."""
    click.echo(
        f"\nOriginal source ({len(result['original_source'].splitlines())} lines):",
    )
    for i, line in enumerate(result["original_source"].splitlines()[:10], 1):
        click.echo(f"   {i:2d}: {line}")
    if len(result["original_source"].splitlines()) > 10:
        click.echo("      ... (truncated)")

    click.echo(
        f"\nReconstructed source ({len(result['reconstructed_source'].splitlines())} lines):",
    )
    for i, line in enumerate(result["reconstructed_source"].splitlines()[:10], 1):
        click.echo(f"   {i:2d}: {line}")
    if len(result["reconstructed_source"].splitlines()) > 10:
        click.echo("      ... (truncated)")


def display_serialize_result(
    output: Path | None,
    fmt: str,
    ast: Any,
    preserve_comments: bool,
    preserve_formatting: bool,
    serialized: str,
) -> None:
    """Display serialize results."""
    if output:
        click.echo(f"✅ Serialized to {output}")
        click.echo(f"   Format: {fmt.upper()}")
        click.echo(f"   Rules: {len(ast.rules)}")
        click.echo(f"   Comments preserved: {preserve_comments}")
        click.echo(f"   Formatting preserved: {preserve_formatting}")
    else:
        click.echo(serialized)


def display_deserialize_result(
    output: Path | None,
    fmt: str,
    ast: Any,
    preserve_formatting: bool,
    yara_code: str,
) -> None:
    """Display deserialize results."""
    if output:
        click.echo(f"✅ Generated YARA code to {output}")
        click.echo(f"   Rules: {len(ast.rules)}")
        click.echo(f"   Formatting preserved: {preserve_formatting}")
    else:
        click.echo(yara_code)


def display_pretty_result(
    output: Path | None,
    style: str,
    ast: Any,
    indent_size: int,
    max_line_length: int,
    formatted_code: str,
) -> None:
    """Display pretty print results."""
    if output:
        click.echo(f"✅ Pretty printed to {output}")
        click.echo(f"   Style: {style}")
        click.echo(f"   Rules: {len(ast.rules)}")
        click.echo(f"   Indent size: {indent_size}")
        click.echo(f"   Max line length: {max_line_length}")
    else:
        click.echo(formatted_code)


def display_pipeline_result(
    output: Path | None,
    yaml_content: str,
    include_manifest: bool,
    manifest_content: str | None,
    ast: Any,
) -> None:
    """Display pipeline serialization results."""
    if output:
        click.echo(f"✅ Pipeline YAML written to {output}")
    else:
        click.echo(yaml_content)

    if include_manifest:
        if output:
            click.echo(f"✅ Rules manifest written to {output.with_suffix('.manifest.yaml')}")
        else:
            click.echo("\n--- Rules Manifest ---")
            if manifest_content is not None:
                click.echo(manifest_content)

    click.echo("\nStatistics:")
    click.echo(f"   Rules: {len(ast.rules)}")
    click.echo(f"   Imports: {len(ast.imports)}")
    click.echo(f"   Includes: {len(ast.includes)}")
