"""Round-trip serialization and pretty printing CLI commands."""

from __future__ import annotations

from pathlib import Path
import sys

import click

from yaraast.cli.roundtrip_reporting import (
    _display_test_failure,
    _display_test_success,
    _display_verbose_source,
    display_deserialize_result,
    display_pipeline_result,
    display_pretty_result,
    display_serialize_result,
)
from yaraast.cli.roundtrip_services import (
    deserialize_roundtrip_file,
    pipeline_serialize_file,
    pretty_print_file,
    serialize_roundtrip_file,
    test_roundtrip_file,
)
from yaraast.cli.utils import _resolve_output_path, format_json, write_text
from yaraast.serialization.roundtrip_serializer import EnhancedYamlSerializer


@click.group()
def roundtrip() -> None:
    """Round-trip serialization and pretty printing commands.

    These commands provide advanced serialization features including:
    - Round-trip YARA ↔ AST conversion with preservation
    - YAML serialization for CI/CD pipelines
    - Enhanced pretty printing with multiple styles
    - Formatting preservation and comment handling
    """


@roundtrip.command()
@click.argument("input_file", type=click.Path(exists=True, dir_okay=False, path_type=Path))
@click.option(
    "--format",
    "-f",
    type=click.Choice(["json", "yaml"]),
    default="json",
    help="Serialization format",
)
@click.option(
    "--output",
    "-o",
    type=click.Path(),
    help="Output file for serialized data",
)
@click.option(
    "--preserve-comments/--no-comments",
    default=True,
    help="Preserve comments in serialization",
)
@click.option(
    "--preserve-formatting/--no-formatting",
    default=True,
    help="Preserve original formatting information",
)
def serialize(
    input_file: Path,
    format: str,
    output: str | None,
    preserve_comments: bool,
    preserve_formatting: bool,
) -> None:
    """Serialize YARA file to JSON/YAML with round-trip metadata.

    This command parses a YARA file and serializes it with metadata
    needed for perfect round-trip conversion, preserving comments
    and formatting information.

    Examples:
        # Serialize to JSON with full preservation
        yaraast roundtrip serialize rules.yar --format json -o rules.json

        # Serialize to YAML for pipeline
        yaraast roundtrip serialize rules.yar --format yaml -o rules.yaml

        # Minimal serialization without comments
        yaraast roundtrip serialize rules.yar --no-comments

    """
    output_path = _resolve_output_path(output)
    try:
        # Read input file
        ast, serialized = serialize_roundtrip_file(
            input_file,
            format,
            preserve_comments,
            preserve_formatting,
        )

        if output_path is not None:
            write_text(output_path, serialized)
        display_serialize_result(
            output_path,
            format,
            ast,
            preserve_comments,
            preserve_formatting,
            serialized,
        )

    except Exception as e:
        click.echo(f"❌ Error serializing {input_file}: {e}", err=True)
        sys.exit(1)


@roundtrip.command()
@click.argument("input_file", type=click.Path(exists=True, dir_okay=False, path_type=Path))
@click.option(
    "--format",
    "-f",
    type=click.Choice(["json", "yaml"]),
    default="json",
    help="Input serialization format",
)
@click.option(
    "--output",
    "-o",
    type=click.Path(),
    help="Output file for generated YARA code",
)
@click.option(
    "--preserve-formatting/--default-formatting",
    default=True,
    help="Use original formatting if available",
)
def deserialize(
    input_file: Path,
    format: str,
    output: str | None,
    preserve_formatting: bool,
) -> None:
    """Deserialize JSON/YAML back to YARA code.

    This command takes serialized AST data and generates YARA code,
    optionally preserving the original formatting and comments.

    Examples:
        # Deserialize JSON back to YARA
        yaraast roundtrip deserialize rules.json -o reconstructed.yar

        # Deserialize YAML with default formatting
        yaraast roundtrip deserialize rules.yaml --default-formatting

    """
    output_path = _resolve_output_path(output)
    try:
        ast, yara_code = deserialize_roundtrip_file(
            input_file,
            format,
            preserve_formatting,
        )

        if output_path is not None:
            write_text(output_path, yara_code)
        display_deserialize_result(
            output_path,
            format,
            ast,
            preserve_formatting,
            yara_code,
        )

    except Exception as e:
        click.echo(f"❌ Error deserializing {input_file}: {e}", err=True)
        sys.exit(1)


@roundtrip.command()
@click.argument("input_file", type=click.Path(exists=True, dir_okay=False, path_type=Path))
@click.option(
    "--format",
    "-f",
    type=click.Choice(["json", "yaml"]),
    default="json",
    help="Serialization format for testing",
)
@click.option(
    "--output",
    "-o",
    type=click.Path(),
    help="Output file for test results",
)
@click.option("--verbose", "-v", is_flag=True, help="Show detailed comparison results")
def test(input_file: Path, format: str, output: str | None, verbose: bool) -> None:
    """Test round-trip conversion fidelity.

    This command performs a complete round-trip test:
    YARA → AST → Serialized → AST → YARA

    It reports any differences between the original and reconstructed
    YARA code, helping validate the preservation quality.

    Examples:
        # Test round-trip with JSON
        yaraast roundtrip test rules.yar --format json

        # Detailed test with YAML output
        yaraast roundtrip test rules.yar --format yaml --verbose -o test_results.json

    """
    output_path = _resolve_output_path(output)
    try:
        result = test_roundtrip_file(input_file, format)

        # Display results
        if result["round_trip_successful"]:
            _display_test_success(input_file, result, format)
        else:
            _display_test_failure(input_file, result, verbose)

        if verbose:
            _display_verbose_source(result)

        # Save detailed results if requested
        if output_path is not None:
            write_text(output_path, format_json(result, ensure_ascii=False))
            click.echo(f"\nDetailed results saved to {output_path}")

        # Exit with error if test failed
        if not result["round_trip_successful"]:
            sys.exit(1)

    except Exception as e:
        click.echo(f"❌ Error testing {input_file}: {e}", err=True)
        sys.exit(1)


@roundtrip.command()
@click.argument("input_file", type=click.Path(exists=True, dir_okay=False, path_type=Path))
@click.option(
    "--output",
    "-o",
    type=click.Path(),
    help="Output file for formatted YARA code",
)
@click.option(
    "--style",
    type=click.Choice(["compact", "readable", "dense", "verbose"]),
    default="readable",
    help="Pretty printing style preset",
)
@click.option("--indent-size", type=click.IntRange(min=1), default=4, help="Indentation size")
@click.option(
    "--max-line-length",
    type=click.IntRange(min=1),
    default=120,
    help="Maximum line length",
)
@click.option(
    "--align-strings/--no-align-strings",
    default=True,
    help="Align string definitions",
)
@click.option("--align-meta/--no-align-meta", default=True, help="Align meta values")
@click.option(
    "--sort-imports/--preserve-import-order",
    default=True,
    help="Sort import statements",
)
@click.option("--sort-tags/--preserve-tag-order", default=True, help="Sort rule tags")
def pretty(
    input_file: Path,
    output: str | None,
    style: str,
    indent_size: int,
    max_line_length: int,
    align_strings: bool,
    align_meta: bool,
    sort_imports: bool,
    sort_tags: bool,
) -> None:
    """Pretty print YARA file with advanced formatting.

    This command applies advanced formatting options to YARA files,
    including alignment, sorting, and various style presets.

    Examples:
        # Pretty print with readable style
        yaraast roundtrip pretty rules.yar --style readable -o formatted.yar

        # Compact formatting
        yaraast roundtrip pretty rules.yar --style compact

        # Custom formatting options
        yaraast roundtrip pretty rules.yar --indent-size 2 --max-line-length 100

    """
    output_path = _resolve_output_path(output)
    try:
        ast, formatted_code = pretty_print_file(
            input_file,
            style,
            indent_size,
            max_line_length,
            align_strings,
            align_meta,
            sort_imports,
            sort_tags,
        )

        if output_path is not None:
            write_text(output_path, formatted_code)
        display_pretty_result(
            output_path,
            style,
            ast,
            indent_size,
            max_line_length,
            formatted_code,
        )

    except Exception as e:
        click.echo(f"❌ Error pretty printing {input_file}: {e}", err=True)
        sys.exit(1)


@roundtrip.command()
@click.argument("input_file", type=click.Path(exists=True, dir_okay=False, path_type=Path))
@click.option(
    "--output",
    "-o",
    type=click.Path(),
    help="Output file for pipeline YAML",
)
@click.option("--pipeline-info", type=str, help="JSON string with pipeline information")
@click.option(
    "--include-manifest/--no-manifest",
    default=False,
    help="Generate rules manifest alongside serialization",
)
def pipeline(
    input_file: Path,
    output: str | None,
    pipeline_info: str | None,
    include_manifest: bool,
) -> None:
    """Serialize YARA file for CI/CD pipeline use.

    This command creates a YAML serialization optimized for CI/CD
    pipelines, including metadata for automated processing.

    Examples:
        # Basic pipeline serialization
        yaraast roundtrip pipeline rules.yar -o pipeline.yaml

        # With pipeline metadata
        yaraast roundtrip pipeline rules.yar --pipeline-info '{"branch":"main","commit":"abc123"}'

        # Include rules manifest
        yaraast roundtrip pipeline rules.yar --include-manifest

    """
    output_path = _resolve_output_path(output)
    try:
        ast, yaml_content, _pipeline_data = pipeline_serialize_file(
            input_file,
            pipeline_info,
        )

        if output_path is not None:
            write_text(output_path, yaml_content)

        manifest_content = None
        if include_manifest:
            manifest_content = EnhancedYamlSerializer().serialize_rules_manifest(ast)
            manifest_path = (
                output_path.with_suffix(".manifest.yaml") if output_path is not None else None
            )

            if manifest_path is not None:
                write_text(manifest_path, manifest_content)
        display_pipeline_result(
            output_path,
            yaml_content,
            include_manifest,
            manifest_content,
            ast,
        )

    except Exception as e:
        click.echo(f"❌ Error creating pipeline YAML for {input_file}: {e}", err=True)
        sys.exit(1)


if __name__ == "__main__":
    roundtrip()
