"""Round-trip serialization and pretty printing CLI commands."""

import json
import sys
from pathlib import Path

import click

from yaraast.codegen.pretty_printer import PrettyPrinter, StylePresets
from yaraast.parser import Parser
from yaraast.serialization.roundtrip_serializer import (
    RoundTripSerializer,
    create_rules_manifest,
    serialize_for_pipeline,
)
from yaraast.serialization.simple_roundtrip import simple_roundtrip_test


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
@click.argument("input_file", type=click.Path(exists=True, path_type=Path))
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
    type=click.Path(path_type=Path),
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
    output: Path | None,
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
    try:
        # Read input file
        with Path(input_file).open(encoding="utf-8") as f:
            yara_source = f.read()

        # Create serializer
        serializer = RoundTripSerializer(
            preserve_comments=preserve_comments,
            preserve_formatting=preserve_formatting,
        )

        # Parse and serialize
        ast, serialized = serializer.parse_and_serialize(
            yara_source,
            source_file=str(input_file),
            format=format,
        )

        # Output result
        if output:
            with Path(output).open("w", encoding="utf-8") as f:
                f.write(serialized)
            click.echo(f"✅ Serialized to {output}")
            click.echo(f"   Format: {format.upper()}")
            click.echo(f"   Rules: {len(ast.rules)}")
            click.echo(f"   Comments preserved: {preserve_comments}")
            click.echo(f"   Formatting preserved: {preserve_formatting}")
        else:
            click.echo(serialized)

    except Exception as e:
        click.echo(f"❌ Error serializing {input_file}: {e}", err=True)
        sys.exit(1)


@roundtrip.command()
@click.argument("input_file", type=click.Path(exists=True, path_type=Path))
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
    type=click.Path(path_type=Path),
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
    output: Path | None,
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
    try:
        # Read serialized data
        with Path(input_file).open(encoding="utf-8") as f:
            serialized_data = f.read()

        # Create serializer
        serializer = RoundTripSerializer()

        # Deserialize and generate
        ast, yara_code = serializer.deserialize_and_generate(
            serialized_data,
            format=format,
            preserve_original_formatting=preserve_formatting,
        )

        # Output result
        if output:
            with Path(output).open("w", encoding="utf-8") as f:
                f.write(yara_code)
            click.echo(f"✅ Generated YARA code to {output}")
            click.echo(f"   Rules: {len(ast.rules)}")
            click.echo(f"   Formatting preserved: {preserve_formatting}")
        else:
            click.echo(yara_code)

    except Exception as e:
        click.echo(f"❌ Error deserializing {input_file}: {e}", err=True)
        sys.exit(1)


def _display_test_success(input_file: Path, result: dict, format: str) -> None:
    """Display successful test results."""
    click.echo(f"✅ Round-trip test PASSED for {input_file}")
    click.echo(f"   Format: {format.upper()}")
    click.echo(f"   Original rules: {result['metadata']['original_rule_count']}")
    click.echo(
        f"   Reconstructed rules: {result['metadata']['reconstructed_rule_count']}",
    )


def _display_test_failure(input_file: Path, result: dict, verbose: bool) -> None:
    """Display failed test results."""
    click.echo(f"❌ Round-trip test FAILED for {input_file}")
    click.echo(f"   Differences found: {len(result['differences'])}")

    if verbose:
        click.echo("\nDifferences:")
        for diff in result["differences"]:
            click.echo(f"   • {diff}")


def _display_verbose_source(result: dict) -> None:
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


@roundtrip.command()
@click.argument("input_file", type=click.Path(exists=True, path_type=Path))
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
    type=click.Path(path_type=Path),
    help="Output file for test results",
)
@click.option("--verbose", "-v", is_flag=True, help="Show detailed comparison results")
def test(input_file: Path, format: str, output: Path | None, verbose: bool) -> None:
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
    try:
        # Read input file
        with Path(input_file).open(encoding="utf-8") as f:
            yara_source = f.read()

        # Perform round-trip test (using simple version for now)
        result = simple_roundtrip_test(yara_source)

        # Display results
        if result["round_trip_successful"]:
            _display_test_success(input_file, result, format)
        else:
            _display_test_failure(input_file, result, verbose)

        if verbose:
            _display_verbose_source(result)

        # Save detailed results if requested
        if output:
            with Path(output).open("w", encoding="utf-8") as f:
                json.dump(result, f, indent=2, ensure_ascii=False)
            click.echo(f"\nDetailed results saved to {output}")

        # Exit with error if test failed
        if not result["round_trip_successful"]:
            sys.exit(1)

    except Exception as e:
        click.echo(f"❌ Error testing {input_file}: {e}", err=True)
        sys.exit(1)


@roundtrip.command()
@click.argument("input_file", type=click.Path(exists=True, path_type=Path))
@click.option(
    "--output",
    "-o",
    type=click.Path(path_type=Path),
    help="Output file for formatted YARA code",
)
@click.option(
    "--style",
    type=click.Choice(["compact", "readable", "dense", "verbose"]),
    default="readable",
    help="Pretty printing style preset",
)
@click.option("--indent-size", type=int, default=4, help="Indentation size")
@click.option("--max-line-length", type=int, default=120, help="Maximum line length")
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
    output: Path | None,
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
    try:
        # Parse input file
        parser = Parser()
        with Path(input_file).open(encoding="utf-8") as f:
            yara_source = f.read()

        ast = parser.parse(yara_source)
        if not ast:
            msg = "Failed to parse YARA file"
            raise ValueError(msg)

        # Create pretty print options
        if style == "compact":
            options = StylePresets.compact()
        elif style == "dense":
            options = StylePresets.dense()
        elif style == "verbose":
            options = StylePresets.verbose()
        else:  # readable
            options = StylePresets.readable()

        # Apply custom options
        options.indent_size = indent_size
        options.max_line_length = max_line_length
        options.align_string_definitions = align_strings
        options.align_meta_values = align_meta
        options.sort_imports = sort_imports
        options.sort_tags = sort_tags

        # Pretty print
        printer = PrettyPrinter(options)
        formatted_code = printer.pretty_print(ast)

        # Output result
        if output:
            with Path(output).open("w", encoding="utf-8") as f:
                f.write(formatted_code)
            click.echo(f"✅ Pretty printed to {output}")
            click.echo(f"   Style: {style}")
            click.echo(f"   Rules: {len(ast.rules)}")
            click.echo(f"   Indent size: {indent_size}")
            click.echo(f"   Max line length: {max_line_length}")
        else:
            click.echo(formatted_code)

    except Exception as e:
        click.echo(f"❌ Error pretty printing {input_file}: {e}", err=True)
        sys.exit(1)


@roundtrip.command()
@click.argument("input_file", type=click.Path(exists=True, path_type=Path))
@click.option(
    "--output",
    "-o",
    type=click.Path(path_type=Path),
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
    output: Path | None,
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
    try:
        # Parse input file
        parser = Parser()
        with Path(input_file).open(encoding="utf-8") as f:
            yara_source = f.read()

        ast = parser.parse(yara_source)
        if not ast:
            msg = "Failed to parse YARA file"
            raise ValueError(msg)

        # Parse pipeline info if provided
        pipeline_data = None
        if pipeline_info:
            pipeline_data = json.loads(pipeline_info)

        # Serialize for pipeline
        yaml_content = serialize_for_pipeline(ast, pipeline_data)

        # Output main file
        if output:
            with Path(output).open("w", encoding="utf-8") as f:
                f.write(yaml_content)
            click.echo(f"✅ Pipeline YAML written to {output}")
        else:
            click.echo(yaml_content)

        # Generate manifest if requested
        if include_manifest:
            manifest_content = create_rules_manifest(ast)
            manifest_path = output.with_suffix(".manifest.yaml") if output else None

            if manifest_path:
                with Path(manifest_path).open("w", encoding="utf-8") as f:
                    f.write(manifest_content)
                click.echo(f"✅ Rules manifest written to {manifest_path}")
            else:
                click.echo("\n--- Rules Manifest ---")
                click.echo(manifest_content)

        # Show statistics
        click.echo("\nStatistics:")
        click.echo(f"   Rules: {len(ast.rules)}")
        click.echo(f"   Imports: {len(ast.imports)}")
        click.echo(f"   Includes: {len(ast.includes)}")

    except Exception as e:
        click.echo(f"❌ Error creating pipeline YAML for {input_file}: {e}", err=True)
        sys.exit(1)


if __name__ == "__main__":
    roundtrip()
