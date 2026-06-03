"""YARA-L specific CLI commands."""

from __future__ import annotations

from dataclasses import asdict, is_dataclass
from typing import Any

import click

from yaraast.cli.utils import _validate_output_path, format_json, read_text
from yaraast.cli.yaral_reporting import (
    display_generate_success,
    display_info,
    display_optimize_preview,
    display_optimize_stats,
    display_parse_mode,
    display_parse_success,
    display_semantic_compare,
    display_structural_compare,
    display_validation_results,
    write_output,
)
from yaraast.cli.yaral_services import (
    compare_semantic,
    compare_structural,
    format_yaral_code,
    generate_yaral,
    optimize_yaral,
    parse_yaral,
    parse_yaral_best_effort,
    validate_yaral,
)
from yaraast.yaral.validator import YaraLValidator


def _ast_to_serializable_data(ast: Any) -> dict[str, Any]:
    if is_dataclass(ast):
        return asdict(ast)
    return ast.__dict__


def _format_yaral_code(code: str) -> str:
    """Backward-compatible wrapper used by tests."""
    return format_yaral_code(code)


@click.group()
def yaral():
    """YARA-L specific operations."""
    pass


@yaral.command()
@click.argument("file", type=click.Path(exists=True, dir_okay=False))
@click.option("--enhanced", is_flag=True, help="Use enhanced parser with full YARA-L 2.0 support")
@click.option("--output", "-o", type=click.Path(), help="Output AST to file")
@click.option(
    "--format",
    type=click.Choice(["json", "yaml", "text"]),
    default="text",
    help="Output format",
)
def parse(file: str, enhanced: bool, output: str | None, format: str):
    """Parse YARA-L file and display AST."""
    output = _validate_output_path(output)
    try:
        content = read_text(file)
        display_parse_mode(enhanced)
        ast = parse_yaral(content, enhanced)
        ast_data = _ast_to_serializable_data(ast)

        if format == "json":
            output_str = format_json(ast_data, default=str)
        elif format == "yaml":
            import yaml

            output_str = yaml.safe_dump(
                ast_data,
                default_flow_style=False,
                allow_unicode=True,
                sort_keys=False,
            )
        else:
            output_str = str(ast)

        write_output(output, output_str, f"AST written to {output}")
        display_parse_success(len(ast.rules))

    except ImportError as e:
        if format != "yaml" or e.name != "yaml":
            raise
        click.echo(f"❌ Error parsing YARA-L file: {e}", err=True)
        raise click.Abort() from None
    except Exception as e:
        click.echo(f"❌ Error parsing YARA-L file: {e}", err=True)
        raise click.Abort() from None


@yaral.command()
@click.argument("file", type=click.Path(exists=True, dir_okay=False))
@click.option("--strict", is_flag=True, help="Treat warnings as errors")
@click.option("--json", "output_json", is_flag=True, help="Output results as JSON")
def validate(file: str, strict: bool, output_json: bool):
    """Validate YARA-L file for semantic correctness."""
    try:
        content = read_text(file)
        ast = parse_yaral(content, enhanced=False)
        errors, warnings = validate_yaral(ast)
        display_validation_results(file, ast, errors, warnings, strict, output_json)
        if errors or (strict and warnings):
            raise SystemExit(1)

    except (SystemExit, click.Abort):
        raise
    except Exception as e:
        click.echo(f"❌ Error validating YARA-L file: {e}", err=True)
        raise click.Abort() from None


@yaral.command()
@click.argument("file", type=click.Path(exists=True, dir_okay=False))
@click.option("--output", "-o", type=click.Path(), help="Output optimized YARA-L to file")
@click.option("--stats", is_flag=True, help="Show optimization statistics")
@click.option(
    "--dry-run",
    is_flag=True,
    help="Show what would be optimized without making changes",
)
def optimize(file: str, output: str | None, stats: bool, dry_run: bool):
    """Optimize YARA-L rules for better performance."""
    output = _validate_output_path(output)
    try:
        content = read_text(file)
        ast = parse_yaral(content, enhanced=False)
        optimized_ast, optimization_stats = optimize_yaral(ast)
        if dry_run:
            display_optimize_preview(optimization_stats)
            return

        optimized_code = generate_yaral(optimized_ast)
        write_output(output, optimized_code, f"✅ Optimized YARA-L written to {output}")

        if stats:
            display_optimize_stats(optimization_stats)

    except Exception as e:
        click.echo(f"❌ Error optimizing YARA-L file: {e}", err=True)
        raise click.Abort() from None


@yaral.command()
@click.argument("file", type=click.Path(exists=True, dir_okay=False))
@click.option("--output", "-o", type=click.Path(), help="Output generated YARA-L to file")
@click.option("--format", is_flag=True, help="Format the output code")
def generate(file: str, output: str | None, format: bool):
    """Generate YARA-L code from AST or transform existing rules."""
    output = _validate_output_path(output)
    try:
        content = read_text(file)
        ast = parse_yaral_best_effort(content)
        code = generate_yaral(ast)
        if format:
            code = format_yaral_code(code)
        write_output(output, code, f"✅ Generated YARA-L written to {output}")
        display_generate_success(len(ast.rules))

    except Exception as e:
        click.echo(f"❌ Error generating YARA-L code: {e}", err=True)
        raise click.Abort() from None


@yaral.command()
@click.argument("file1", type=click.Path(exists=True, dir_okay=False))
@click.argument("file2", type=click.Path(exists=True, dir_okay=False))
@click.option("--semantic", is_flag=True, help="Compare semantic meaning, not just syntax")
def compare(file1: str, file2: str, semantic: bool):
    """Compare two YARA-L files for differences."""
    try:
        ast1 = parse_yaral(read_text(file1), enhanced=False)
        ast2 = parse_yaral(read_text(file2), enhanced=False)
        if semantic:
            display_semantic_compare(compare_semantic(ast1, ast2))
        else:
            display_structural_compare(compare_structural(ast1, ast2))

    except Exception as e:
        click.echo(f"❌ Error comparing YARA-L files: {e}", err=True)
        raise click.Abort() from None


@yaral.command()
@click.option("--examples", is_flag=True, help="Show example YARA-L rules")
@click.option("--fields", is_flag=True, help="Show valid UDM fields")
@click.option("--functions", is_flag=True, help="Show available aggregation functions")
def info(examples: bool, fields: bool, functions: bool):
    """Show information about YARA-L syntax and features."""
    validator = YaraLValidator()
    display_info(examples, fields, functions, validator)
