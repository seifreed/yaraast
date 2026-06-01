"""YARA-X specific CLI commands."""

from __future__ import annotations

import click

from yaraast.cli.utils import _require_file_path, read_text, write_text
from yaraast.cli.yarax_reporting import (
    display_compatibility_issues,
    display_feature_showcase,
    display_playground_input,
    display_playground_results,
    display_yarax_features,
)
from yaraast.cli.yarax_services import (
    check_yarax_compatibility,
    convert_yara_to_yarax,
    convert_yarax_to_yara,
    detect_playground_features,
    detect_yarax_features,
    get_default_playground_code,
    parse_yara_file_ast,
    parse_yarax_content,
)


@click.group()
def yarax():
    """YARA-X specific operations for next-gen YARA syntax."""
    pass


def _validate_output_path(output: str | None) -> str | None:
    if output is None:
        return None
    try:
        output_path = _require_file_path(output)
    except (TypeError, ValueError) as exc:
        raise click.BadParameter(str(exc), param_hint="--output") from exc
    if output_path.exists() and output_path.is_dir():
        raise click.BadParameter("output path must not be a directory", param_hint="--output")
    return output


@yarax.command()
@click.argument("file", type=click.Path(exists=True))
@click.option("--output", "-o", type=click.Path(), help="Output AST to file")
@click.option("--show-features", is_flag=True, help="Show YARA-X features used")
def parse(file: str, output: str | None, show_features: bool):
    """Parse YARA-X file with support for new syntax features."""
    output = _validate_output_path(output)
    try:
        content = read_text(file)

        _ast, code = parse_yarax_content(content)

        if output is not None:
            write_text(output, code)
            click.echo(f"✅ AST written to {output}")
        else:
            click.echo(code)

        if show_features:
            display_yarax_features(detect_yarax_features(content))

    except Exception as e:
        click.echo(f"❌ Error parsing YARA-X file: {e}", err=True)
        raise click.Abort() from None


@yarax.command()
@click.argument("file", type=click.Path(exists=True))
@click.option("--strict", is_flag=True, help="Use strict YARA-X compatibility")
@click.option("--fix", is_flag=True, help="Suggest fixes for compatibility issues")
def check(file: str, strict: bool, fix: bool):
    """Check YARA file for YARA-X compatibility."""
    try:
        # Parse file
        ast = parse_yara_file_ast(file)

        # Check compatibility
        issues = check_yarax_compatibility(ast, strict)

        if not issues:
            click.echo("✅ File is fully compatible with YARA-X")
        else:
            display_compatibility_issues(issues, fix)

    except Exception as e:
        click.echo(f"❌ Error checking YARA-X compatibility: {e}", err=True)
        raise click.Abort() from None


@yarax.command()
@click.argument("file", type=click.Path(exists=True))
@click.option("--output", "-o", type=click.Path(), help="Output converted file")
@click.option(
    "--target",
    type=click.Choice(["yarax", "yara"]),
    default="yarax",
    help="Target format",
)
def convert(file: str, output: str | None, target: str):
    """Convert between YARA and YARA-X formats."""
    output = _validate_output_path(output)
    try:
        content = read_text(file)

        if target == "yarax":
            # Convert YARA to YARA-X (add modern features where possible)
            converted = convert_yara_to_yarax(content)

            click.echo("✅ Converted to YARA-X format")
        else:
            # Convert YARA-X to standard YARA (remove new features)
            converted = convert_yarax_to_yara(content)

            click.echo("⚠️  Converted to standard YARA (some features may be lost)")

        if output is not None:
            write_text(output, converted)
            click.echo(f"✅ Converted file written to {output}")
        else:
            click.echo(converted)

    except Exception as e:
        click.echo(f"❌ Error converting file: {e}", err=True)
        raise click.Abort() from None


@yarax.command()
def features():
    """Show YARA-X feature support and examples."""
    display_feature_showcase()


@yarax.command()
@click.argument("code", required=False)
@click.option("--file", "-f", type=click.Path(exists=True), help="Read code from file")
def playground(code: str | None, file: str | None):
    """Interactive playground for testing YARA-X features."""
    used_default = False
    if file:
        code = read_text(file)
    elif not code:
        code = get_default_playground_code()
        used_default = True

    display_playground_input(code, used_default)

    try:
        # Parse with YARA-X parser
        _ast, generated = parse_yarax_content(code)

        features = detect_playground_features(code)
        display_playground_results(generated, features)

    except Exception as e:
        click.echo(f"❌ Parse error: {e}", err=True)
