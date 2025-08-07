"""YARA-L specific CLI commands."""

from pathlib import Path

import click

from yaraast.yaral.enhanced_parser import EnhancedYaraLParser
from yaraast.yaral.generator import YaraLGenerator
from yaraast.yaral.optimizer import YaraLOptimizer
from yaraast.yaral.parser import YaraLParser
from yaraast.yaral.validator import YaraLValidator


def _display_validation_results(file, ast, errors, warnings, strict, output_json):
    """Display validation results in JSON or text format."""
    if output_json:
        _display_json_results(file, errors, warnings, strict)
    else:
        _display_text_results(ast, errors, warnings, strict)


def _display_json_results(file, errors, warnings, strict):
    """Display validation results in JSON format."""
    import json

    result = {
        "file": file,
        "errors": [
            {"severity": e.severity, "message": e.message, "section": e.section} for e in errors
        ],
        "warnings": [
            {"severity": w.severity, "message": w.message, "section": w.section} for w in warnings
        ],
        "valid": len(errors) == 0 and (not strict or len(warnings) == 0),
    }
    click.echo(json.dumps(result, indent=2))


def _display_text_results(ast, errors, warnings, strict):
    """Display validation results in text format."""
    # Display errors
    if errors:
        click.echo("❌ Validation Errors:", err=True)
        for error in errors:
            click.echo(f"  • {error}", err=True)

    # Display warnings
    if warnings:
        click.echo("⚠️  Validation Warnings:")
        for warning in warnings:
            click.echo(f"  • {warning}")

    # Summary
    if not errors and (not strict or not warnings):
        click.echo(f"✅ YARA-L file is valid ({len(ast.rules)} rules)")
    else:
        click.echo(
            f"❌ YARA-L file has {len(errors)} errors and {len(warnings)} warnings",
            err=True,
        )
        if strict and warnings:
            raise click.Abort() from None


def _format_yaral_code(code: str) -> str:
    """Format YARA-L code with proper indentation."""
    lines = code.split("\n")
    formatted_lines = []
    indent = 0

    section_keywords = [
        "rule",
        "meta",
        "events",
        "match",
        "condition",
        "outcome",
        "options",
    ]

    for line in lines:
        stripped = line.strip()
        if not stripped:
            formatted_lines.append("")
            continue

        formatted_line, indent = _format_line(stripped, indent, section_keywords)
        formatted_lines.append(formatted_line)

    return "\n".join(formatted_lines)


def _format_line(stripped: str, indent: int, section_keywords: list) -> tuple[str, int]:
    """Format a single line and return the formatted line and new indent level."""
    if stripped.endswith("{"):
        return ("  " * indent + stripped, indent + 1)
    if stripped.startswith("}"):
        new_indent = max(0, indent - 1)
        return ("  " * new_indent + stripped, new_indent)
    if stripped.endswith(":"):
        line = "  " * indent + stripped
        new_indent = indent + 1 if not stripped.startswith("rule") else indent
        return (line, new_indent)
    if stripped and not any(stripped.startswith(s) for s in section_keywords):
        return ("  " * max(1, indent) + stripped, indent)

    new_indent = 1 if stripped in section_keywords[1:] else indent
    return ("  " * new_indent + stripped, new_indent)


@click.group()
def yaral():
    """YARA-L specific operations."""
    pass


@yaral.command()
@click.argument("file", type=click.Path(exists=True))
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
    try:
        with open(file) as f:
            content = f.read()

        # Choose parser
        if enhanced:
            parser = EnhancedYaraLParser(content)
            click.echo("Using enhanced YARA-L parser...")
        else:
            parser = YaraLParser(content)
            click.echo("Using standard YARA-L parser...")

        # Parse
        ast = parser.parse()

        # Format output
        if format == "json":
            import json

            output_str = json.dumps(ast.__dict__, default=str, indent=2)
        elif format == "yaml":
            import yaml

            output_str = yaml.dump(ast.__dict__, default_flow_style=False)
        else:
            output_str = str(ast)

        # Output
        if output:
            Path(output).write_text(output_str)
            click.echo(f"AST written to {output}")
        else:
            click.echo(output_str)

        click.echo(f"✅ Successfully parsed {len(ast.rules)} rules")

    except Exception as e:
        click.echo(f"❌ Error parsing YARA-L file: {e}", err=True)
        raise click.Abort() from None


@yaral.command()
@click.argument("file", type=click.Path(exists=True))
@click.option("--strict", is_flag=True, help="Treat warnings as errors")
@click.option("--json", "output_json", is_flag=True, help="Output results as JSON")
def validate(file: str, strict: bool, output_json: bool):
    """Validate YARA-L file for semantic correctness."""
    try:
        with open(file) as f:
            content = f.read()

        # Parse
        parser = YaraLParser(content)
        ast = parser.parse()

        # Validate
        validator = YaraLValidator()
        errors, warnings = validator.validate(ast)

        _display_validation_results(file, ast, errors, warnings, strict, output_json)

    except Exception as e:
        click.echo(f"❌ Error validating YARA-L file: {e}", err=True)
        raise click.Abort() from None


@yaral.command()
@click.argument("file", type=click.Path(exists=True))
@click.option("--output", "-o", type=click.Path(), help="Output optimized YARA-L to file")
@click.option("--stats", is_flag=True, help="Show optimization statistics")
@click.option(
    "--dry-run",
    is_flag=True,
    help="Show what would be optimized without making changes",
)
def optimize(file: str, output: str | None, stats: bool, dry_run: bool):
    """Optimize YARA-L rules for better performance."""
    try:
        with open(file) as f:
            content = f.read()

        # Parse
        parser = YaraLParser(content)
        ast = parser.parse()

        # Optimize
        optimizer = YaraLOptimizer()
        optimized_ast, optimization_stats = optimizer.optimize(ast)

        if dry_run:
            click.echo("🔍 Optimization Preview (dry run):")
            click.echo(f"  • Would optimize {optimization_stats.rules_optimized} rules")
            click.echo(f"  • Would simplify {optimization_stats.conditions_simplified} conditions")
            click.echo(f"  • Would optimize {optimization_stats.events_optimized} events")
            click.echo(
                f"  • Would remove {optimization_stats.redundant_checks_removed} redundant checks"
            )
            click.echo(f"  • Would suggest {optimization_stats.indexes_suggested} indexes")
            return

        # Generate optimized code
        generator = YaraLGenerator()
        optimized_code = generator.generate(optimized_ast)

        # Output
        if output:
            Path(output).write_text(optimized_code)
            click.echo(f"✅ Optimized YARA-L written to {output}")
        else:
            click.echo(optimized_code)

        # Show stats
        if stats:
            click.echo("\n📊 Optimization Statistics:")
            click.echo(f"  • Rules optimized: {optimization_stats.rules_optimized}")
            click.echo(f"  • Conditions simplified: {optimization_stats.conditions_simplified}")
            click.echo(f"  • Events optimized: {optimization_stats.events_optimized}")
            click.echo(
                f"  • Redundant checks removed: {optimization_stats.redundant_checks_removed}"
            )
            click.echo(f"  • Indexes suggested: {optimization_stats.indexes_suggested}")
            click.echo(f"  • Time windows optimized: {optimization_stats.time_windows_optimized}")

    except Exception as e:
        click.echo(f"❌ Error optimizing YARA-L file: {e}", err=True)
        raise click.Abort() from None


@yaral.command()
@click.argument("file", type=click.Path(exists=True))
@click.option("--output", "-o", type=click.Path(), help="Output generated YARA-L to file")
@click.option("--format", is_flag=True, help="Format the output code")
def generate(file: str, output: str | None, format: bool):
    """Generate YARA-L code from AST or transform existing rules."""
    try:
        with open(file) as f:
            content = f.read()

        # Parse
        parser = EnhancedYaraLParser(content)
        ast = parser.parse()

        # Generate
        generator = YaraLGenerator()
        code = generator.generate(ast)

        # Format if requested
        if format:
            code = _format_yaral_code(code)

        # Output
        if output:
            Path(output).write_text(code)
            click.echo(f"✅ Generated YARA-L written to {output}")
        else:
            click.echo(code)

        click.echo(f"✅ Successfully generated code for {len(ast.rules)} rules")

    except Exception as e:
        click.echo(f"❌ Error generating YARA-L code: {e}", err=True)
        raise click.Abort() from None


@yaral.command()
@click.argument("file1", type=click.Path(exists=True))
@click.argument("file2", type=click.Path(exists=True))
@click.option("--semantic", is_flag=True, help="Compare semantic meaning, not just syntax")
def compare(file1: str, file2: str, semantic: bool):
    """Compare two YARA-L files for differences."""
    try:
        # Parse both files
        ast1 = _parse_file(file1)
        ast2 = _parse_file(file2)

        # Compare
        if semantic:
            _compare_semantic(ast1, ast2)
        else:
            _compare_structural(ast1, ast2)

    except Exception as e:
        click.echo(f"❌ Error comparing YARA-L files: {e}", err=True)
        raise click.Abort() from None


def _parse_file(file_path: str):
    """Parse a YARA-L file and return its AST."""
    with open(file_path) as f:
        content = f.read()
    parser = YaraLParser(content)
    return parser.parse()


def _compare_semantic(ast1, ast2):
    """Compare two ASTs semantically."""
    generator = YaraLGenerator()
    normalized1 = generator.generate(ast1)
    normalized2 = generator.generate(ast2)

    if normalized1 == normalized2:
        click.echo("✅ Files are semantically equivalent")
    else:
        click.echo("❌ Files are semantically different")


def _compare_structural(ast1, ast2):
    """Compare two ASTs structurally."""
    if len(ast1.rules) != len(ast2.rules):
        click.echo(f"❌ Different number of rules: {len(ast1.rules)} vs {len(ast2.rules)}")
        return

    differences = []
    for _i, (rule1, rule2) in enumerate(zip(ast1.rules, ast2.rules, strict=False)):
        if rule1.name != rule2.name:
            differences.append(f"Rule name: {rule1.name} vs {rule2.name}")

    if differences:
        click.echo("❌ Files have differences:")
        for diff in differences:
            click.echo(f"  • {diff}")
    else:
        click.echo("✅ Files have the same structure")


@yaral.command()
@click.option("--examples", is_flag=True, help="Show example YARA-L rules")
@click.option("--fields", is_flag=True, help="Show valid UDM fields")
@click.option("--functions", is_flag=True, help="Show available aggregation functions")
def info(examples: bool, fields: bool, functions: bool):
    """Show information about YARA-L syntax and features."""
    if examples:
        click.echo("📚 Example YARA-L Rules:\n")
        click.echo(
            """rule suspicious_login_attempts {
    meta:
        author = "security-team"
        description = "Detect multiple failed login attempts"
        severity = "medium"

    events:
        $login.metadata.event_type = "USER_LOGIN"
        $login.security_result.action = "BLOCK"
        $login.principal.user = $user

    match:
        $user over 5m

    condition:
        #login > 5

    outcome:
        $risk_score = 50 + (#login * 10)
        $affected_user = $user
        $login_count = count($login)
}"""
        )

    if fields:
        click.echo("📋 Valid UDM Field Namespaces:\n")
        validator = YaraLValidator()
        for namespace, fields_list in validator.VALID_UDM_FIELDS.items():
            click.echo(f"  {namespace}:")
            for field in fields_list[:5]:  # Show first 5
                click.echo(f"    • {field}")
            if len(fields_list) > 5:
                click.echo(f"    ... and {len(fields_list) - 5} more")

    if functions:
        click.echo("🔧 Available Aggregation Functions:\n")
        functions = [
            ("count", "Count number of events"),
            ("count_distinct", "Count unique values"),
            ("sum", "Sum numeric values"),
            ("avg", "Calculate average"),
            ("min", "Find minimum value"),
            ("max", "Find maximum value"),
            ("array", "Collect values into array"),
            ("array_distinct", "Collect unique values into array"),
            ("string_concat", "Concatenate string values"),
        ]
        for func, desc in functions:
            click.echo(f"  • {func}(): {desc}")

    if not any([examples, fields, functions]):
        click.echo("YARA-L Support Status:")
        click.echo("  ✅ Basic rule parsing")
        click.echo("  ✅ Event patterns and UDM fields")
        click.echo("  ✅ Time windows and correlation")
        click.echo("  ✅ Aggregation functions")
        click.echo("  ✅ Conditional expressions")
        click.echo("  ✅ Semantic validation")
        click.echo("  ✅ Query optimization")
        click.echo("  ✅ Code generation")
        click.echo("\nUse --examples, --fields, or --functions for more details.")
