"""YARA-X specific CLI commands."""

from pathlib import Path

import click

from yaraast.yarax.compatibility_checker import YaraXCompatibilityChecker
from yaraast.yarax.feature_flags import YaraXFeatures
from yaraast.yarax.generator import YaraXGenerator
from yaraast.yarax.parser import YaraXParser

# Constants
FOR_KEYWORD = " for "


def _display_yarax_features(content: str):
    """Display detected YARA-X features in content."""
    click.echo("\n📊 YARA-X Features Used:")
    features = []

    if "with " in content:
        features.append("• with statements")
    if FOR_KEYWORD in content and "[" in content:
        features.append("• array comprehensions")
    if FOR_KEYWORD in content and "{" in content:
        features.append("• dict comprehensions")
    if "lambda" in content:
        features.append("• lambda expressions")
    if "match " in content:
        features.append("• pattern matching")
    if "..." in content or "**" in content:
        features.append("• spread operators")

    if features:
        for feature in features:
            click.echo(feature)
    else:
        click.echo("  No YARA-X specific features detected")


@click.group()
def yarax():
    """YARA-X specific operations for next-gen YARA syntax."""
    pass


@yarax.command()
@click.argument("file", type=click.Path(exists=True))
@click.option("--output", "-o", type=click.Path(), help="Output AST to file")
@click.option("--show-features", is_flag=True, help="Show YARA-X features used")
def parse(file: str, output: str | None, show_features: bool):
    """Parse YARA-X file with support for new syntax features."""
    try:
        with open(file) as f:
            content = f.read()

        # Parse with YARA-X parser
        parser = YaraXParser(content)
        ast = parser.parse()

        # Generate output
        generator = YaraXGenerator()
        code = generator.generate(ast)

        if output:
            Path(output).write_text(code)
            click.echo(f"✅ AST written to {output}")
        else:
            click.echo(code)

        if show_features:
            _display_yarax_features(content)

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
        ast = _parse_yara_file(file)

        # Check compatibility
        issues = _check_yarax_compatibility(ast, strict)

        if not issues:
            click.echo("✅ File is fully compatible with YARA-X")
        else:
            _display_compatibility_issues(issues, fix)

    except Exception as e:
        click.echo(f"❌ Error checking YARA-X compatibility: {e}", err=True)
        raise click.Abort() from None


def _parse_yara_file(file_path: str):
    """Parse a YARA file and return its AST."""
    with open(file_path) as f:
        content = f.read()

    from yaraast.parser.parser import Parser

    parser = Parser(content)
    return parser.parse()


def _check_yarax_compatibility(ast, strict: bool):
    """Check AST for YARA-X compatibility."""
    features = YaraXFeatures.yarax_strict() if strict else YaraXFeatures.yarax_compatible()
    checker = YaraXCompatibilityChecker(features)
    return checker.check(ast)


def _display_compatibility_issues(issues, fix: bool):
    """Display compatibility issues grouped by severity."""
    # Group issues by severity
    errors = [i for i in issues if i.severity == "error"]
    warnings = [i for i in issues if i.severity == "warning"]
    info = [i for i in issues if i.severity == "info"]

    if errors:
        _display_issue_group("❌", errors, 5, fix, err=True)
    if warnings:
        _display_issue_group("⚠️ ", warnings, 5, fix)
    if info:
        _display_issue_group("i ", info, 3, fix)


def _display_issue_group(icon: str, issues: list, limit: int, show_fixes: bool, err: bool = False):
    """Display a group of issues with optional fixes."""
    click.echo(f"{icon} {len(issues)} {issues[0].severity.title()}s:", err=err)
    for issue in issues[:limit]:
        click.echo(f"  • {issue.message}", err=err)
        if show_fixes and issue.suggestion:
            click.echo(f"    → {issue.suggestion}")


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
    try:
        with open(file) as f:
            content = f.read()

        if target == "yarax":
            # Convert YARA to YARA-X (add modern features where possible)
            from yaraast.parser.parser import Parser

            parser = Parser(content)
            ast = parser.parse()

            # Generate with YARA-X generator
            generator = YaraXGenerator()
            converted = generator.generate(ast)

            click.echo("✅ Converted to YARA-X format")
        else:
            # Convert YARA-X to standard YARA (remove new features)
            parser = YaraXParser(content)
            ast = parser.parse()

            # Generate with standard generator (will lose some features)
            from yaraast.code_generator import CodeGenerator

            generator = CodeGenerator()
            converted = generator.generate(ast)

            click.echo("⚠️  Converted to standard YARA (some features may be lost)")

        if output:
            Path(output).write_text(converted)
            click.echo(f"✅ Converted file written to {output}")
        else:
            click.echo(converted)

    except Exception as e:
        click.echo(f"❌ Error converting file: {e}", err=True)
        raise click.Abort() from None


@yarax.command()
def features():
    """Show YARA-X feature support and examples."""
    click.echo("🚀 YARA-X New Features:\n")

    click.echo("1️⃣  WITH STATEMENTS")
    click.echo("   Declare local variables for use in conditions:")
    click.echo(
        """
   rule example_with {
       condition:
           with $a = "test", $b = 10:
               $a matches /test/ and #b > 5
   }
   """
    )

    click.echo("2️⃣  ARRAY COMPREHENSIONS")
    click.echo("   Create arrays with compact syntax:")
    click.echo(
        """
   [x * 2 for x in (1, 2, 3)]
   [s for s in strings if s matches /test/]
   """
    )

    click.echo("3️⃣  DICT COMPREHENSIONS")
    click.echo("   Create dictionaries with compact syntax:")
    click.echo(
        """
   {k: v * 2 for k, v in items}
   {s: #s for s in strings if #s > 0}
   """
    )

    click.echo("4️⃣  TUPLE INDEXING")
    click.echo("   Access tuple elements by index:")
    click.echo(
        """
   my_func()[0]  // First element of function result
   my_tuple[-1]  // Last element
   """
    )

    click.echo("5️⃣  SLICE EXPRESSIONS")
    click.echo("   Extract subsequences from arrays/strings:")
    click.echo(
        """
   array[1:5]    // Elements 1-4
   string[:-1]   // All but last character
   data[::2]     // Every second element
   """
    )

    click.echo("6️⃣  LAMBDA EXPRESSIONS")
    click.echo("   Anonymous functions for functional programming:")
    click.echo(
        """
   map(lambda x: x * 2, array)
   filter(lambda s: s matches /test/, strings)
   """
    )

    click.echo("7️⃣  PATTERN MATCHING")
    click.echo("   Match expressions for cleaner conditionals:")
    click.echo(
        """
   match value {
       1 => "one",
       2 => "two",
       _ => "other"
   }
   """
    )

    click.echo("8️⃣  SPREAD OPERATORS")
    click.echo("   Unpack arrays and dicts:")
    click.echo(
        """
   [...array1, ...array2]  // Combine arrays
   {**dict1, **dict2}      // Merge dictionaries
   """
    )

    click.echo("\n✅ All features are fully supported in this implementation!")


@yarax.command()
@click.argument("code", required=False)
@click.option("--file", "-f", type=click.Path(exists=True), help="Read code from file")
def playground(code: str | None, file: str | None):
    """Interactive playground for testing YARA-X features."""
    if file:
        with open(file) as f:
            code = f.read()
    elif not code:
        # Provide example code
        code = """
rule yarax_demo {
    meta:
        description = "YARA-X feature demonstration"

    strings:
        $str1 = "test"
        $str2 = /pattern/i

    condition:
        // With statement for local variables
        with $count = #str1, $threshold = 5:
            $count > $threshold and

            // Array comprehension
            any of [s for s in ($str1, $str2) if s]
}
"""
        click.echo("📝 Example YARA-X code (no input provided):")

    click.echo(code)
    click.echo("\n" + "=" * 50 + "\n")

    try:
        # Parse with YARA-X parser
        parser = YaraXParser(code)
        ast = parser.parse()

        click.echo("✅ Successfully parsed!")

        # Generate back
        generator = YaraXGenerator()
        generated = generator.generate(ast)

        click.echo("\n📄 Generated code:")
        click.echo(generated)

        # Show detected features
        features = []
        if "with " in code:
            features.append("with statements")
        if "[" in code and FOR_KEYWORD in code:
            features.append("comprehensions")
        if "lambda" in code:
            features.append("lambda expressions")

        if features:
            click.echo(f"\n🔍 Features used: {', '.join(features)}")

    except Exception as e:
        click.echo(f"❌ Parse error: {e}", err=True)
