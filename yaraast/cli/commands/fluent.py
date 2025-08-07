"""Fluent API demonstration CLI command."""

import sys
from pathlib import Path

import click

from yaraast.builder import (
    malware_rule,
    packed_rule,
    rule,
    text,
    transform_rule,
    trojan_rule,
    yara_file,
)
from yaraast.builder.fluent_condition_builder import FluentConditionBuilder
from yaraast.codegen import CodeGenerator


@click.group()
def fluent() -> None:
    """Fluent API demonstrations and examples.

    The fluent API provides a programmatic way to construct YARA rules
    using method chaining and builder patterns, making rule creation
    more readable and maintainable.
    """


def create_example_rules():
    """Create example rules using fluent API."""
    return (
        yara_file()
        .with_rule(
            rule("example_malware")
            .tagged("malware", "backdoor")
            .authored_by("Fluent API")
            .described_as("Example malware detection rule")
            .string("$mz")
            .hex("4D 5A")
            .then()
            .string("$suspicious")
            .text("backdoor")
            .nocase()
            .then()
            .condition("$mz at 0 and $suspicious")
            .build(),
        )
        .with_rule(
            rule("example_packer")
            .tagged("packer")
            .string("$upx")
            .text("UPX!")
            .then()
            .condition("$upx")
            .build(),
        )
        .build()
    )


@fluent.command()
@click.option(
    "--output",
    "-o",
    type=click.Path(path_type=Path),
    help="Output file (default: stdout)",
)
def examples(output: Path | None) -> None:
    """Generate example rules using the fluent API.

    This command demonstrates various fluent API patterns for building
    YARA rules programmatically, including string definitions, conditions,
    and rule transformations.
    """
    try:
        # Create example YARA file using fluent API
        yara_ast = create_example_rules()

        # Generate YARA code
        generator = CodeGenerator()
        yara_code = generator.generate(yara_ast)

        if output:
            with Path(output).open("w", encoding="utf-8") as f:
                f.write(yara_code)
            click.echo(f"✅ Example rules written to {output}")
        else:
            click.echo(yara_code)

    except Exception as e:
        click.echo(f"❌ Error generating examples: {e}", err=True)
        sys.exit(1)


@fluent.command()
@click.option(
    "--output",
    "-o",
    type=click.Path(path_type=Path),
    help="Output file (default: stdout)",
)
def string_patterns(output: Path | None) -> None:
    """Demonstrate string pattern builders.

    Shows how to use the fluent string builder API to create various
    types of string patterns with modifiers.
    """
    try:
        # Create rule with various string patterns
        rule_ast = (
            rule("string_pattern_demo")
            .tagged("demo", "strings")
            .authored_by("Fluent API Demo")
            .described_as("Demonstration of string pattern builders")
            # Plain text strings with modifiers
            .string("$text1")
            .text("hello world")
            .nocase()
            .then()
            .string("$text2")
            .text("backdoor")
            .wide()
            .fullword()
            .then()
            .string("$text3")
            .text("password")
            .ascii()
            .private()
            .then()
            # Hex patterns
            .string("$hex1")
            .hex("4D 5A ?? 00")
            .then()
            .string("$hex2")
            .hex("50 45 00 00")
            .then()
            .string("$hex3")
            .hex("?? FF FE ??")
            .then()
            # Regex patterns
            .string("$regex1")
            .regex(r"[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}")
            .nocase()
            .then()
            .string("$regex2")
            .regex(r"\b(?:[0-9]{1,3}\.){3}[0-9]{1,3}\b")
            .then()
            # Common patterns
            .mz_header("$mz")
            .pe_header("$pe")
            .email_pattern("$email")
            .ip_pattern("$ip")
            .url_pattern("$url")
            # XOR encoded strings
            .string("$xor1")
            .text("malware")
            .xor(0x42)
            .then()
            .string("$xor2")
            .text("trojan")
            .xor()
            .then()  # Any XOR key
            # Base64 encoded
            .string("$b64")
            .text("payload")
            .base64()
            .then()
            .matches_any()
            .build()
        )

        # Generate single rule
        generator = CodeGenerator()
        yara_code = generator.generate(rule_ast)

        if output:
            with Path(output).open("w", encoding="utf-8") as f:
                f.write(yara_code)
            click.echo(f"✅ String pattern demo written to {output}")
        else:
            click.echo(yara_code)

    except Exception as e:
        click.echo(f"❌ Error generating string patterns: {e}", err=True)
        sys.exit(1)


@fluent.command()
@click.option(
    "--output",
    "-o",
    type=click.Path(path_type=Path),
    help="Output file (default: stdout)",
)
def conditions(output: Path | None) -> None:
    """Demonstrate condition builders.

    Shows how to use the fluent condition builder API to create
    complex rule conditions with logical operators and quantifiers.
    """
    try:
        # Create rule with complex conditions
        rule_ast = (
            rule("condition_demo")
            .tagged("demo", "conditions")
            .authored_by("Fluent API Demo")
            .described_as("Demonstration of condition builders")
            .text_string("$a", "malware")
            .text_string("$b", "trojan")
            .text_string("$c", "backdoor")
            .hex_string("$mz", "4D 5A")
            .hex_string("$pe", "50 45 00 00")
            # Complex condition using fluent builder
            .with_condition_builder(
                lambda c: c.string_matches("$mz")
                .at(0)
                .and_(c.one_of("$a", "$b", "$c"))
                .and_(c.filesize_gt(1024))
                .and_(c.pe_is_exe()),
            )
            .build()
        )

        # Also create examples of different condition patterns
        rules = []
        rules.append(rule_ast)

        # Quantifier examples
        rules.append(
            rule("quantifier_demo")
            .tagged("demo")
            .text_string("$s1", "test1")
            .text_string("$s2", "test2")
            .text_string("$s3", "test3")
            .matches_any_of("$s1", "$s2", "$s3")
            .build(),
        )

        # File size conditions
        rules.append(
            rule("filesize_demo")
            .tagged("demo")
            .text_string("$test", "sample")
            .with_condition_builder(
                lambda c: c.string_matches("$test").and_(
                    c.filesize_between(1024, 1024 * 1024),
                ),
            )
            .build(),
        )

        # PE-specific conditions
        rules.append(
            rule("pe_demo")
            .tagged("demo", "pe")
            .mz_header()
            .with_condition_builder(
                lambda c: c.string_matches("$mz")
                .at(0)
                .and_(c.pe_is_dll())
                .and_(c.pe_section_count_eq(3)),
            )
            .build(),
        )

        # Create YARA file with all rules
        yara_ast = yara_file().import_module("pe").import_module("math")

        for r in rules:
            yara_ast.with_rule(r)

        # Generate code
        generator = CodeGenerator()
        yara_code = generator.generate(yara_ast.build())

        if output:
            with Path(output).open("w", encoding="utf-8") as f:
                f.write(yara_code)
            click.echo(f"✅ Condition demo written to {output}")
        else:
            click.echo(yara_code)

    except Exception as e:
        click.echo(f"❌ Error generating conditions: {e}", err=True)
        sys.exit(1)


@fluent.command()
@click.option(
    "--output",
    "-o",
    type=click.Path(path_type=Path),
    help="Output file (default: stdout)",
)
def transformations(output: Path | None) -> None:
    """Demonstrate AST transformations.

    Shows how to clone and transform existing rules to create variants
    with different names, tags, conditions, and string identifiers.
    """
    try:
        # Create base rule
        base_rule = (
            malware_rule("base_malware")
            .described_as("Base malware detection rule")
            .text_string("$str1", "malware")
            .text_string("$str2", "backdoor")
            .matches_any()
            .build()
        )

        # Create transformations
        rules = [base_rule]

        # Clone and rename
        variant1 = (
            transform_rule(base_rule)
            .rename("variant_malware")
            .add_tag("variant")
            .set_author("Transformation Demo")
            .build()
        )
        rules.append(variant1)

        # Clone with prefix
        variant2 = (
            transform_rule(base_rule)
            .add_prefix("win32_")
            .add_tag("windows")
            .prefix_strings("win_")
            .build()
        )
        rules.append(variant2)

        # Clone with different modifiers
        variant3 = (
            transform_rule(base_rule)
            .add_suffix("_private")
            .make_private()
            .add_tag("private")
            .build()
        )
        rules.append(variant3)

        # Create packed variant with different condition
        packed_base = (
            packed_rule("packed_sample").described_as("Packed executable template").build()
        )
        rules.append(packed_base)

        # Transform packed rule
        packed_variant = (
            transform_rule(packed_base)
            .rename("upx_packed")
            .add_tag("upx")
            .add_string(text("$upx", "UPX!").build())
            .transform_condition(
                lambda cond: FluentConditionBuilder(cond)
                .and_(FluentConditionBuilder().string_matches("$upx"))
                .build(),
            )
            .build()
        )
        rules.append(packed_variant)

        # Create YARA file
        yara_ast = yara_file().import_module("pe").import_module("math")

        for r in rules:
            yara_ast.with_rule(r)

        # Generate code
        generator = CodeGenerator()
        yara_code = generator.generate(yara_ast.build())

        if output:
            with Path(output).open("w", encoding="utf-8") as f:
                f.write(yara_code)
            click.echo(f"✅ Transformation demo written to {output}")
        else:
            click.echo(yara_code)

    except Exception as e:
        click.echo(f"❌ Error generating transformations: {e}", err=True)
        sys.exit(1)


@fluent.command()
@click.argument("rule_name")
@click.option(
    "--type",
    "rule_type",
    type=click.Choice(["malware", "trojan", "packed", "document", "network"]),
    default="malware",
    help="Type of rule template to generate",
)
@click.option("--author", default="Fluent API", help="Rule author")
@click.option("--tags", help="Comma-separated list of tags")
@click.option(
    "--output",
    "-o",
    type=click.Path(path_type=Path),
    help="Output file (default: stdout)",
)
def template(
    rule_name: str,
    rule_type: str,
    author: str,
    tags: str | None,
    output: Path | None,
) -> None:
    """Generate a rule template using fluent API.

    Creates a YARA rule template of the specified type with common
    patterns and conditions pre-configured.

    RULE_NAME: Name for the generated rule
    """
    try:
        # Parse tags
        tag_list = []
        if tags:
            tag_list = [tag.strip() for tag in tags.split(",")]

        # Create rule based on type
        if rule_type == "malware":
            rule_ast = malware_rule(rule_name)
        elif rule_type == "trojan":
            rule_ast = trojan_rule(rule_name)
        elif rule_type == "packed":
            rule_ast = packed_rule(rule_name)
        elif rule_type == "document":
            rule_ast = (
                rule(rule_name)
                .tagged("document")
                .text_string("$doc1", "%PDF-")
                .text_string("$doc2", "PK\x03\x04")  # ZIP
                .text_string("$doc3", "\xd0\xcf\x11\xe0")  # OLE
                .matches_any_of("$doc1", "$doc2", "$doc3")
            )
        elif rule_type == "network":
            rule_ast = (
                rule(rule_name)
                .tagged("network")
                .ip_pattern()
                .url_pattern()
                .email_pattern()
                .matches_any()
            )
        else:
            rule_ast = rule(rule_name).tagged(rule_type)

        # Add custom tags and author
        rule_ast = rule_ast.authored_by(author)
        for tag in tag_list:
            rule_ast = rule_ast.with_tag(tag)

        # Build and generate
        built_rule = rule_ast.build()
        generator = CodeGenerator()
        yara_code = generator.generate(built_rule)

        if output:
            with Path(output).open("w", encoding="utf-8") as f:
                f.write(yara_code)
            click.echo(f"✅ Rule template written to {output}")
        else:
            click.echo(yara_code)

    except Exception as e:
        click.echo(f"❌ Error generating template: {e}", err=True)
        sys.exit(1)


if __name__ == "__main__":
    fluent()
