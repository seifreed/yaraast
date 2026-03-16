"""Fluent API demonstration CLI command."""

from __future__ import annotations

from pathlib import Path

import click

from yaraast.cli.fluent_reporting import display_error, write_output
from yaraast.cli.fluent_services import (
    build_yara_file_with_rules,
    create_condition_demo_rules,
    create_example_rules,
    create_string_patterns_rule,
    create_template_rule,
    create_transformation_rules,
    generate_code,
)


@click.group()
def fluent() -> None:
    """Fluent API demonstrations and examples.

    The fluent API provides a programmatic way to construct YARA rules
    using method chaining and builder patterns, making rule creation
    more readable and maintainable.
    """


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
        yara_ast = create_example_rules()
        yara_code = generate_code(yara_ast)
        write_output(output, yara_code, f"✅ Example rules written to {output}")
    except Exception as e:
        display_error(f"❌ Error generating examples: {e}")
        raise click.Abort from None


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
        rule_ast = create_string_patterns_rule()
        yara_code = generate_code(rule_ast)
        write_output(output, yara_code, f"✅ String pattern demo written to {output}")

    except Exception as e:
        display_error(f"❌ Error generating string patterns: {e}")
        raise click.Abort from None


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
        rules = create_condition_demo_rules()
        yara_code = build_yara_file_with_rules(rules)
        write_output(output, yara_code, f"✅ Condition demo written to {output}")

    except Exception as e:
        display_error(f"❌ Error generating conditions: {e}")
        raise click.Abort from None


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
        rules = create_transformation_rules()
        yara_code = build_yara_file_with_rules(rules)
        write_output(output, yara_code, f"✅ Transformation demo written to {output}")

    except Exception as e:
        display_error(f"❌ Error generating transformations: {e}")
        raise click.Abort from None


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
        tag_list = []
        if tags:
            tag_list = [tag.strip() for tag in tags.split(",")]

        built_rule = create_template_rule(rule_name, rule_type, author, tag_list)
        yara_code = generate_code(built_rule)
        write_output(output, yara_code, f"✅ Rule template written to {output}")

    except Exception as e:
        display_error(f"❌ Error generating template: {e}")
        raise click.Abort from None


if __name__ == "__main__":
    fluent()
