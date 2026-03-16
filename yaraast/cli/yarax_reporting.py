"""Reporting helpers for YARA-X CLI output."""

from __future__ import annotations

from typing import Any

import click


def display_yarax_features(features: list[str]) -> None:
    """Display detected YARA-X features."""
    click.echo("\n📊 YARA-X Features Used:")
    if features:
        for feature in features:
            click.echo(f"• {feature}")
    else:
        click.echo("  No YARA-X specific features detected")


def display_compatibility_issues(issues: list[Any], show_fixes: bool) -> None:
    """Display compatibility issues grouped by severity."""
    errors = [i for i in issues if i.severity == "error"]
    warnings = [i for i in issues if i.severity == "warning"]
    info = [i for i in issues if i.severity == "info"]

    if errors:
        _display_issue_group("❌", errors, 5, show_fixes, err=True)
    if warnings:
        _display_issue_group("⚠️ ", warnings, 5, show_fixes)
    if info:
        _display_issue_group("i ", info, 3, show_fixes)


def _display_issue_group(
    icon: str, issues: list[Any], limit: int, show_fixes: bool, err: bool = False
):
    """Display a group of issues with optional fixes."""
    click.echo(f"{icon} {len(issues)} {issues[0].severity.title()}s:", err=err)
    for issue in issues[:limit]:
        click.echo(f"  • {issue.message}", err=err)
        if show_fixes and issue.suggestion:
            click.echo(f"    → {issue.suggestion}")


def display_feature_showcase() -> None:
    """Print static feature showcase."""
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


def display_playground_input(code: str, used_default: bool) -> None:
    if used_default:
        click.echo("📝 Example YARA-X code (no input provided):")
    click.echo(code)
    click.echo("\n" + "=" * 50 + "\n")


def display_playground_results(generated: str, features: list[str]) -> None:
    click.echo("✅ Successfully parsed!")
    click.echo("\n📄 Generated code:")
    click.echo(generated)

    if features:
        click.echo(f"\n🔍 Features used: {', '.join(features)}")
