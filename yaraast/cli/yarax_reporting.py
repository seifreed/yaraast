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

    _display_syntax_features()

    click.echo("\n✅ All features are fully supported in this implementation!")


_SYNTAX_FEATURE_EXAMPLES: list[tuple[str, str, str]] = [
    (
        "1️⃣  WITH STATEMENTS",
        "Declare local variables for use in conditions:",
        """
   rule example_with {
       condition:
           with $a = "test", $b = 10:
               $a matches /test/ and #b > 5
   }
   """,
    ),
    (
        "2️⃣  ARRAY COMPREHENSIONS",
        "Create arrays with compact syntax:",
        """
   [x * 2 for x in (1, 2, 3)]
   [s for s in strings if s matches /test/]
   """,
    ),
    (
        "3️⃣  DICT COMPREHENSIONS",
        "Create dictionaries with compact syntax:",
        """
   {k: v * 2 for k, v in items}
   {s: #s for s in strings if #s > 0}
   """,
    ),
    (
        "4️⃣  TUPLE INDEXING",
        "Access tuple elements by index:",
        """
   my_func()[0]  // First element of function result
   my_tuple[-1]  // Last element
   """,
    ),
    (
        "5️⃣  SLICE EXPRESSIONS",
        "Extract subsequences from arrays/strings:",
        """
   array[1:5]    // Elements 1-4
   string[:-1]   // All but last character
   data[::2]     // Every second element
   """,
    ),
    (
        "6️⃣  LAMBDA EXPRESSIONS",
        "Anonymous functions for functional programming:",
        """
   map(lambda x: x * 2, array)
   filter(lambda s: s matches /test/, strings)
   """,
    ),
    (
        "7️⃣  PATTERN MATCHING",
        "Match expressions for cleaner conditionals:",
        """
   match value {
       1 => "one",
       2 => "two",
       _ => "other"
   }
   """,
    ),
    (
        "8️⃣  SPREAD OPERATORS",
        "Unpack arrays and dicts:",
        """
   [...array1, ...array2]  // Combine arrays
   {**dict1, **dict2}      // Merge dictionaries
   """,
    ),
]


def _display_syntax_features() -> None:
    """Display the syntax feature examples table."""
    for title, description, example in _SYNTAX_FEATURE_EXAMPLES:
        click.echo(title)
        click.echo(f"   {description}")
        click.echo(example)


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
