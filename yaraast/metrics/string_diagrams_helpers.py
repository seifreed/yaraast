"""Convenience helpers for string diagram analysis."""

from __future__ import annotations

from typing import Any

from yaraast.ast.strings import HexString, PlainString, RegexString
from yaraast.metrics.string_diagram_primitives import (
    analyze_string_patterns,
)
from yaraast.metrics.string_diagrams_common import (
    modifier_names,
    plain_value_length,
    plain_value_text,
    string_pattern_identity,
)

from .string_diagrams import StringDiagramGenerator

# Convenience functions


def generate_string_diagram(string_def) -> str:
    """Generate string diagram for a string definition."""
    gen = StringDiagramGenerator()
    return gen.generate(string_def)


def generate_pattern_report(strings: list) -> dict[str, Any]:
    """Generate comprehensive pattern analysis report."""
    analysis = analyze_string_patterns(strings)
    details: list[dict[str, Any]] = []

    report = {
        "summary": {
            "total": analysis["total_strings"],
            "by_type": analysis["types"],
            "unique_patterns": len({string_pattern_identity(string_def) for string_def in strings}),
        },
        "details": details,
    }

    # Add details for each string
    for string_def in strings:
        detail = {
            "identifier": string_def.identifier,
            "type": type(string_def).__name__,
            "modifiers": modifier_names(string_def.modifiers),
        }

        if isinstance(string_def, PlainString):
            detail["value"] = plain_value_text(string_def.value)
            detail["length"] = plain_value_length(string_def.value)
        elif isinstance(string_def, HexString):
            detail["tokens"] = len(string_def.tokens)
        elif isinstance(string_def, RegexString):
            detail["pattern"] = string_def.regex

        details.append(detail)

    return report
