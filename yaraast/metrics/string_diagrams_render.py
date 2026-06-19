"""Render helpers for string pattern diagrams."""

from __future__ import annotations

import re

from yaraast.ast.strings import HexString, PlainString, RegexString
from yaraast.metrics.string_diagram_primitives import (
    analyze_string_patterns as analyze_string_patterns,
)
from yaraast.metrics.string_diagrams_common import (
    format_hex_token_for_diagram,
    modifier_names,
    plain_value_length,
    plain_value_text,
)

__all__ = [
    "StringDiagramRenderMixin",
    "analyze_string_patterns",
]


class StringDiagramRenderMixin:
    """Mixin providing string diagram helpers."""

    def _generate_plain_diagram(self, string_def: PlainString) -> str:
        """Generate diagram for plain string."""
        value = plain_value_text(string_def.value)
        diagram = f"PlainString: {string_def.identifier}\n"
        diagram += f'Value: "{value}"\n'
        diagram += f"Length: {plain_value_length(string_def.value)}\n"

        if string_def.modifiers:
            modifiers = ", ".join(modifier_names(string_def.modifiers))
            diagram += f"Modifiers: {modifiers}\n"

        return diagram

    def _generate_hex_diagram(self, string_def: HexString) -> str:
        """Generate diagram for hex string."""
        diagram = f"HexString: {string_def.identifier}\n"
        diagram += "Pattern: { "
        pattern_parts = [format_hex_token_for_diagram(token) for token in string_def.tokens]
        diagram += " ".join(pattern_parts) + " }\n"

        if string_def.modifiers:
            modifiers = ", ".join(modifier_names(string_def.modifiers))
            diagram += f"Modifiers: {modifiers}\n"

        return diagram

    def _generate_regex_diagram(self, string_def: RegexString) -> str:
        """Generate diagram for regex string."""
        diagram = f"RegexString: {string_def.identifier}\n"
        diagram += f"Pattern: /{string_def.regex}/\n"

        # Simple regex analysis
        groups = len(re.findall(r"\([^?]", string_def.regex))
        quantifiers = len(re.findall(r"[*+?{]", string_def.regex))

        if groups > 0:
            diagram += f"Capture Groups: {groups}\n"
        if quantifiers > 0:
            diagram += f"Quantifiers: {quantifiers}\n"

        if string_def.modifiers:
            modifiers = ", ".join(modifier_names(string_def.modifiers))
            diagram += f"Modifiers: {modifiers}\n"

        return diagram
