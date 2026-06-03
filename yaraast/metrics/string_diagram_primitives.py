"""Pure string-pattern diagram builders shared across the metrics diagram modules.

Extracted from string_diagrams_helpers so both it and string_diagrams_render reuse
one implementation; this module imports no sibling metrics module, breaking the
cycle helpers <-> string_diagrams.
"""

from __future__ import annotations

from collections import Counter
import re
from typing import Any

from yaraast.ast.strings import HexString, PlainString, RegexString
from yaraast.metrics.string_diagrams_common import (
    format_hex_token_for_diagram,
    modifier_names,
    plain_value_text,
)


def create_hex_diagram(tokens: list) -> str:
    """Create hex pattern diagram from tokens."""
    return " ".join(format_hex_token_for_diagram(token) for token in tokens)


def create_regex_diagram(pattern: str) -> str:
    """Create regex pattern diagram."""
    groups = re.findall(r"\([^?]", pattern)
    quantifiers = re.findall(r"[*+?{]", pattern)
    anchors = re.findall(r"[\^$]", pattern)
    char_classes = re.findall(r"\[[^\]]+\]", pattern)

    diagram = f"Pattern: /{pattern}/\n"

    if groups:
        diagram += f"Capture groups: {len(groups)}\n"
        diagram += f"  Groups: {groups}\n"

    if quantifiers:
        diagram += f"Quantifiers: {quantifiers}\n"

    if anchors:
        diagram += f"Anchors: {anchors}\n"

    if char_classes:
        diagram += f"Character classes: {char_classes}\n"

    return diagram


def analyze_string_patterns(strings: list) -> dict[str, Any]:
    """Analyze patterns in a list of string definitions."""
    analysis = {
        "total_strings": len(strings),
        "types": {
            "plain": 0,
            "hex": 0,
            "regex": 0,
        },
        "patterns": {
            "common_prefixes": [],
            "common_suffixes": [],
            "duplicates": [],
        },
        "modifiers": {},
    }

    plain_values = []

    for string_def in strings:
        if isinstance(string_def, PlainString):
            analysis["types"]["plain"] += 1
            plain_values.append(plain_value_text(string_def.value))
        elif isinstance(string_def, HexString):
            analysis["types"]["hex"] += 1
        elif isinstance(string_def, RegexString):
            analysis["types"]["regex"] += 1

        # Count modifiers
        for mod in string_def.modifiers:
            mod_name = modifier_names([mod])[0]
            analysis["modifiers"][mod_name] = analysis["modifiers"].get(mod_name, 0) + 1

    # Find common prefixes in plain strings
    if len(plain_values) > 1:
        # Find common prefixes
        prefixes = Counter()
        for i, s1 in enumerate(plain_values):
            for _j, s2 in enumerate(plain_values[i + 1 :], i + 1):
                # Find common prefix
                prefix = ""
                for k in range(min(len(s1), len(s2))):
                    if s1[k] == s2[k]:
                        prefix += s1[k]
                    else:
                        break
                if len(prefix) >= 3:  # Minimum prefix length
                    prefixes[prefix] += 1

        analysis["patterns"]["common_prefixes"] = [
            p for p, count in prefixes.most_common(5) if count >= 2
        ]

        suffixes = Counter()
        for i, s1 in enumerate(plain_values):
            for _j, s2 in enumerate(plain_values[i + 1 :], i + 1):
                suffix = ""
                for k in range(1, min(len(s1), len(s2)) + 1):
                    if s1[-k] == s2[-k]:
                        suffix = s1[-k] + suffix
                    else:
                        break
                if len(suffix) >= 3:
                    suffixes[suffix] += 1

        analysis["patterns"]["common_suffixes"] = [
            s for s, count in suffixes.most_common(5) if count >= 2
        ]

        # Find duplicates
        value_counts = Counter(plain_values)
        analysis["patterns"]["duplicates"] = [v for v, count in value_counts.items() if count > 1]

    return analysis
