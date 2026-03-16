"""Convenience helpers for string diagram analysis."""

from __future__ import annotations

import re
from collections import Counter
from typing import Any

from yaraast.ast.strings import HexString, PlainString, RegexString

from .string_diagrams import StringDiagramGenerator

# Convenience functions


def generate_string_diagram(string_def) -> str:
    """Generate string diagram for a string definition."""
    gen = StringDiagramGenerator()
    return gen.generate(string_def)


def create_hex_diagram(tokens: list) -> str:
    """Create hex pattern diagram from tokens."""
    from yaraast.ast.strings import HexAlternative, HexByte, HexJump, HexWildcard

    pattern_parts = []
    for token in tokens:
        if isinstance(token, HexByte):
            pattern_parts.append(f"{token.value:02X}")
        elif isinstance(token, HexWildcard):
            pattern_parts.append("??")
        elif isinstance(token, HexJump):
            if token.min_jump == token.max_jump:
                pattern_parts.append(f"[{token.min_jump}]")
            else:
                pattern_parts.append(f"[{token.min_jump}-{token.max_jump}]")
        elif isinstance(token, HexAlternative):
            alt_str = "|".join(f"{b:02X}" for b in token.alternatives)
            pattern_parts.append(f"({alt_str})")

    return " ".join(pattern_parts)


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
            plain_values.append(string_def.value)
        elif isinstance(string_def, HexString):
            analysis["types"]["hex"] += 1
        elif isinstance(string_def, RegexString):
            analysis["types"]["regex"] += 1

        # Count modifiers
        for mod in string_def.modifiers:
            # Handle both string and object modifiers
            mod_name = mod.name if hasattr(mod, "name") else str(mod)
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

        # Find duplicates
        value_counts = Counter(plain_values)
        analysis["patterns"]["duplicates"] = [v for v, count in value_counts.items() if count > 1]

    return analysis


def generate_pattern_report(strings: list) -> dict[str, Any]:
    """Generate comprehensive pattern analysis report."""
    analysis = analyze_string_patterns(strings)

    report = {
        "summary": {
            "total": analysis["total_strings"],
            "by_type": analysis["types"],
            "unique_patterns": analysis["total_strings"] - len(analysis["patterns"]["duplicates"]),
        },
        "details": [],
    }

    # Add details for each string
    for string_def in strings:
        detail = {
            "identifier": string_def.identifier,
            "type": type(string_def).__name__,
            "modifiers": [
                mod.name if hasattr(mod, "name") else str(mod) for mod in string_def.modifiers
            ],
        }

        if isinstance(string_def, PlainString):
            detail["value"] = string_def.value
            detail["length"] = len(string_def.value)
        elif isinstance(string_def, HexString):
            detail["tokens"] = len(string_def.tokens)
        elif isinstance(string_def, RegexString):
            detail["pattern"] = string_def.regex

        report["details"].append(detail)

    return report
