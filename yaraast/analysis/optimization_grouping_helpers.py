"""Grouping helpers for optimization analysis."""

from __future__ import annotations

from collections import defaultdict

from yaraast.ast.rules import Rule
from yaraast.ast.strings import HexString, PlainString


def hex_to_string(hex_str: HexString) -> str:
    parts = []
    for token in hex_str.tokens:
        if hasattr(token, "value"):
            value = token.value
            if isinstance(value, str):
                value = int(value, 16)
            parts.append(f"{value:02X}")
        else:
            parts.append("??")
    return " ".join(parts)


def group_duplicate_strings(rules: list[Rule]) -> dict[tuple[str, str], list[str]]:
    string_to_rules = defaultdict(list)
    for rule in rules:
        for string_def in rule.strings:
            if isinstance(string_def, PlainString):
                key = ("plain", string_def.value)
            elif isinstance(string_def, HexString):
                key = ("hex", hex_to_string(string_def))
            else:
                continue
            string_to_rules[key].append(rule.name)
    return string_to_rules


def group_rules_by_pattern(
    rules: list[Rule], pattern_func
) -> dict[tuple[int, str | None], list[str]]:
    rule_patterns: dict[tuple[int, str | None], list[str]] = {}
    for rule in rules:
        pattern = (len(rule.strings), pattern_func(rule.condition) if rule.condition else None)
        rule_patterns.setdefault(pattern, []).append(rule.name)
    return rule_patterns
