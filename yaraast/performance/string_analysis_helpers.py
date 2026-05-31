"""Statistical helpers behind StringPatternAnalyzer."""

from __future__ import annotations

from collections import Counter, defaultdict
from collections.abc import Sequence
from typing import Any

from yaraast.ast.strings import HexString, PlainString, RegexString
from yaraast.codegen.generator_helpers import escape_plain_string_value

StringValue = str | bytes


def _string_report_value(value: StringValue) -> str:
    if isinstance(value, bytes):
        return escape_plain_string_value(value)
    return value


def find_duplicates(analyzer: Any, strings: Sequence[StringValue]) -> dict[str, int]:
    counter = Counter(strings)
    duplicates = {_string_report_value(s): count for s, count in counter.items() if count > 1}
    analyzer._stats["duplicate_values"] = len(duplicates)
    return duplicates


def find_common_prefixes(
    analyzer: Any, strings: Sequence[StringValue], min_length: int = 3
) -> dict[str, list[str]]:
    prefixes = defaultdict(list)
    for string in strings:
        if len(string) >= min_length:
            for i in range(min_length, min(len(string), 20)):
                prefixes[string[:i]].append(string)
    common = {
        _string_report_value(prefix): [_string_report_value(value) for value in values]
        for prefix, values in prefixes.items()
        if len(values) > 1
    }
    analyzer._stats["common_prefixes"] = len(common)
    return common


def find_common_suffixes(
    analyzer: Any, strings: Sequence[StringValue], min_length: int = 3
) -> dict[str, list[str]]:
    suffixes = defaultdict(list)
    for string in strings:
        if len(string) >= min_length:
            for i in range(min_length, min(len(string), 20)):
                suffixes[string[-i:]].append(string)
    common = {
        _string_report_value(suffix): [_string_report_value(value) for value in values]
        for suffix, values in suffixes.items()
        if len(values) > 1
    }
    analyzer._stats["common_suffixes"] = len(common)
    return common


def analyze_lengths(strings: Sequence[StringValue]) -> dict[str, Any]:
    if not strings:
        return {"min": 0, "max": 0, "average": 0, "distribution": {}}
    lengths = [len(s) for s in strings]
    return {
        "min": min(lengths),
        "max": max(lengths),
        "average": sum(lengths) / len(lengths),
        "distribution": dict(Counter(lengths)),
    }


def categorize_patterns(analyzer: Any, patterns: Sequence[StringValue | object]) -> dict[str, int]:
    categories = {"plain": 0, "hex": 0, "regex": 0, "other": 0}
    for pattern in patterns:
        if isinstance(pattern, PlainString):
            categories["plain"] += 1
        elif isinstance(pattern, HexString):
            categories["hex"] += 1
        elif isinstance(pattern, RegexString):
            categories["regex"] += 1
        else:
            categories["other"] += 1
    analyzer._stats["plain_strings"] = categories["plain"]
    analyzer._stats["hex_strings"] = categories["hex"]
    analyzer._stats["regex_strings"] = categories["regex"]
    return categories


def find_optimizations(
    strings: Sequence[StringValue],
    duplicates: dict[str, int],
    prefixes: dict[str, list[str]],
    suffixes: dict[str, list[str]],
) -> list[dict[str, Any]]:
    optimizations: list[dict[str, Any]] = []
    if duplicates:
        optimizations.append(
            {
                "type": "duplicate_removal",
                "impact": "high",
                "description": f"Found {len(duplicates)} duplicate strings",
                "strings": list(duplicates.keys()),
            },
        )
    if len(prefixes) > 5:
        optimizations.append(
            {
                "type": "prefix_tree",
                "impact": "medium",
                "description": f"Found {len(prefixes)} common prefixes",
                "prefixes": list(prefixes.keys())[:10],
            },
        )
    if len(suffixes) > 5:
        optimizations.append(
            {
                "type": "suffix_tree",
                "impact": "medium",
                "description": f"Found {len(suffixes)} common suffixes",
                "suffixes": list(suffixes.keys())[:10],
            },
        )
    total_size = sum(len(s) for s in strings)
    unique_size = sum(len(s) for s in set(strings))
    if total_size > unique_size * 1.2:
        optimizations.append(
            {
                "type": "string_pooling",
                "impact": "medium",
                "description": f"String pooling could save {total_size - unique_size} bytes",
                "savings": total_size - unique_size,
            },
        )
    return optimizations


def analyze_cross_rule_patterns(rules: Sequence[Any]) -> dict[str, Any]:
    string_to_rules: defaultdict[str, list[str]] = defaultdict(list)
    for rule in rules:
        if rule.strings:
            for string_def in rule.strings:
                if hasattr(string_def, "value"):
                    string_to_rules[_string_report_value(string_def.value)].append(rule.name)
    shared = {string: rules for string, rules in string_to_rules.items() if len(rules) > 1}
    return {
        "shared_strings": shared,
        "total_unique": len(string_to_rules),
        "total_shared": len(shared),
    }
