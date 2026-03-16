"""Rule-focused helper logic for OptimizationAnalyzer."""

from __future__ import annotations

from collections import defaultdict

from yaraast.analysis.optimization_grouping_helpers import (
    group_duplicate_strings,
    group_rules_by_pattern,
)
from yaraast.analysis.optimization_helpers import (
    extract_comparison,
    get_condition_pattern,
    get_hex_prefix,
    should_be_hex,
)
from yaraast.ast.strings import HexString, PlainString


def analyze_string_definitions(analyzer, rule) -> None:
    hex_strings = []
    plain_strings = []
    for string_def in rule.strings:
        if isinstance(string_def, HexString):
            hex_strings.append(string_def)
        elif isinstance(string_def, PlainString):
            plain_strings.append(string_def)

    if len(hex_strings) > 1:
        check_hex_consolidation(analyzer, rule, hex_strings)

    for plain in plain_strings:
        if should_be_hex(plain):
            analyzer.report.add_suggestion(
                rule.name,
                "string_optimization",
                f"String '{plain.identifier}' contains mostly non-printable chars; a hex pattern may be clearer",
                "medium",
                f'$str = "{plain.value}"',
                f"$str = {{ {' '.join(f'{ord(c):02X}' for c in plain.value)} }}",
            )

    check_overlapping_patterns(analyzer, rule, rule.strings)


def check_hex_consolidation(analyzer, rule, hex_strings: list[HexString]) -> None:
    groups = defaultdict(list)
    for hex_str in hex_strings:
        prefix = get_hex_prefix(hex_str, min(5, len(hex_str.tokens) - 1))
        if prefix and len(prefix) >= 4:
            groups[prefix].append(hex_str)
    for similar in groups.values():
        if len(similar) > 2:
            names = [s.identifier for s in similar]
            analyzer.report.add_suggestion(
                rule.name,
                "pattern_consolidation",
                f"Hex patterns {', '.join(names)} share a common prefix; alternatives or wildcards may reduce duplication",
                "medium",
            )


def check_overlapping_patterns(analyzer, rule, strings: list[object]) -> None:
    plain_strings = [(s.identifier, s.value) for s in strings if isinstance(s, PlainString)]
    for i, (id1, val1) in enumerate(plain_strings):
        for id2, val2 in plain_strings[i + 1 :]:
            if val1 in val2:
                analyzer.report.add_suggestion(
                    rule.name,
                    "redundant_pattern",
                    f"String '{id1}' is contained in '{id2}'; it may be redundant",
                    "low",
                )
            elif val2 in val1:
                analyzer.report.add_suggestion(
                    rule.name,
                    "redundant_pattern",
                    f"String '{id2}' is contained in '{id1}'; it may be redundant",
                    "low",
                )


def analyze_condition_patterns(analyzer, rule) -> None:
    for string_id, refs in analyzer._string_refs.items():
        if len(refs) > 3:
            analyzer.report.add_suggestion(
                rule.name,
                "condition_optimization",
                f"String '{string_id}' is referenced {len(refs)} times; consider storing the result in a variable if readability suffers",
                "low",
            )
    if analyzer._max_condition_depth > 4:
        analyzer.report.add_suggestion(
            rule.name,
            "condition_complexity",
            "deep condition nesting may be harder to maintain; consider breaking it into multiple rules",
            "medium",
        )


def visit_binary_expression(analyzer, node) -> None:
    analyzer._condition_depth += 1
    analyzer._max_condition_depth = max(analyzer._max_condition_depth, analyzer._condition_depth)
    if node.operator == "and":
        left_cmp = extract_comparison(node.left)
        right_cmp = extract_comparison(node.right)
        if (
            left_cmp
            and right_cmp
            and left_cmp["var"] == right_cmp["var"]
            and left_cmp["op"] in [">", ">="]
            and right_cmp["op"] in [">", ">="]
            and analyzer._current_rule
        ):
            analyzer.report.add_suggestion(
                analyzer._current_rule.name,
                "redundant_comparison",
                f"Redundant comparisons on '{left_cmp['var']}' may be present; keep only the stricter one if semantics stay the same",
                "low",
            )
    analyzer.visit(node.left)
    analyzer.visit(node.right)
    analyzer._condition_depth -= 1


def analyze_cross_rule_patterns(analyzer, rules) -> None:
    string_to_rules = group_duplicate_strings(rules)
    for (str_type, _value), rule_names in string_to_rules.items():
        if len(rule_names) > 2:
            analyzer.report.add_suggestion(
                "global",
                "duplication",
                f"Same {str_type} pattern used in {len(rule_names)} rules: {', '.join(rule_names[:3])}...; consider a shared include if that fits your workflow",
                "medium",
            )
    find_similar_rules(analyzer, rules)


def find_similar_rules(analyzer, rules) -> None:
    rule_patterns = group_rules_by_pattern(rules, get_condition_pattern)
    for pattern, names in rule_patterns.items():
        if len(names) > 3 and pattern[0] > 0:
            analyzer.report.add_suggestion(
                "global",
                "rule_similarity",
                f"{len(names)} rules have similar structure ({pattern[0]} strings, similar conditions); consider consolidation if the rules are intended to evolve together",
                "medium",
            )
