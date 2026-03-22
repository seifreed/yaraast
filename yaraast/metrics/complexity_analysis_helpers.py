"""Analysis helpers for ComplexityAnalyzer."""

from __future__ import annotations

import re

from yaraast.ast.strings import HexString, PlainString, RegexString


def analyze_rule(analyzer, rule) -> None:
    analyzer._current_rule = rule
    if "private" in rule.modifiers:
        analyzer.metrics.private_rules += 1
    if "global" in rule.modifiers:
        analyzer.metrics.global_rules += 1
    if rule.strings:
        analyzer.metrics.rules_with_strings += 1
        analyze_strings(analyzer, rule)
    if rule.meta:
        analyzer.metrics.rules_with_meta += 1
    if rule.tags:
        analyzer.metrics.rules_with_tags += 1
    if rule.condition:
        analyzer._current_depth = 0
        analyzer.visit(rule.condition)
        rule_max_depth = max(analyzer._condition_depths) if analyzer._condition_depths else 0
        analyzer.metrics.max_condition_depth = max(
            analyzer.metrics.max_condition_depth, rule_max_depth
        )
        analyzer.metrics.cyclomatic_complexity[rule.name] = calculate_cyclomatic_complexity(
            analyzer
        )
        if rule_max_depth > 6 or analyzer.metrics.cyclomatic_complexity[rule.name] > 10:
            analyzer.metrics.complex_rules.append(rule.name)


def analyze_strings(analyzer, rule) -> None:
    for string_def in rule.strings:
        analyzer.metrics.total_strings += 1
        analyzer._rule_strings.setdefault(rule.name, set()).add(string_def.identifier)
        if isinstance(string_def, PlainString):
            analyzer.metrics.plain_strings += 1
            if string_def.modifiers:
                analyzer.metrics.strings_with_modifiers += 1
        elif isinstance(string_def, HexString):
            analyzer.metrics.hex_strings += 1
            if string_def.modifiers:
                analyzer.metrics.strings_with_modifiers += 1
            analyze_hex_tokens(analyzer, string_def.tokens)
        elif isinstance(string_def, RegexString):
            analyzer.metrics.regex_strings += 1
            if string_def.modifiers:
                analyzer.metrics.strings_with_modifiers += 1
            analyze_regex_complexity(analyzer, string_def.regex)


def analyze_hex_tokens(analyzer, tokens: list) -> None:
    from yaraast.ast.strings import HexAlternative, HexJump, HexWildcard

    for token in tokens:
        if isinstance(token, HexWildcard):
            analyzer.metrics.hex_wildcards += 1
        elif isinstance(token, HexJump):
            analyzer.metrics.hex_jumps += 1
        elif isinstance(token, HexAlternative):
            analyzer.metrics.hex_alternatives += 1


def analyze_regex_complexity(analyzer, regex: str) -> None:
    analyzer.metrics.regex_groups += len(re.findall(r"\([^?]", regex))
    analyzer.metrics.regex_quantifiers += len(re.findall(r"[*+?{]", regex))


def calculate_cyclomatic_complexity(analyzer) -> int:
    from yaraast.metrics.complexity_helpers import calculate_cyclomatic_complexity as calc_from_expr

    rule = analyzer._current_rule
    if rule and rule.condition:
        return calc_from_expr(rule.condition)
    return 1


def calculate_derived_metrics(analyzer) -> None:
    if analyzer._condition_depths:
        analyzer.metrics.avg_condition_depth = sum(analyzer._condition_depths) / len(
            analyzer._condition_depths
        )
    for rule_name, string_ids in analyzer._rule_strings.items():
        used_strings = analyzer._string_usage.get(rule_name, set())
        for unused_string in string_ids - used_strings:
            analyzer.metrics.unused_strings.append(f"{rule_name}:{unused_string}")
    for rule_name, string_ids in analyzer._string_usage.items():
        if string_ids:
            analyzer.metrics.string_dependencies[rule_name] = string_ids
