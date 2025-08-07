"""String pattern analyzer for YARA rules optimization."""

from __future__ import annotations

from collections import Counter, defaultdict
from dataclasses import dataclass
from typing import TYPE_CHECKING, Any

from yaraast.ast.strings import HexString, PlainString, RegexString, StringDefinition

if TYPE_CHECKING:
    from yaraast.ast.base import YaraFile
    from yaraast.ast.rules import Rule


@dataclass
class StringPerformanceIssue:
    """Represents a performance issue with a string definition."""

    rule_name: str
    string_id: str
    issue_type: str
    severity: str  # "low", "medium", "high"
    description: str
    suggestion: str


class StringPatternAnalyzer:
    """Analyzes string patterns in YARA rules for optimization opportunities."""

    def __init__(self) -> None:
        """Initialize string pattern analyzer."""
        self._stats = {
            "total_strings": 0,
            "plain_strings": 0,
            "hex_strings": 0,
            "regex_strings": 0,
            "duplicate_values": 0,
            "common_prefixes": 0,
            "common_suffixes": 0,
        }

    def analyze_patterns(
        self,
        patterns: list[str | StringDefinition],
    ) -> dict[str, Any]:
        """Analyze a list of string patterns.

        Args:
            patterns: List of patterns (strings or StringDefinition objects)

        Returns:
            Analysis results

        """
        # Extract string values
        string_values = []
        for pattern in patterns:
            if isinstance(pattern, str):
                string_values.append(pattern)
            elif hasattr(pattern, "value"):
                string_values.append(pattern.value)

        self._stats["total_strings"] = len(string_values)

        # Analyze patterns
        duplicates = self._find_duplicates(string_values)
        prefixes = self._find_common_prefixes(string_values)
        suffixes = self._find_common_suffixes(string_values)
        lengths = self._analyze_lengths(string_values)

        return {
            "total": len(string_values),
            "duplicates": duplicates,
            "common_prefixes": prefixes,
            "common_suffixes": suffixes,
            "length_statistics": lengths,
            "pattern_types": self._categorize_patterns(patterns),
            "optimization_opportunities": self._find_optimizations(
                string_values,
                duplicates,
                prefixes,
                suffixes,
            ),
        }

    def analyze_rule(self, rule: Rule) -> dict[str, Any]:
        """Analyze strings in a single rule.

        Args:
            rule: Rule to analyze

        Returns:
            String analysis for the rule

        """
        if not rule.strings:
            return {"rule": rule.name, "strings": 0, "analysis": None}

        analysis = self.analyze_patterns(rule.strings)
        analysis["rule"] = rule.name

        return analysis

    def analyze_file(self, yara_file: YaraFile) -> dict[str, Any]:
        """Analyze all strings in a YARA file.

        Args:
            yara_file: YARA file to analyze

        Returns:
            Comprehensive string analysis

        """
        all_strings = []
        rule_analyses = []

        for rule in yara_file.rules:
            if rule.strings:
                all_strings.extend(rule.strings)
                rule_analyses.append(self.analyze_rule(rule))

        # Global analysis
        global_analysis = self.analyze_patterns(all_strings)

        # Cross-rule analysis
        cross_rule = self._analyze_cross_rule_patterns(yara_file.rules)

        return {
            "global": global_analysis,
            "per_rule": rule_analyses,
            "cross_rule": cross_rule,
            "statistics": self.get_statistics(),
        }

    def _find_duplicates(self, strings: list[str]) -> dict[str, int]:
        """Find duplicate string values."""
        counter = Counter(strings)
        duplicates = {s: count for s, count in counter.items() if count > 1}
        self._stats["duplicate_values"] = len(duplicates)
        return duplicates

    def _find_common_prefixes(
        self,
        strings: list[str],
        min_length: int = 3,
    ) -> dict[str, list[str]]:
        """Find common prefixes among strings."""
        prefixes = defaultdict(list)

        for string in strings:
            if len(string) >= min_length:
                for i in range(min_length, min(len(string), 20)):
                    prefix = string[:i]
                    prefixes[prefix].append(string)

        # Filter to common prefixes
        common = {prefix: strings for prefix, strings in prefixes.items() if len(strings) > 1}

        self._stats["common_prefixes"] = len(common)
        return common

    def _find_common_suffixes(
        self,
        strings: list[str],
        min_length: int = 3,
    ) -> dict[str, list[str]]:
        """Find common suffixes among strings."""
        suffixes = defaultdict(list)

        for string in strings:
            if len(string) >= min_length:
                for i in range(min_length, min(len(string), 20)):
                    suffix = string[-i:]
                    suffixes[suffix].append(string)

        # Filter to common suffixes
        common = {suffix: strings for suffix, strings in suffixes.items() if len(strings) > 1}

        self._stats["common_suffixes"] = len(common)
        return common

    def _analyze_lengths(self, strings: list[str]) -> dict[str, Any]:
        """Analyze string length distribution."""
        if not strings:
            return {
                "min": 0,
                "max": 0,
                "average": 0,
                "distribution": {},
            }

        lengths = [len(s) for s in strings]
        length_dist = Counter(lengths)

        return {
            "min": min(lengths),
            "max": max(lengths),
            "average": sum(lengths) / len(lengths),
            "distribution": dict(length_dist),
        }

    def _categorize_patterns(
        self,
        patterns: list[str | StringDefinition],
    ) -> dict[str, int]:
        """Categorize patterns by type."""
        categories = {
            "plain": 0,
            "hex": 0,
            "regex": 0,
            "other": 0,
        }

        for pattern in patterns:
            if isinstance(pattern, PlainString):
                categories["plain"] += 1
            elif isinstance(pattern, HexString):
                categories["hex"] += 1
            elif isinstance(pattern, RegexString):
                categories["regex"] += 1
            else:
                categories["other"] += 1

        self._stats["plain_strings"] = categories["plain"]
        self._stats["hex_strings"] = categories["hex"]
        self._stats["regex_strings"] = categories["regex"]

        return categories

    def _find_optimizations(
        self,
        strings: list[str],
        duplicates: dict[str, int],
        prefixes: dict[str, list[str]],
        suffixes: dict[str, list[str]],
    ) -> list[dict[str, Any]]:
        """Find optimization opportunities."""
        optimizations = []

        # Duplicate removal
        if duplicates:
            optimizations.append(
                {
                    "type": "duplicate_removal",
                    "impact": "high",
                    "description": f"Found {len(duplicates)} duplicate strings",
                    "strings": list(duplicates.keys()),
                },
            )

        # Prefix optimization
        if len(prefixes) > 5:
            optimizations.append(
                {
                    "type": "prefix_tree",
                    "impact": "medium",
                    "description": f"Found {len(prefixes)} common prefixes",
                    "prefixes": list(prefixes.keys())[:10],
                },
            )

        # String pooling
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

    def _analyze_cross_rule_patterns(self, rules: list[Rule]) -> dict[str, Any]:
        """Analyze patterns across multiple rules."""
        # Collect all strings with their rule associations
        string_to_rules = defaultdict(list)

        for rule in rules:
            if rule.strings:
                for string_def in rule.strings:
                    if hasattr(string_def, "value"):
                        string_to_rules[string_def.value].append(rule.name)

        # Find shared strings
        shared = {string: rules for string, rules in string_to_rules.items() if len(rules) > 1}

        return {
            "shared_strings": shared,
            "total_unique": len(string_to_rules),
            "total_shared": len(shared),
        }

    def get_statistics(self) -> dict[str, Any]:
        """Get analyzer statistics."""
        return dict(self._stats)

    def reset_statistics(self) -> None:
        """Reset analyzer statistics."""
        self._stats = {
            "total_strings": 0,
            "plain_strings": 0,
            "hex_strings": 0,
            "regex_strings": 0,
            "duplicate_values": 0,
            "common_prefixes": 0,
            "common_suffixes": 0,
        }


# Alias for compatibility
StringAnalyzer = StringPatternAnalyzer


def analyze_rule_performance(rule: Rule) -> list[StringPerformanceIssue]:
    """Analyze performance characteristics of a rule.

    Args:
        rule: Rule to analyze

    Returns:
        List of performance issues found

    """
    issues = []

    # Check for expensive patterns
    if rule.strings:
        for string_def in rule.strings:
            if isinstance(string_def, RegexString):
                issues.append(
                    StringPerformanceIssue(
                        rule_name=rule.name,
                        string_id=string_def.identifier,
                        issue_type="expensive_regex",
                        severity="warning",
                        description="Regular expression may have performance impact",
                        suggestion="Consider using plain strings or hex patterns when possible",
                    ),
                )
            elif isinstance(string_def, PlainString) and len(string_def.value) < 3:
                issues.append(
                    StringPerformanceIssue(
                        rule_name=rule.name,
                        string_id=string_def.identifier,
                        issue_type="short_string",
                        severity="info",
                        description="Very short string may cause false positives",
                        suggestion="Use longer, more specific strings when possible",
                    ),
                )

    return issues


def _estimate_rule_cost(rule: Rule) -> int:
    """Estimate computational cost of a rule."""
    cost = 0

    # String costs
    if rule.strings:
        for string_def in rule.strings:
            if isinstance(string_def, PlainString):
                cost += 1
            elif isinstance(string_def, HexString):
                cost += 2
            elif isinstance(string_def, RegexString):
                cost += 10

    # Condition complexity
    if rule.condition:
        condition_str = str(rule.condition)
        cost += condition_str.count(" and ") * 2
        cost += condition_str.count(" or ") * 2
        cost += condition_str.count("for ") * 5

    return cost
