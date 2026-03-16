"""String pattern analyzer for YARA rules optimization."""

from __future__ import annotations

from dataclasses import dataclass
from typing import TYPE_CHECKING, Any

from yaraast.ast.strings import StringDefinition
from yaraast.performance.string_analysis_helpers import (
    analyze_cross_rule_patterns as helper_analyze_cross_rule_patterns,
)
from yaraast.performance.string_analysis_helpers import analyze_lengths as helper_analyze_lengths
from yaraast.performance.string_analysis_helpers import (
    categorize_patterns as helper_categorize_patterns,
)
from yaraast.performance.string_analysis_helpers import (
    find_common_prefixes as helper_find_common_prefixes,
)
from yaraast.performance.string_analysis_helpers import (
    find_common_suffixes as helper_find_common_suffixes,
)
from yaraast.performance.string_analysis_helpers import find_duplicates as helper_find_duplicates
from yaraast.performance.string_analysis_helpers import (
    find_optimizations as helper_find_optimizations,
)

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
        return helper_find_duplicates(self, strings)

    def _find_common_prefixes(
        self,
        strings: list[str],
        min_length: int = 3,
    ) -> dict[str, list[str]]:
        return helper_find_common_prefixes(self, strings, min_length)

    def _find_common_suffixes(
        self,
        strings: list[str],
        min_length: int = 3,
    ) -> dict[str, list[str]]:
        return helper_find_common_suffixes(self, strings, min_length)

    def _analyze_lengths(self, strings: list[str]) -> dict[str, Any]:
        return helper_analyze_lengths(strings)

    def _categorize_patterns(
        self,
        patterns: list[str | StringDefinition],
    ) -> dict[str, int]:
        return helper_categorize_patterns(self, patterns)

    def _find_optimizations(
        self,
        strings: list[str],
        duplicates: dict[str, int],
        prefixes: dict[str, list[str]],
        suffixes: dict[str, list[str]],
    ) -> list[dict[str, Any]]:
        return helper_find_optimizations(strings, duplicates, prefixes, suffixes)

    def _analyze_cross_rule_patterns(self, rules: list[Rule]) -> dict[str, Any]:
        return helper_analyze_cross_rule_patterns(rules)

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


def analyze_rule_performance(rule: Rule) -> list[StringPerformanceIssue]:
    from yaraast.performance.string_performance_checks import (
        analyze_rule_performance as helper_analyze_rule_performance,
    )

    return helper_analyze_rule_performance(rule)


def _estimate_rule_cost(rule: Rule) -> int:
    from yaraast.performance.string_performance_checks import estimate_rule_cost

    return estimate_rule_cost(rule)
