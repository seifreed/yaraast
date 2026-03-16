"""AST-based best practices analyzer.

This module provides AST analysis for YARA rule best practices and optimization
suggestions. It's not a full linter but rather an AST-based analyzer that can
identify patterns and suggest improvements.
"""

from __future__ import annotations

import re
from collections import Counter
from dataclasses import dataclass, field
from typing import Any

from yaraast.analysis.best_practices_helpers import (
    analyze_global_patterns as helper_analyze_global_patterns,
)
from yaraast.analysis.best_practices_helpers import get_hex_prefix as helper_get_hex_prefix
from yaraast.analysis.best_practices_helpers import (
    levenshtein_distance as helper_levenshtein_distance,
)
from yaraast.ast.base import YaraFile
from yaraast.ast.expressions import StringIdentifier
from yaraast.ast.rules import Rule
from yaraast.ast.strings import HexString, PlainString, RegexString
from yaraast.visitor.base import BaseVisitor


@dataclass
class Suggestion:
    """A suggestion for improvement."""

    rule_name: str
    category: str  # 'style', 'optimization', 'structure'
    severity: str  # 'info', 'warning', 'error'
    message: str
    location: str | None = None

    def format(self) -> str:
        """Format suggestion for display."""
        prefix = {"info": "i", "warning": "⚠", "error": "✗"}.get(self.severity, "•")

        location = f" ({self.location})" if self.location else ""
        return f"{prefix} [{self.category}] {self.rule_name}{location}: {self.message}"


@dataclass
class AnalysisReport:
    """Report from best practices analysis."""

    suggestions: list[Suggestion] = field(default_factory=list)
    statistics: dict[str, int] = field(default_factory=dict)

    def add_suggestion(
        self,
        rule: str,
        category: str,
        severity: str,
        message: str,
        location: str | None = None,
    ) -> None:
        """Add a suggestion to the report."""
        self.suggestions.append(Suggestion(rule, category, severity, message, location))

    @property
    def has_issues(self) -> bool:
        """Check if there are any warnings or errors."""
        return any(s.severity in ("warning", "error") for s in self.suggestions)

    def get_by_severity(self, severity: str) -> list[Suggestion]:
        """Get suggestions by severity."""
        return [s for s in self.suggestions if s.severity == severity]

    def get_by_category(self, category: str) -> list[Suggestion]:
        """Get suggestions by category."""
        return [s for s in self.suggestions if s.category == category]


class BestPracticesAnalyzer(BaseVisitor[None]):
    """Analyze YARA AST for best practices and optimization opportunities."""

    def __init__(self) -> None:
        self.report = AnalysisReport()
        self._current_rule: Rule | None = None
        self._string_usage: dict[str, int] = {}
        self._hex_patterns: list[tuple[str, HexString]] = []

    def analyze(self, ast: YaraFile) -> AnalysisReport:
        """Analyze AST and return report."""
        self.report = AnalysisReport()
        self.visit(ast)
        self._analyze_global_patterns()
        return self.report

    def visit_yara_file(self, node: YaraFile) -> None:
        """Analyze file-level patterns."""
        # Check for duplicate rule names
        rule_names = [rule.name for rule in node.rules]
        duplicates = [name for name, count in Counter(rule_names).items() if count > 1]
        if duplicates:
            for dup in duplicates:
                self.report.add_suggestion(
                    dup,
                    "structure",
                    "error",
                    f"Duplicate rule name '{dup}'",
                )

        # Visit all rules
        for rule in node.rules:
            self.visit(rule)

        # Statistics
        self.report.statistics["total_rules"] = len(node.rules)
        self.report.statistics["total_imports"] = len(node.imports)

    def visit_rule(self, node: Rule) -> None:
        """Analyze individual rule."""
        self._current_rule = node
        self._string_usage.clear()
        self._hex_patterns.clear()

        # Check rule name conventions - must start with letter, no leading numbers
        # Also check for numbers immediately after letters (bad123name pattern)
        if (
            not re.match(r"^[a-zA-Z][a-zA-Z_]*$", node.name)
            or node.name.startswith("_")
            or re.search(r"[a-zA-Z]\d", node.name)
        ):
            self.report.add_suggestion(
                node.name,
                "style",
                "warning",
                "Rule name should start with letter and contain only alphanumeric/underscore",
            )

        # Check for very short rule names
        if len(node.name) < 3:
            self.report.add_suggestion(
                node.name,
                "style",
                "info",
                "Consider using more descriptive rule names (3+ characters)",
            )

        # Section order cannot be inferred reliably from the current AST shape.
        # Avoid emitting suggestions without structural evidence from source order.

        # Analyze strings
        if node.strings:
            self._analyze_strings(node)

        # Check for rules without strings (might be intentional)
        if not node.strings and node.condition:
            # Only suggest if it's not using imports or file properties
            condition_str = str(node.condition)
            if not any(
                term in condition_str for term in ["filesize", "entrypoint", "pe.", "elf.", "math."]
            ):
                self.report.add_suggestion(
                    node.name,
                    "style",
                    "info",
                    "Rule has no strings defined; verify that non-string-only matching is intentional",
                )

        # Visit condition to track string usage
        if node.condition:
            self.visit(node.condition)
            self._check_unused_strings(node)

    def _analyze_strings(self, rule: Rule) -> None:
        """Analyze string definitions for patterns."""
        string_names = []

        for string_def in rule.strings:
            # Check string naming conventions
            if not re.match(r"^\$[a-zA-Z]\w*$", string_def.identifier):
                self.report.add_suggestion(
                    rule.name,
                    "style",
                    "warning",
                    f"String identifier '{string_def.identifier}' should follow $name convention",
                    f"string {string_def.identifier}",
                )

            string_names.append(string_def.identifier)

            # Analyze specific string types
            if isinstance(string_def, PlainString):
                self._analyze_plain_string(rule, string_def)
            elif isinstance(string_def, HexString):
                self._analyze_hex_string(rule, string_def)
                self._hex_patterns.append((string_def.identifier, string_def))
            elif isinstance(string_def, RegexString):
                self._analyze_regex_string(rule, string_def)

        # Check for duplicate string names
        duplicates = [name for name, count in Counter(string_names).items() if count > 1]
        if duplicates:
            for dup in duplicates:
                self.report.add_suggestion(
                    rule.name,
                    "structure",
                    "error",
                    f"Duplicate string identifier '{dup}'",
                )

        # Check for very similar string names
        self._check_similar_names(rule, string_names)

    def _analyze_plain_string(self, rule: Rule, string: PlainString) -> None:
        """Analyze plain string patterns."""
        # Check for very short strings without modifiers
        if len(string.value) < 4 and not string.modifiers:
            self.report.add_suggestion(
                rule.name,
                "optimization",
                "info",
                f"Short string '{string.identifier}' ({len(string.value)} chars) might cause false positives",
                f"string {string.identifier}",
            )

        # Check for strings that might benefit from regex
        if any(pattern in string.value for pattern in ["*", "?", "[", "]"]):
            self.report.add_suggestion(
                rule.name,
                "optimization",
                "info",
                f"String '{string.identifier}' contains pattern characters - consider regex?",
                f"string {string.identifier}",
            )

    def _analyze_hex_string(self, rule: Rule, string: HexString) -> None:
        """Analyze hex string patterns."""
        # Count wildcards and jumps
        wildcards = sum(
            1
            for token in string.tokens
            if hasattr(token, "__class__") and token.__class__.__name__ == "HexWildcard"
        )

        # Too many wildcards might be inefficient
        if wildcards > len(string.tokens) * 0.5:
            self.report.add_suggestion(
                rule.name,
                "optimization",
                "warning",
                f"Hex string '{string.identifier}' has many wildcards - might be inefficient",
                f"string {string.identifier}",
            )

    def _analyze_regex_string(self, rule: Rule, string: RegexString) -> None:
        """Analyze regex patterns."""
        # Check for unescaped dots (common mistake)
        if "." in string.regex and r"\." not in string.regex:
            # Might be intentional, so just info
            self.report.add_suggestion(
                rule.name,
                "style",
                "info",
                f"Regex '{string.identifier}' contains unescaped dots - intentional?",
                f"string {string.identifier}",
            )

        # Check for catastrophic backtracking patterns
        dangerous_patterns = [
            r"(.+)+",
            r"(.+)*",
            r"(.*)+",
            r"(.+)?+",
            r"([^x]+)+",
            r"([^x]*)*",
        ]
        for pattern in dangerous_patterns:
            if pattern in string.regex:
                self.report.add_suggestion(
                    rule.name,
                    "optimization",
                    "warning",
                    f"Regex '{string.identifier}' might cause catastrophic backtracking",
                    f"string {string.identifier}",
                )
                break

    def _check_similar_names(self, rule: Rule, names: list[str]) -> None:
        """Check for very similar string names that might be confusing."""
        for i, name1 in enumerate(names):
            for name2 in names[i + 1 :]:
                # Simple edit distance check
                if self._levenshtein_distance(name1, name2) == 1:
                    self.report.add_suggestion(
                        rule.name,
                        "style",
                        "info",
                        f"Similar string names: '{name1}' and '{name2}' - potential confusion?",
                        "strings section",
                    )

    def _check_unused_strings(self, rule: Rule) -> None:
        """Check for defined but unused strings."""
        defined_strings = {s.identifier for s in rule.strings}
        used_strings = set(self._string_usage.keys())

        unused = defined_strings - used_strings
        for string_id in unused:
            self.report.add_suggestion(
                rule.name,
                "optimization",
                "warning",
                f"String '{string_id}' is defined but never used in condition",
                f"string {string_id}",
            )

    def visit_string_identifier(self, node: StringIdentifier) -> None:
        """Track string usage."""
        self._string_usage[node.name] = self._string_usage.get(node.name, 0) + 1

    def _analyze_global_patterns(self) -> None:
        """Analyze patterns across all rules."""
        helper_analyze_global_patterns(self)

    def _get_hex_prefix(self, hex_string: HexString, length: int) -> tuple[Any, ...]:
        """Get first N bytes of hex string for comparison."""
        return helper_get_hex_prefix(hex_string, length)

    def _levenshtein_distance(self, s1: str, s2: str) -> int:
        """Calculate edit distance between two strings."""
        return helper_levenshtein_distance(s1, s2)
