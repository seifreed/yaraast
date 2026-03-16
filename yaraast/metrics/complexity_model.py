"""Complexity metrics model and scoring helpers."""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any


@dataclass
class ComplexityMetrics:
    """Complexity metrics for YARA rules."""

    # File-level metrics
    total_rules: int = 0
    total_imports: int = 0
    total_includes: int = 0

    # Rule-level metrics
    rules_with_strings: int = 0
    rules_with_meta: int = 0
    rules_with_tags: int = 0
    private_rules: int = 0
    global_rules: int = 0

    # String complexity
    total_strings: int = 0
    plain_strings: int = 0
    hex_strings: int = 0
    regex_strings: int = 0
    strings_with_modifiers: int = 0

    # Condition complexity
    max_condition_depth: int = 0
    avg_condition_depth: float = 0.0
    total_binary_ops: int = 0
    total_unary_ops: int = 0
    for_expressions: int = 0
    for_of_expressions: int = 0
    of_expressions: int = 0

    # Pattern complexity
    hex_wildcards: int = 0
    hex_jumps: int = 0
    hex_alternatives: int = 0
    regex_groups: int = 0
    regex_quantifiers: int = 0

    # Quality metrics
    unused_strings: list[str] = field(default_factory=list)
    complex_rules: list[str] = field(default_factory=list)  # Rules exceeding heuristic thresholds
    cyclomatic_complexity: dict[str, int] = field(default_factory=dict)

    # Dependencies
    string_dependencies: dict[str, set[str]] = field(default_factory=dict)
    module_usage: dict[str, int] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        """Convert metrics to dictionary for serialization."""
        return {
            "analysis_kind": "heuristic",
            "heuristic": True,
            "file_metrics": {
                "total_rules": self.total_rules,
                "total_imports": self.total_imports,
                "total_includes": self.total_includes,
            },
            "rule_metrics": {
                "rules_with_strings": self.rules_with_strings,
                "rules_with_meta": self.rules_with_meta,
                "rules_with_tags": self.rules_with_tags,
                "private_rules": self.private_rules,
                "global_rules": self.global_rules,
            },
            "string_metrics": {
                "total_strings": self.total_strings,
                "plain_strings": self.plain_strings,
                "hex_strings": self.hex_strings,
                "regex_strings": self.regex_strings,
                "strings_with_modifiers": self.strings_with_modifiers,
            },
            "condition_metrics": {
                "max_condition_depth": self.max_condition_depth,
                "avg_condition_depth": self.avg_condition_depth,
                "total_binary_ops": self.total_binary_ops,
                "total_unary_ops": self.total_unary_ops,
                "for_expressions": self.for_expressions,
                "for_of_expressions": self.for_of_expressions,
                "of_expressions": self.of_expressions,
            },
            "pattern_metrics": {
                "hex_wildcards": self.hex_wildcards,
                "hex_jumps": self.hex_jumps,
                "hex_alternatives": self.hex_alternatives,
                "regex_groups": self.regex_groups,
                "regex_quantifiers": self.regex_quantifiers,
            },
            "quality_metrics": {
                "unused_strings": self.unused_strings,
                "complex_rules": self.complex_rules,
                "cyclomatic_complexity": self.cyclomatic_complexity,
            },
            "dependencies": {
                "string_dependencies": {k: list(v) for k, v in self.string_dependencies.items()},
                "module_usage": self.module_usage,
            },
        }

    def get_quality_score(self) -> float:
        """Calculate an overall heuristic quality score (0-100)."""
        score = 100.0

        # Deduct for complexity issues
        if self.max_condition_depth > 8:
            score -= 20
        elif self.max_condition_depth > 5:
            score -= 10

        # Deduct for unused strings
        if self.unused_strings:
            score -= min(20, len(self.unused_strings) * 5)

        # Deduct for very complex rules
        if self.complex_rules:
            score -= min(25, len(self.complex_rules) * 10)

        # Bonus for good practices
        if self.rules_with_meta / max(1, self.total_rules) > 0.8:
            score += 5

        return max(0.0, score)

    def get_complexity_grade(self) -> str:
        """Get a letter grade derived from the heuristic quality score."""
        score = self.get_quality_score()
        if score >= 90:
            return "A"
        if score >= 80:
            return "B"
        if score >= 70:
            return "C"
        if score >= 60:
            return "D"
        return "F"
