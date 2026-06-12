"""AST-based best practices analyzer.

This module provides AST analysis for YARA rule best practices and optimization
suggestions. It's not a full linter but rather an AST-based analyzer that can
identify patterns and suggest improvements.
"""

from __future__ import annotations

from collections import Counter
from dataclasses import dataclass, field
from fnmatch import fnmatchcase
import re
from typing import TYPE_CHECKING, Any

from yaraast.analysis.best_practices_helpers import (
    analyze_global_patterns,
    get_hex_prefix,
    levenshtein_distance,
)
from yaraast.ast.base import ASTNode, YaraFile, require_string
from yaraast.ast.expressions import (
    Identifier,
    ParenthesesExpression,
    SetExpression,
    StringIdentifier,
    StringLiteral,
    StringWildcard,
)
from yaraast.ast.rules import Rule
from yaraast.ast.strings import HexString, PlainString, RegexString
from yaraast.metrics.string_diagrams_common import plain_value_length
from yaraast.shared.local_scope import local_name_variants
from yaraast.string_references import normalize_string_reference_id
from yaraast.visitor.base import BaseVisitor

if TYPE_CHECKING:
    from yaraast.ast.conditions import AtExpression, ForOfExpression, InExpression, OfExpression
    from yaraast.ast.expressions import StringCount, StringLength, StringOffset


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
        severity = require_string(severity, "AnalysisReport severity")
        return [s for s in self.suggestions if s.severity == severity]

    def get_by_category(self, category: str) -> list[Suggestion]:
        """Get suggestions by category."""
        category = require_string(category, "AnalysisReport category")
        return [s for s in self.suggestions if s.category == category]


class BestPracticesAnalyzer(BaseVisitor[None]):
    """Analyzes YARA rules for best practice compliance.

    Examples:
        >>> from yaraast.parser import Parser
        >>> from yaraast.analysis.best_practices import BestPracticesAnalyzer
        >>> ast = Parser().parse('rule test { condition: true }')
        >>> analyzer = BestPracticesAnalyzer()
        >>> report = analyzer.analyze(ast)
        >>> len(report.suggestions) >= 0
        True
    """

    _LOCAL_WITHOUT_VALUE = object()
    _MISSING_LOCAL = object()

    def __init__(self) -> None:
        self.report = AnalysisReport()
        self._current_rule: Rule | None = None
        self._string_usage: dict[str, int] = {}
        self._hex_patterns: list[tuple[str, HexString]] = []
        self._local_scopes: list[dict[str, object]] = []

    def analyze(self, ast: YaraFile) -> AnalysisReport:
        """Analyze AST and return report."""
        self.report = AnalysisReport()
        self._current_rule = None
        self._string_usage.clear()
        self._hex_patterns.clear()
        self._local_scopes.clear()
        self.visit(ast)
        self._analyze_global_patterns()
        return self.report

    def visit_yara_file(self, node: YaraFile) -> None:
        """Analyze file-level patterns."""
        # Check for duplicate rule names
        rule_names = [self._validate_rule_name(rule.name) for rule in node.rules]
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
        rule_name = self._validate_rule_name(node.name)
        self._current_rule = node
        self._string_usage.clear()
        self._local_scopes.clear()

        # Check rule name conventions - must start with letter, no leading numbers
        # Also check for numbers immediately after letters (bad123name pattern)
        if (
            not re.match(r"^[a-zA-Z][a-zA-Z_]*$", rule_name)
            or rule_name.startswith("_")
            or re.search(r"[a-zA-Z]\d", rule_name)
        ):
            self.report.add_suggestion(
                rule_name,
                "style",
                "warning",
                "Rule name should start with letter and contain only alphanumeric/underscore",
            )

        # Check for very short rule names
        if len(rule_name) < 3:
            self.report.add_suggestion(
                rule_name,
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
        if not node.strings and node.condition is not None:
            # Only suggest if it's not using imports or file properties
            condition_str = str(node.condition)
            if not any(
                term in condition_str for term in ["filesize", "entrypoint", "pe.", "elf.", "math."]
            ):
                self.report.add_suggestion(
                    rule_name,
                    "style",
                    "info",
                    "Rule has no strings defined; verify that non-string-only matching is intentional",
                )

        # Visit condition to track string usage
        try:
            if node.condition is not None:
                self.visit(node.condition)
                self._check_unused_strings(node)
        finally:
            self._local_scopes.clear()

    def _analyze_strings(self, rule: Rule) -> None:
        """Analyze string definitions for patterns."""
        string_names = []

        for string_def in rule.strings:
            string_id = self._validate_string_identifier(string_def.identifier)

            # Check string naming conventions
            if not re.match(r"^\$[a-zA-Z]\w*$", string_id):
                self.report.add_suggestion(
                    rule.name,
                    "style",
                    "warning",
                    f"String identifier '{string_id}' should follow $name convention",
                    f"string {string_id}",
                )

            string_names.append(string_id)

            # Analyze specific string types
            if isinstance(string_def, PlainString):
                self._analyze_plain_string(rule, string_def)
            elif isinstance(string_def, HexString):
                self._analyze_hex_string(rule, string_def)
                self._hex_patterns.append((string_id, string_def))
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
        if not isinstance(string.value, str | bytes):
            raise TypeError("Plain string value must be text or bytes")
        pattern_chars = b"*?[]" if isinstance(string.value, bytes) else "*?[]"
        value_length = plain_value_length(string.value)

        # Check for very short strings without modifiers
        if value_length < 4 and not string.modifiers:
            self.report.add_suggestion(
                rule.name,
                "optimization",
                "info",
                f"Short string '{string.identifier}' ({value_length} bytes) might cause false positives",
                f"string {string.identifier}",
            )

        # Check for strings that might benefit from regex
        if any(pattern in string.value for pattern in pattern_chars):
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
        from yaraast.ast.strings import HexWildcard

        wildcards = sum(1 for token in string.tokens if isinstance(token, HexWildcard))

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
        if not isinstance(string.regex, str):
            raise TypeError("Regex value must be a string")

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
        defined_strings = {self._normalize_string_id(s.identifier) for s in rule.strings}
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

    def _mark_string_usage(self, string_id: str) -> None:
        normalized = self._normalize_string_id(string_id)
        self._string_usage[normalized] = self._string_usage.get(normalized, 0) + 1

    def _mark_condition_string_usage(self, string_id: str) -> None:
        normalized = self._normalize_string_id(string_id)
        if self._is_local(normalized):
            return
        self._mark_string_usage(normalized)

    def _mark_string_identifier_usage(self, string_id: str) -> None:
        self._mark_condition_string_usage(string_id)

    def _normalize_string_id(self, string_id: str) -> str:
        return normalize_string_reference_id(string_id)

    def _mark_string_set_text(self, text: str) -> None:
        if text == "them":
            self._mark_all_current_rule_strings()
            return

        normalized = self._normalize_string_id(text)
        local_value = self._local_value(normalized)
        if local_value is not self._MISSING_LOCAL:
            if local_value is not self._LOCAL_WITHOUT_VALUE:
                self._visit_string_set_value(local_value)
            return
        if "*" in text and not text.startswith("$"):
            return
        if "*" in normalized:
            self._mark_wildcard_usage(normalized)
            return

        self._mark_string_usage(normalized)

    def _mark_wildcard_usage(self, pattern: str) -> None:
        if not self._current_rule:
            self._mark_string_usage(pattern)
            return

        if pattern == "$*":
            self._mark_all_current_rule_strings()
            return

        matched = False
        for string_def in self._current_rule.strings:
            if getattr(string_def, "is_anonymous", False):
                continue
            if fnmatchcase(self._normalize_string_id(string_def.identifier), pattern):
                self._mark_string_usage(string_def.identifier)
                matched = True

        if not matched:
            self._mark_string_usage(pattern)

    def _mark_all_current_rule_strings(self) -> None:
        if not self._current_rule:
            return

        for string_def in self._current_rule.strings:
            self._mark_string_usage(string_def.identifier)

    def _visit_ast_value(self, value: Any) -> None:
        if hasattr(value, "accept"):
            self.visit(value)
            return
        if isinstance(value, list | tuple | set | frozenset):
            for item in value:
                self._visit_ast_value(item)

    def _visit_string_set_value(self, string_set: Any) -> None:
        if isinstance(string_set, str):
            self._mark_string_set_text(string_set)
            return
        if isinstance(string_set, list | tuple | set | frozenset):
            for item in string_set:
                self._visit_string_set_value(item)
            return
        if isinstance(string_set, Identifier):
            name = require_string(string_set.name, "String set identifier")
            if name == "them":
                self._mark_all_current_rule_strings()
                return
            if name.startswith("$"):
                self._mark_string_set_text(name)
                return
            self._visit_ast_value(string_set)
            return
        if isinstance(string_set, StringLiteral):
            self._mark_string_set_text(string_set.value)
            return
        if isinstance(string_set, StringIdentifier):
            self._mark_string_set_text(string_set.name)
            return
        if isinstance(string_set, StringWildcard):
            self._mark_string_set_text(string_set.pattern)
            return
        if isinstance(string_set, ParenthesesExpression):
            self._visit_string_set_value(string_set.expression)
            return
        if isinstance(string_set, SetExpression):
            for element in string_set.elements:
                self._visit_string_set_value(element)
            return
        self._visit_ast_value(string_set)

    def visit_string_identifier(self, node: StringIdentifier) -> None:
        """Track string usage."""
        self._mark_string_identifier_usage(node.name)

    def visit_string_wildcard(self, node: StringWildcard) -> None:
        self._mark_string_set_text(node.pattern)

    def visit_string_count(self, node: StringCount) -> None:
        self._mark_condition_string_usage(node.string_id)

    def visit_string_offset(self, node: StringOffset) -> None:
        self._mark_condition_string_usage(node.string_id)
        super().visit_string_offset(node)

    def visit_string_length(self, node: StringLength) -> None:
        self._mark_condition_string_usage(node.string_id)
        super().visit_string_length(node)

    def visit_at_expression(self, node: AtExpression) -> None:
        if isinstance(node.string_id, str):
            self._mark_condition_string_usage(node.string_id)
        super().visit_at_expression(node)

    def visit_in_expression(self, node: InExpression) -> None:
        if isinstance(node.subject, str):
            self._mark_condition_string_usage(node.subject)
        elif isinstance(node.subject, ASTNode):
            self.visit(node.subject)
        else:
            self._mark_condition_string_usage(node.subject)
        if not isinstance(node.range, ASTNode):
            msg = "'in' range must be an AST node"
            raise TypeError(msg)
        self.visit(node.range)

    def visit_for_of_expression(self, node: ForOfExpression) -> None:
        self._visit_ast_value(node.quantifier)
        self._visit_string_set_value(node.string_set)
        if node.condition is not None:
            self.visit(node.condition)

    def visit_of_expression(self, node: OfExpression) -> None:
        self._visit_ast_value(node.quantifier)
        self._visit_string_set_value(node.string_set)

    def visit_for_expression(self, node: Any) -> None:
        self._visit_ast_value(node.quantifier)
        self.visit(node.iterable)
        self._push_local_scope(node.variable)
        try:
            self.visit(node.body)
        finally:
            self._pop_local_scope()

    def visit_with_statement(self, node: Any) -> None:
        self._push_local_scope()
        try:
            for declaration in node.declarations:
                self.visit(declaration)
            self.visit(node.body)
        finally:
            self._pop_local_scope()

    def visit_with_declaration(self, node: Any) -> None:
        self._visit_ast_value(node.value)
        self._define_local(node.identifier, node.value)

    def visit_array_comprehension(self, node: Any) -> None:
        self._visit_ast_value(node.iterable)
        self._push_local_scope(node.variable)
        try:
            self._visit_ast_value(node.condition)
            self._visit_ast_value(node.expression)
        finally:
            self._pop_local_scope()

    def visit_dict_comprehension(self, node: Any) -> None:
        self._visit_ast_value(node.iterable)
        names = [node.key_variable]
        if node.value_variable:
            names.append(node.value_variable)
        self._push_local_scope(*names)
        try:
            self._visit_ast_value(node.condition)
            self._visit_ast_value(node.key_expression)
            self._visit_ast_value(node.value_expression)
        finally:
            self._pop_local_scope()

    def visit_lambda_expression(self, node: Any) -> None:
        self._push_local_scope(*node.parameters)
        try:
            self._visit_ast_value(node.body)
        finally:
            self._pop_local_scope()

    def _is_local(self, name: str) -> bool:
        return any(name in scope for scope in reversed(self._local_scopes))

    def _local_value(self, name: str) -> object:
        for scope in reversed(self._local_scopes):
            if name in scope:
                return scope[name]
        return self._MISSING_LOCAL

    def _push_local_scope(self, *names: str) -> None:
        scope: dict[str, object] = {}
        for name in names:
            for local_name in local_name_variants(name):
                scope[local_name] = self._LOCAL_WITHOUT_VALUE
        self._local_scopes.append(scope)

    def _pop_local_scope(self) -> None:
        self._local_scopes.pop()

    def _define_local(self, name: str, value: object = _LOCAL_WITHOUT_VALUE) -> None:
        if self._local_scopes:
            for local_name in local_name_variants(name, allow_string_identifier=True):
                self._local_scopes[-1][local_name] = value

    @staticmethod
    def _validate_rule_name(rule_name: object) -> str:
        if not isinstance(rule_name, str):
            raise TypeError("Rule name must be a string")
        return rule_name

    @staticmethod
    def _validate_string_identifier(string_id: object) -> str:
        if not isinstance(string_id, str):
            raise TypeError("String identifier must be a string")
        return string_id

    def _analyze_global_patterns(self) -> None:
        """Analyze patterns across all rules."""
        analyze_global_patterns(self)

    def _get_hex_prefix(self, hex_string: HexString, length: int) -> tuple[Any, ...]:
        """Get first N bytes of hex string for comparison."""
        return get_hex_prefix(hex_string, length)

    def _levenshtein_distance(self, s1: str, s2: str) -> int:
        """Calculate edit distance between two strings."""
        return levenshtein_distance(s1, s2)
