"""String performance analyzer for YARA rules."""

from dataclasses import dataclass

from yaraast.ast.rules import Rule
from yaraast.ast.strings import HexString, HexWildcard, PlainString, RegexString


@dataclass
class StringPerformanceIssue:
    """Performance issue found in a string."""

    rule_name: str
    string_id: str
    issue_type: str
    severity: str  # "warning", "critical"
    description: str
    suggestion: str | None = None


class StringPerformanceAnalyzer:
    """Analyze strings for potential performance issues."""

    def __init__(self):
        self.issues: list[StringPerformanceIssue] = []
        self.current_rule: str | None = None

    def analyze_rule(self, rule: Rule) -> list[StringPerformanceIssue]:
        """Analyze a single rule for performance issues."""
        self.issues = []
        self.current_rule = rule.name

        # Analyze all strings in the rule
        for string in rule.strings:
            if isinstance(string, HexString):
                self.analyze_hex_string(string)
            elif isinstance(string, PlainString):
                self.analyze_plain_string(string)
            elif isinstance(string, RegexString):
                self.analyze_regex_string(string)

        return self.issues

    def analyze_hex_string(self, node: HexString) -> None:
        """Analyze hex strings for performance issues."""
        if not node.tokens:
            return

        # Count wildcards
        wildcard_count = sum(1 for token in node.tokens if isinstance(token, HexWildcard))
        total_count = len(node.tokens)

        # High wildcard ratio can slow down scanning
        if total_count > 0:
            wildcard_ratio = wildcard_count / total_count

            if wildcard_ratio > 0.5 and total_count > 10:
                self.issues.append(
                    StringPerformanceIssue(
                        rule_name=self.current_rule,
                        string_id=node.identifier,
                        issue_type="high_wildcard_ratio",
                        severity="warning",
                        description=f"Hex string has {wildcard_ratio:.0%} wildcards ({wildcard_count}/{total_count})",
                        suggestion="Consider using more specific byte patterns to improve scanning speed",
                    )
                )

            # Many consecutive wildcards are particularly bad
            consecutive_wildcards = self._count_max_consecutive_wildcards(node.tokens)
            if consecutive_wildcards >= 4:
                self.issues.append(
                    StringPerformanceIssue(
                        rule_name=self.current_rule,
                        string_id=node.identifier,
                        issue_type="consecutive_wildcards",
                        severity="critical" if consecutive_wildcards >= 8 else "warning",
                        description=f"Hex string has {consecutive_wildcards} consecutive wildcards",
                        suggestion="Long wildcard sequences significantly slow down scanning",
                    )
                )

    def analyze_plain_string(self, node: PlainString) -> None:
        """Analyze plain strings for performance issues."""
        if not node.value:
            return

        # Very short strings can cause many false positives and slow scanning
        if len(node.value) <= 2:
            self.issues.append(
                StringPerformanceIssue(
                    rule_name=self.current_rule,
                    string_id=node.identifier,
                    issue_type="short_string",
                    severity="warning",
                    description=f"String is only {len(node.value)} character(s) long",
                    suggestion="Very short strings can cause many matches and slow down scanning",
                )
            )

        # Strings with only common characters are also problematic
        if len(node.value) > 0 and all(c in " \t\n\r\x00" for c in node.value):
            self.issues.append(
                StringPerformanceIssue(
                    rule_name=self.current_rule,
                    string_id=node.identifier,
                    issue_type="whitespace_only",
                    severity="warning",
                    description="String contains only whitespace or null characters",
                    suggestion="Whitespace-only strings match frequently and slow down scanning",
                )
            )

    def analyze_regex_string(self, node: RegexString) -> None:
        """Analyze regex strings for performance issues."""
        if not node.regex:
            return

        # Check for problematic regex patterns
        problematic_patterns = [
            (r".*", "greedy_match", "Greedy .* can cause excessive backtracking"),
            (r".+", "greedy_plus", "Greedy .+ can cause excessive backtracking"),
            (
                r"(.+)+",
                "catastrophic_backtrack",
                "Nested quantifiers can cause catastrophic backtracking",
            ),
            (
                r"(.*)*",
                "catastrophic_backtrack",
                "Nested quantifiers can cause catastrophic backtracking",
            ),
            (r"^.*", "unnecessary_anchor", "Leading .* with ^ anchor is redundant"),
        ]

        for pattern, issue_type, description in problematic_patterns:
            if pattern in node.regex:
                self.issues.append(
                    StringPerformanceIssue(
                        rule_name=self.current_rule,
                        string_id=node.identifier,
                        issue_type=issue_type,
                        severity="critical" if "catastrophic" in issue_type else "warning",
                        description=f"Regex contains '{pattern}': {description}",
                        suggestion="Optimize regex pattern to avoid backtracking",
                    )
                )

    def _count_max_consecutive_wildcards(self, tokens) -> int:
        """Count maximum consecutive wildcards in hex tokens."""
        max_consecutive = 0
        current_consecutive = 0

        for token in tokens:
            if isinstance(token, HexWildcard):
                current_consecutive += 1
                max_consecutive = max(max_consecutive, current_consecutive)
            else:
                current_consecutive = 0

        return max_consecutive


def analyze_rule_performance(rule: Rule) -> list[StringPerformanceIssue]:
    """Analyze a rule for performance issues."""
    analyzer = StringPerformanceAnalyzer()
    return analyzer.analyze_rule(rule)
