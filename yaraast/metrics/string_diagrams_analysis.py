"""Analysis helpers for string pattern diagrams."""

from __future__ import annotations

from collections import defaultdict
import re
from typing import TYPE_CHECKING, Any

from yaraast.ast.strings import HexString, PlainString, RegexString
from yaraast.metrics.string_diagrams_common import modifier_names

if TYPE_CHECKING:
    from yaraast.ast.base import YaraFile


class StringDiagramAnalysisMixin:
    """Mixin providing string diagram helpers."""

    def _analyze_patterns(self, ast: YaraFile) -> None:
        """Analyze all string patterns in the AST."""
        self.string_patterns.clear()
        self.pattern_relationships.clear()
        self.pattern_stats.clear()

        pattern_id = 0
        for rule in ast.rules:
            self._current_rule = rule.name

            for string_def in rule.strings:
                pattern_id += 1
                pid = f"pattern_{pattern_id}"

                pattern_info: dict[str, Any] = {
                    "id": pid,
                    "identifier": string_def.identifier,
                    "rule": rule.name,
                    "modifiers": modifier_names(string_def.modifiers),
                }

                if isinstance(string_def, PlainString):
                    pattern_info.update(
                        {
                            "type": "plain",
                            "value": string_def.value,
                            "length": len(string_def.value),
                            "printable_ratio": self._calculate_printable_ratio(
                                string_def.value,
                            ),
                        },
                    )

                elif isinstance(string_def, HexString):
                    token_analysis = self._analyze_hex_tokens(string_def.tokens)
                    pattern_info.update(
                        {
                            "type": "hex",
                            "tokens": len(string_def.tokens),
                            "token_analysis": token_analysis,
                            "length": len(string_def.tokens),
                        },
                    )

                elif isinstance(string_def, RegexString):
                    regex_analysis = self._analyze_regex_pattern(string_def.regex)
                    pattern_info.update(
                        {
                            "type": "regex",
                            "pattern": string_def.regex,
                            "regex_analysis": regex_analysis,
                            "length": len(string_def.regex),
                        },
                    )

                self.string_patterns[pid] = pattern_info

    def _analyze_hex_tokens(self, tokens: list) -> dict[str, Any]:
        """Analyze hex string tokens."""
        from yaraast.ast.strings import HexAlternative, HexByte, HexJump, HexWildcard

        analysis = {
            "bytes": 0,
            "wildcards": 0,
            "jumps": 0,
            "alternatives": 0,
            "wildcard_ratio": 0.0,
            "complexity_score": 0,
        }

        for token in tokens:
            if isinstance(token, HexByte):
                analysis["bytes"] += 1
            elif isinstance(token, HexWildcard):
                analysis["wildcards"] += 1
            elif isinstance(token, HexJump):
                analysis["jumps"] += 1
                analysis["complexity_score"] += 2
            elif isinstance(token, HexAlternative):
                analysis["alternatives"] += 1
                analysis["complexity_score"] += 3

        total_tokens = len(tokens)
        if total_tokens > 0:
            analysis["wildcard_ratio"] = analysis["wildcards"] / total_tokens

        analysis["complexity_score"] += analysis["wildcards"] * 0.5

        return analysis

    def _analyze_regex_pattern(self, pattern: str) -> dict[str, Any]:
        """Analyze regex pattern complexity."""
        analysis = {
            "groups": len(re.findall(r"\([^?]", pattern)),
            "quantifiers": len(re.findall(r"[*+?{]", pattern)),
            "anchors": len(re.findall(r"[\^$]", pattern)),
            "character_classes": len(re.findall(r"\[[^\]]+\]", pattern)),
            "complexity_score": 0,
        }

        # Calculate complexity score
        analysis["complexity_score"] = (
            analysis["groups"] * 2
            + analysis["quantifiers"]
            + analysis["character_classes"] * 1.5
            + analysis["anchors"] * 0.5
        )

        return analysis

    def _calculate_printable_ratio(self, text: str) -> float:
        """Calculate ratio of printable characters."""
        if not text:
            return 0.0

        printable_count = sum(1 for c in text if c.isprintable() and not c.isspace())
        return printable_count / len(text)

    def _calculate_pattern_complexity(self, pattern_info: dict[str, Any]) -> int:
        """Calculate overall pattern complexity score."""
        complexity = 1  # Base complexity

        if pattern_info["type"] == "plain":
            # Plain string complexity based on length and printability
            length = pattern_info.get("length", 0)
            printable_ratio = pattern_info.get("printable_ratio", 1.0)

            complexity += length // 10  # Length factor
            if printable_ratio < 0.8:
                complexity += 2  # Non-printable penalty

        elif pattern_info["type"] == "hex":
            # Hex complexity from token analysis
            token_analysis = pattern_info.get("token_analysis", {})
            complexity += int(token_analysis.get("complexity_score", 0))

        elif pattern_info["type"] == "regex":
            # Regex complexity from analysis
            regex_analysis = pattern_info.get("regex_analysis", {})
            complexity += int(regex_analysis.get("complexity_score", 0))

        # Modifier complexity
        complexity += len(pattern_info.get("modifiers", []))

        return complexity

    def _find_similar_patterns(self) -> dict[str, set[str]]:
        """Find groups of similar patterns."""
        groups = defaultdict(set)

        # Group by type first
        for pattern_id, pattern_info in self.string_patterns.items():
            pattern_type = pattern_info["type"]
            groups[pattern_type].add(pattern_id)

        # Further group by characteristics
        refined_groups = {}

        for group_type, pattern_ids in groups.items():
            if group_type == "plain":
                # Group plain strings by length ranges
                short_patterns = set()
                medium_patterns = set()
                long_patterns = set()

                for pid in pattern_ids:
                    length = self.string_patterns[pid].get("length", 0)
                    if length < 10:
                        short_patterns.add(pid)
                    elif length < 50:
                        medium_patterns.add(pid)
                    else:
                        long_patterns.add(pid)

                if short_patterns:
                    refined_groups["Short Plain"] = short_patterns
                if medium_patterns:
                    refined_groups["Medium Plain"] = medium_patterns
                if long_patterns:
                    refined_groups["Long Plain"] = long_patterns

            elif group_type == "hex":
                # Group hex patterns by wildcard ratio
                low_wildcard = set()
                high_wildcard = set()

                for pid in pattern_ids:
                    token_analysis = self.string_patterns[pid].get("token_analysis", {})
                    wildcard_ratio = token_analysis.get("wildcard_ratio", 0)

                    if wildcard_ratio < 0.3:
                        low_wildcard.add(pid)
                    else:
                        high_wildcard.add(pid)

                if low_wildcard:
                    refined_groups["Precise Hex"] = low_wildcard
                if high_wildcard:
                    refined_groups["Flexible Hex"] = high_wildcard

            else:  # regex
                refined_groups["Regex"] = pattern_ids

        return refined_groups

    def _calculate_similarity(
        self,
        pattern1: dict[str, Any],
        pattern2: dict[str, Any],
    ) -> float:
        """Calculate similarity between two patterns."""
        if pattern1["type"] != pattern2["type"]:
            return 0.0

        similarity = 0.0

        if pattern1["type"] == "plain":
            # Simple string similarity
            str1 = pattern1.get("value", "")
            str2 = pattern2.get("value", "")

            if len(str1) == 0 or len(str2) == 0:
                return 0.0

            # Simple Jaccard similarity on character level
            set1 = set(str1.lower())
            set2 = set(str2.lower())
            intersection = len(set1 & set2)
            union = len(set1 | set2)

            similarity = intersection / union if union > 0 else 0.0

        elif pattern1["type"] == "hex":
            # Compare hex token patterns
            tokens1 = pattern1.get("token_analysis", {})
            tokens2 = pattern2.get("token_analysis", {})

            # Compare wildcard ratios
            ratio1 = tokens1.get("wildcard_ratio", 0)
            ratio2 = tokens2.get("wildcard_ratio", 0)
            similarity = 1.0 - abs(ratio1 - ratio2)

        elif pattern1["type"] == "regex":
            # Simple regex similarity (could be enhanced)
            regex1 = pattern1.get("pattern", "")
            regex2 = pattern2.get("pattern", "")

            if len(regex1) == 0 or len(regex2) == 0:
                return 0.0

            # Character-level similarity
            set1 = set(regex1)
            set2 = set(regex2)
            intersection = len(set1 & set2)
            union = len(set1 | set2)

            similarity = intersection / union if union > 0 else 0.0

        return similarity
