"""Statistics helpers for string pattern diagrams."""

from __future__ import annotations

from collections import Counter
from typing import Any


class StringDiagramStatsMixin:
    """Mixin providing string diagram helpers."""

    def get_pattern_statistics(self) -> dict[str, Any]:
        """Get comprehensive pattern statistics."""
        if not self.string_patterns:
            return {"total_patterns": 0}

        return {
            "total_patterns": len(self.string_patterns),
            "by_type": {
                "plain": len(
                    [p for p in self.string_patterns.values() if p["type"] == "plain"],
                ),
                "hex": len(
                    [p for p in self.string_patterns.values() if p["type"] == "hex"],
                ),
                "regex": len(
                    [p for p in self.string_patterns.values() if p["type"] == "regex"],
                ),
            },
            "complexity_distribution": self._get_complexity_distribution(),
            "common_patterns": self._find_common_patterns(),
            "pattern_lengths": self._get_length_statistics(),
            "modifiers_usage": self._get_modifier_statistics(),
        }

    def _get_complexity_distribution(self) -> dict[str, int]:
        """Get distribution of complexity scores."""
        distribution = {"low": 0, "medium": 0, "high": 0}

        for pattern_info in self.string_patterns.values():
            complexity = self._calculate_pattern_complexity(pattern_info)

            if complexity <= 3:
                distribution["low"] += 1
            elif complexity <= 6:
                distribution["medium"] += 1
            else:
                distribution["high"] += 1

        return distribution

    def _find_common_patterns(self) -> list[tuple[str, int]]:
        """Find most common pattern types/characteristics."""
        common = []

        # Most common modifiers
        common.extend(
            [("modifier_" + mod, count) for mod, count in self._modifier_counts().most_common(3)],
        )

        return common

    def _get_length_statistics(self) -> dict[str, float]:
        """Get pattern length statistics."""
        lengths = [pattern_info.get("length", 0) for pattern_info in self.string_patterns.values()]

        if not lengths:
            return {}

        return {
            "min": min(lengths),
            "max": max(lengths),
            "avg": sum(lengths) / len(lengths),
            "median": sorted(lengths)[len(lengths) // 2],
        }

    def _get_modifier_statistics(self) -> dict[str, int]:
        """Get modifier usage statistics."""
        return dict(self._modifier_counts())

    def _modifier_counts(self) -> Counter:
        modifier_counts = Counter()
        for pattern_info in self.string_patterns.values():
            for modifier in pattern_info.get("modifiers", []):
                modifier_counts[modifier] += 1
        return modifier_counts
