"""Label helpers for string pattern diagrams."""

from __future__ import annotations

from typing import Any


class StringDiagramLabelsMixin:
    """Mixin providing string diagram helpers."""

    def _truncate(self, text: str, max_len: int) -> str:
        if len(text) <= max_len:
            return text
        return text[:max_len] + "..."

    def _label_lines(self, *lines: str) -> str:
        return "\\n".join(lines)

    def _create_pattern_label(self, pattern_info: dict[str, Any]) -> str:
        """Create label for plain string pattern."""
        identifier = pattern_info["identifier"]
        value = pattern_info.get("value", "")
        length = pattern_info.get("length", 0)

        # Truncate long values
        display_value = self._truncate(value, 20)

        return self._label_lines(identifier, f'"{display_value}"', f"Length: {length}")

    def _create_hex_pattern_label(self, pattern_info: dict[str, Any]) -> str:
        """Create label for hex pattern."""
        identifier = pattern_info["identifier"]
        tokens = pattern_info.get("tokens", 0)
        token_analysis = pattern_info.get("token_analysis", {})

        wildcards = token_analysis.get("wildcards", 0)
        wildcard_ratio = token_analysis.get("wildcard_ratio", 0)

        return f"{identifier}\\nTokens: {tokens}\\nWildcards: {wildcards} ({wildcard_ratio:.1%})"

    def _create_regex_pattern_label(self, pattern_info: dict[str, Any]) -> str:
        """Create label for regex pattern."""
        identifier = pattern_info["identifier"]
        pattern = pattern_info.get("pattern", "")
        regex_analysis = pattern_info.get("regex_analysis", {})

        # Truncate long patterns
        display_pattern = self._truncate(pattern, 15)
        groups = regex_analysis.get("groups", 0)

        return self._label_lines(identifier, f"/{display_pattern}/", f"Groups: {groups}")

    def _create_short_label(self, pattern_info: dict[str, Any]) -> str:
        """Create short label for similarity diagram."""
        return pattern_info["identifier"]

    def _create_hex_token_label(self, token_analysis: dict[str, Any]) -> str:
        """Create detailed hex token label."""
        bytes_count = token_analysis.get("bytes", 0)
        wildcards = token_analysis.get("wildcards", 0)
        jumps = token_analysis.get("jumps", 0)
        alternatives = token_analysis.get("alternatives", 0)

        return f"Bytes: {bytes_count}|Wildcards: {wildcards}|Jumps: {jumps}|Alternatives: {alternatives}"

    def _create_hex_complexity_label(
        self,
        pattern_info: dict[str, Any],
        token_analysis: dict[str, Any],
    ) -> str:
        """Create hex complexity metrics label."""
        complexity = self._calculate_pattern_complexity(pattern_info)
        wildcard_ratio = token_analysis.get("wildcard_ratio", 0)
        complexity_score = token_analysis.get("complexity_score", 0)

        return self._label_lines(
            f"Overall Complexity: {complexity}",
            f"Wildcard Ratio: {wildcard_ratio:.1%}",
            f"Token Score: {complexity_score}",
        )

    def _get_pattern_shape(self, pattern_type: str) -> str:
        """Get shape for pattern type."""
        if pattern_type == "plain":
            return "circle"
        if pattern_type == "hex":
            return "hexagon"
        return "ellipse"
