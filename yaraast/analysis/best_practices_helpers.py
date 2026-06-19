"""Helper algorithms for BestPracticesAnalyzer."""

from __future__ import annotations

from typing import Any

from yaraast.ast.strings import HexString


def get_hex_prefix(hex_string: HexString, length: int) -> tuple[Any, ...]:
    prefix = []
    for token in hex_string.tokens[:length]:
        prefix.append(token.value if hasattr(token, "value") else None)
    return tuple(prefix)


def levenshtein_distance(s1: str, s2: str) -> int:
    if len(s1) < len(s2):
        return levenshtein_distance(s2, s1)
    if len(s2) == 0:
        return len(s1)
    previous_row = list(range(len(s2) + 1))
    for i, c1 in enumerate(s1):
        current_row = [i + 1]
        for j, c2 in enumerate(s2):
            insertions = previous_row[j + 1] + 1
            deletions = current_row[j] + 1
            substitutions = previous_row[j] + (c1 != c2)
            current_row.append(min(insertions, deletions, substitutions))
        previous_row = current_row
    return previous_row[-1]
