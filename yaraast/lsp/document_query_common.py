"""Shared helpers for LSP document query modules."""

from __future__ import annotations


def whole_word_positions(line: str, word: str) -> list[int]:
    if not word:
        return []
    positions: list[int] = []
    col = 0
    while True:
        col = line.find(word, col)
        if col == -1:
            return positions
        left_ok = col == 0 or not (line[col - 1].isalnum() or line[col - 1] == "_")
        right_idx = col + len(word)
        right_ok = right_idx >= len(line) or not (
            line[right_idx].isalnum() or line[right_idx] == "_"
        )
        if left_ok and right_ok:
            positions.append(col)
        col += len(word)
