"""Lexer state container."""

from __future__ import annotations

from dataclasses import dataclass


@dataclass
class LexerState:
    text: str
    position: int = 0
    line: int = 1
    column: int = 1

    def reset(self, text: str) -> None:
        self.text = text
        self.position = 0
        self.line = 1
        self.column = 1
