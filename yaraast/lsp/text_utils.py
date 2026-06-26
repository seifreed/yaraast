"""Text and position helpers for LSP utilities."""

from __future__ import annotations

from lsprotocol.types import Position, Range

from yaraast.lsp.utf16 import utf8_col_to_utf16, utf16_col_to_utf8, utf16_len


def _require_text(text: object) -> str:
    if not isinstance(text, str):
        msg = "text must be a string"
        raise TypeError(msg)
    return text


def _require_position(position: object) -> Position:
    if not isinstance(position, Position):
        msg = "position must be an LSP Position"
        raise TypeError(msg)
    return position


def get_word_at_position(text: str, position: Position) -> tuple[str, Range]:
    text = _require_text(text)
    position = _require_position(position)
    lines = text.split("\n")
    if position.line >= len(lines):
        return "", Range(start=position, end=position)

    line = lines[position.line]
    if position.character > utf16_len(line):
        return "", Range(start=position, end=position)

    position_character = utf16_col_to_utf8(line, position.character)
    start = position_character
    end = position_character
    while start > 0 and (line[start - 1].isalnum() or line[start - 1] in "._$#@!"):
        start -= 1
    while end < len(line) and (line[end].isalnum() or line[end] in "._$#@!"):
        end += 1

    return (
        line[start:end],
        Range(
            start=Position(line=position.line, character=utf8_col_to_utf16(line, start)),
            end=Position(line=position.line, character=utf8_col_to_utf16(line, end)),
        ),
    )
