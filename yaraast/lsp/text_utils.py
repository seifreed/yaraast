"""Text and position helpers for LSP utilities."""

from __future__ import annotations

from lsprotocol.types import Position, Range

from yaraast.lsp.utf16 import utf8_col_to_utf16, utf16_col_to_utf8, utf16_len


def position_to_offset(text: str, position: Position) -> int:
    lines = text.split("\n")
    offset = 0
    for i in range(position.line):
        if i < len(lines):
            offset += len(lines[i]) + 1
    if position.line < len(lines):
        offset += utf16_col_to_utf8(lines[position.line], position.character)
    return offset


def offset_to_position(text: str, offset: int) -> Position:
    if isinstance(offset, bool) or not isinstance(offset, int):
        msg = "offset must be an integer"
        raise TypeError(msg)
    if offset < 0:
        msg = "offset must be non-negative"
        raise ValueError(msg)
    lines = text.split("\n")
    current_offset = 0
    for line_num, line in enumerate(lines):
        line_length = len(line) + 1
        if current_offset + line_length > offset:
            return Position(
                line=line_num,
                character=utf8_col_to_utf16(line, offset - current_offset),
            )
        current_offset += line_length
    return Position(line=len(lines) - 1, character=utf16_len(lines[-1]) if lines else 0)


def get_word_at_position(text: str, position: Position) -> tuple[str, Range]:
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
