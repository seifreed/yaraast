"""Text and position helpers for LSP utilities."""

from __future__ import annotations

from lsprotocol.types import Position, Range


def position_to_offset(text: str, position: Position) -> int:
    lines = text.split("\n")
    offset = 0
    for i in range(position.line):
        if i < len(lines):
            offset += len(lines[i]) + 1
    if position.line < len(lines):
        offset += min(position.character, len(lines[position.line]))
    return offset


def offset_to_position(text: str, offset: int) -> Position:
    lines = text.split("\n")
    current_offset = 0
    for line_num, line in enumerate(lines):
        line_length = len(line) + 1
        if current_offset + line_length > offset:
            return Position(line=line_num, character=offset - current_offset)
        current_offset += line_length
    return Position(line=len(lines) - 1, character=len(lines[-1]) if lines else 0)


def get_word_at_position(text: str, position: Position) -> tuple[str, Range]:
    lines = text.split("\n")
    if position.line >= len(lines):
        return "", Range(start=position, end=position)

    line = lines[position.line]
    if position.character >= len(line):
        return "", Range(start=position, end=position)

    start = position.character
    end = position.character
    while start > 0 and (line[start - 1].isalnum() or line[start - 1] in "._$#@!"):
        start -= 1
    while end < len(line) and (line[end].isalnum() or line[end] in "._$#@!"):
        end += 1

    return (
        line[start:end],
        Range(
            start=Position(line=position.line, character=start),
            end=Position(line=position.line, character=end),
        ),
    )
