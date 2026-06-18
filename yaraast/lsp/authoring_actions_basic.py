"""Basic line-oriented structural edits for authoring actions."""

from __future__ import annotations

from typing import TYPE_CHECKING

from lsprotocol.types import Position, Range, TextEdit

from yaraast.lsp.authoring_support import (
    PLAIN_STRING_RE,
    STRING_DEF_RE,
    modifier_start,
    normalize_modifiers,
)
from yaraast.lsp.utf16 import utf8_col_to_utf16

if TYPE_CHECKING:
    from yaraast.lsp.authoring_actions import StructuralEdit


def _whole_line_range(line_num: int, line: str) -> Range:
    return Range(
        start=Position(line=line_num, character=0),
        end=Position(line=line_num, character=utf8_col_to_utf16(line, len(line))),
    )


def _hex_escape_byte(value: str, position: int) -> int | None:
    hex_start = position + 2
    hex_digits = value[hex_start : hex_start + 2]
    if len(hex_digits) == 2 and all(char in "0123456789abcdefABCDEF" for char in hex_digits):
        return int(hex_digits, 16)
    return None


def _plain_string_source_bytes(value: str) -> bytes:
    decoded = bytearray()
    position = 0
    while position < len(value):
        char = value[position]
        if char != "\\":
            decoded.extend(char.encode("utf-8"))
            position += 1
            continue

        if position + 1 >= len(value):
            decoded.append(ord("\\"))
            position += 1
            continue

        next_char = value[position + 1]
        if next_char == "x":
            byte_value = _hex_escape_byte(value, position)
            if byte_value is not None:
                decoded.append(byte_value)
                position += 4
                continue
            decoded.extend(b"\\x")
        elif next_char == "n":
            decoded.append(0x0A)
        elif next_char == "r":
            decoded.append(0x0D)
        elif next_char == "t":
            decoded.append(0x09)
        elif next_char in {'"', "\\"}:
            decoded.append(ord(next_char))
        else:
            decoded.extend(f"\\{next_char}".encode())
        position += 2
    return bytes(decoded)


def create_missing_string(
    text: str, identifier: str, diagnostic_range: Range
) -> StructuralEdit | None:
    from yaraast.lsp.authoring_actions import StructuralEdit
    from yaraast.lsp.structure import find_rule_start, find_section_line

    lines = text.split("\n")
    rule_start = find_rule_start(lines, diagnostic_range.start.line)
    if rule_start < 0:
        return None
    condition_line = find_section_line(lines, "condition:", rule_start)
    if condition_line < 0:
        return None
    strings_line = find_section_line(lines, "strings:", rule_start)
    if strings_line >= 0:
        insert_line = strings_line + 1
        for idx in range(strings_line + 1, len(lines)):
            stripped = lines[idx].strip()
            if stripped.startswith("$"):
                insert_line = idx + 1
                continue
            if stripped.endswith(":") and not stripped.startswith("$"):
                break
        new_text = f'        {identifier} = ""\n'
    else:
        insert_line = condition_line
        new_text = f'    strings:\n        {identifier} = ""\n'
    pos = Position(line=insert_line, character=0)
    return StructuralEdit(
        title=f"Add string definition for {identifier}",
        edit=TextEdit(range=Range(start=pos, end=pos), new_text=new_text),
        preview=f"Insert {identifier} into {'strings' if strings_line >= 0 else 'new strings section'}",
    )


def normalize_string_modifiers(text: str, selection: Range) -> StructuralEdit | None:
    from yaraast.lsp.authoring_actions import StructuralEdit

    line_num = selection.start.line
    lines = text.split("\n")
    if line_num >= len(lines):
        return None
    line = lines[line_num]
    match = STRING_DEF_RE.match(line)
    if not match:
        return None
    body = match.group("body")
    start = modifier_start(body)
    if start is None:
        return None
    prefix = body[:start].rstrip()
    raw_modifiers = body[start:].split()
    if len(raw_modifiers) < 2:
        return None
    normalized = normalize_modifiers(raw_modifiers)
    if normalized == raw_modifiers:
        return None
    new_line = (
        f"{match.group('indent')}{match.group('identifier')} = {prefix} {' '.join(normalized)}"
    )
    return StructuralEdit(
        title="Normalize string modifiers",
        edit=TextEdit(
            range=_whole_line_range(line_num, line),
            new_text=new_line,
        ),
        preview="Deduplicate and reorder modifiers",
    )


def convert_plain_string_to_hex(text: str, selection: Range) -> StructuralEdit | None:
    from yaraast.lsp.authoring_actions import StructuralEdit

    line_num = selection.start.line
    lines = text.split("\n")
    if line_num >= len(lines):
        return None
    line = lines[line_num]
    match = STRING_DEF_RE.match(line)
    if not match:
        return None
    body = match.group("body")
    plain_match = PLAIN_STRING_RE.match(body)
    if not plain_match:
        return None
    tail = plain_match.group("tail").strip()
    if tail:
        return None
    value = plain_match.group("value")
    try:
        hex_bytes = " ".join(f"{byte:02X}" for byte in _plain_string_source_bytes(value))
    except UnicodeEncodeError:
        return None
    new_line = f"{match.group('indent')}{match.group('identifier')} = {{ {hex_bytes} }}"
    return StructuralEdit(
        title="Convert string to hex",
        edit=TextEdit(
            range=_whole_line_range(line_num, line),
            new_text=new_line,
        ),
        preview=f'"{value}" -> {{ {hex_bytes} }}',
    )
