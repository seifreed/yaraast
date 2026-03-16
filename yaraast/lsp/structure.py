"""Shared structural scanners for YARA source text."""

from __future__ import annotations

from dataclasses import dataclass

from lsprotocol.types import Position, Range

SECTION_NAMES = ("meta", "strings", "condition", "events", "match", "outcome", "options")


@dataclass(frozen=True, slots=True)
class RuleTextRange:
    """Text range that covers one parsed rule in the source."""

    start: int
    end: int
    lines: list[str]

    @property
    def text(self) -> str:
        return "\n".join(self.lines[self.start : self.end + 1])


def split_lines(text: str) -> list[str]:
    return text.split("\n")


def find_line_containing(lines: list[str], text: str, start: int = 0) -> int:
    for idx in range(max(0, start), len(lines)):
        if text in lines[idx]:
            return idx
    return -1


def find_rule_start(lines: list[str], current_line: int) -> int:
    for idx in range(min(current_line, len(lines) - 1), -1, -1):
        if lines[idx].lstrip().startswith("rule "):
            return idx
    return -1


def find_rule_line(lines: list[str], rule_name: str) -> int:
    for idx, line in enumerate(lines):
        if f"rule {rule_name}" in line or f"rule {rule_name}:" in line:
            return idx
    return -1


def find_rule_end(lines: list[str], start_line: int) -> int:
    brace_depth = 0
    found_open = False
    in_string = False
    in_regex = False
    in_block_comment = False
    escape = False

    for line_idx in range(max(0, start_line), len(lines)):
        line = lines[line_idx]
        char_idx = 0
        while char_idx < len(line):
            char = line[char_idx]
            nxt = line[char_idx + 1] if char_idx + 1 < len(line) else ""

            if in_block_comment:
                if char == "*" and nxt == "/":
                    in_block_comment = False
                    char_idx += 2
                    continue
                char_idx += 1
                continue

            if not in_string and not in_regex:
                if char == "/" and nxt == "/":
                    break
                if char == "/" and nxt == "*":
                    in_block_comment = True
                    char_idx += 2
                    continue

            if escape:
                escape = False
                char_idx += 1
                continue

            if char == "\\" and (in_string or in_regex):
                escape = True
                char_idx += 1
                continue

            if not in_regex and char == '"':
                in_string = not in_string
                char_idx += 1
                continue

            if not in_string and char == "/":
                in_regex = not in_regex
                char_idx += 1
                continue

            if in_string or in_regex:
                char_idx += 1
                continue

            if char == "{":
                brace_depth += 1
                found_open = True
            elif char == "}":
                brace_depth -= 1
                if found_open and brace_depth == 0:
                    return line_idx
            char_idx += 1

    return len(lines) - 1


def get_rule_text_range(text: str, current_line: int) -> RuleTextRange | None:
    lines = split_lines(text)
    start_line = find_rule_start(lines, current_line)
    if start_line < 0:
        return None
    end_line = find_rule_end(lines, start_line)
    if end_line < start_line:
        return None
    return RuleTextRange(start=start_line, end=end_line, lines=lines)


def find_section_line(lines: list[str], section_header: str, start_line: int) -> int:
    for idx in range(max(0, start_line), len(lines)):
        stripped = lines[idx].strip()
        if stripped.startswith("rule ") and idx > start_line:
            return -1
        if stripped == section_header:
            return idx
    return -1


def find_string_line(lines: list[str], string_id: str, start: int = 0) -> int:
    for idx in range(max(0, start), len(lines)):
        line = lines[idx]
        if f"{string_id} =" in line or f"{string_id}=" in line:
            return idx
    return -1


def find_section_range(
    lines: list[str],
    section_name: str,
    rule_line: int,
    rule_end: int,
) -> Range | None:
    section_line = find_line_containing(lines, f"{section_name}:", rule_line)
    if section_line < 0:
        return None
    next_line = rule_end
    for candidate in SECTION_NAMES:
        if candidate == section_name:
            continue
        candidate_line = find_line_containing(lines, f"{candidate}:", section_line + 1)
        if candidate_line >= 0 and candidate_line <= rule_end:
            next_line = min(next_line, candidate_line - 1)
    end_line = max(section_line, next_line)
    if end_line == rule_end and lines[rule_end].strip() == "}":
        end_line -= 1
    if end_line <= section_line:
        return None
    return Range(
        start=Position(line=section_line, character=0),
        end=Position(line=end_line, character=len(lines[end_line])),
    )


def find_section_header_range(lines: list[str], section_name: str, line_num: int) -> Range:
    line = lines[line_num]
    start = line.find(section_name)
    if start < 0:
        return make_range(line_num, 0, len(line))
    return make_range(line_num, start, start + len(section_name))


def find_quoted_value_range(lines: list[str], line_num: int, value: str) -> Range | None:
    if line_num < 0 or line_num >= len(lines):
        return None
    quoted = f'"{value}"'
    line = lines[line_num]
    start = line.find(quoted)
    if start < 0:
        return None
    return make_range(line_num, start + 1, start + 1 + len(value))


def make_range(line: int, start: int, end: int) -> Range:
    return Range(
        start=Position(line=line, character=start),
        end=Position(line=line, character=end),
    )
