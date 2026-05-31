"""Shared structural scanners for YARA source text."""

from __future__ import annotations

from dataclasses import dataclass
import re

from lsprotocol.types import Position, Range

from yaraast.lsp.utf16 import utf8_col_to_utf16

SECTION_NAMES = ("meta", "strings", "condition", "events", "match", "outcome", "options")
RULE_DECLARATION_RE = re.compile(r"\s*(?:(?:global|private)\s+)*rule\s+")
REGEX_CONTEXT_CHARS = frozenset("([{,=!:<>~&|?+-*")
REGEX_CONTEXT_WORDS = frozenset({"matches", "contains", "and", "or", "not", "condition"})


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
        if RULE_DECLARATION_RE.match(lines[idx]):
            return idx
    return -1


def find_rule_line(lines: list[str], rule_name: str) -> int:
    pattern = re.compile(
        rf"\s*(?:(?:global|private)\s+)*rule\s+{re.escape(rule_name)}(?![A-Za-z0-9_])"
    )
    for idx, line in enumerate(lines):
        if pattern.match(line):
            return idx
    return -1


def _previous_significant_char(line: str, index: int) -> str | None:
    for char in reversed(line[:index]):
        if not char.isspace():
            return char
    return None


def _previous_significant_word(line: str, index: int) -> str | None:
    end = index
    while end > 0 and line[end - 1].isspace():
        end -= 1
    start = end
    while start > 0 and (line[start - 1].isalnum() or line[start - 1] == "_"):
        start -= 1
    if start == end:
        return None
    return line[start:end].lower()


def _starts_regex_literal(line: str, index: int) -> bool:
    if line[index] != "/":
        return False
    if index + 1 < len(line) and line[index + 1] in {"/", "*"}:
        return False
    previous = _previous_significant_char(line, index)
    if previous is None or previous in REGEX_CONTEXT_CHARS:
        return True
    word = _previous_significant_word(line, index)
    return word in REGEX_CONTEXT_WORDS


def _is_identifier_char(char: str) -> bool:
    return char.isalnum() or char == "_"


def _scan_visible_section_header(
    line: str,
    section_name: str,
    in_block_comment: bool,
) -> tuple[int | None, bool]:
    in_string = False
    in_regex = False
    escape = False
    char_idx = 0
    section_header = f"{section_name}:"

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
            if in_regex:
                in_regex = False
            elif _starts_regex_literal(line, char_idx):
                in_regex = True
            char_idx += 1
            continue

        if (
            not in_string
            and not in_regex
            and line.startswith(section_header, char_idx)
            and (char_idx == 0 or not _is_identifier_char(line[char_idx - 1]))
        ):
            return char_idx, in_block_comment

        char_idx += 1

    return None, in_block_comment


def find_section_header_position(
    lines: list[str],
    section_name: str,
    start_line: int,
    end_line: int | None = None,
) -> tuple[int, int] | None:
    in_block_comment = False
    stop_line = len(lines) - 1 if end_line is None else min(end_line, len(lines) - 1)
    for line_num in range(max(0, start_line), stop_line + 1):
        column, in_block_comment = _scan_visible_section_header(
            lines[line_num], section_name, in_block_comment
        )
        if column is not None:
            return (line_num, column)
    return None


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
                if in_regex:
                    in_regex = False
                elif _starts_regex_literal(line, char_idx):
                    in_regex = True
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
        if RULE_DECLARATION_RE.match(stripped) and idx > start_line:
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
    section_position = find_section_header_position(lines, section_name, rule_line, rule_end)
    if section_position is None:
        return None
    section_line = section_position[0]
    next_line = rule_end
    for candidate in SECTION_NAMES:
        if candidate == section_name:
            continue
        candidate_position = find_section_header_position(
            lines, candidate, section_line + 1, rule_end
        )
        if candidate_position is not None:
            candidate_line = candidate_position[0]
            next_line = min(next_line, candidate_line - 1)
    end_line = max(section_line, next_line)
    if end_line == rule_end and lines[rule_end].strip() == "}":
        end_line -= 1
    if end_line <= section_line:
        return None
    return Range(
        start=Position(line=section_line, character=0),
        end=Position(
            line=end_line,
            character=utf8_col_to_utf16(lines[end_line], len(lines[end_line])),
        ),
    )


def find_section_header_range(
    lines: list[str],
    section_name: str,
    line_num: int,
    column: int | None = None,
) -> Range:
    line = lines[line_num]
    start = column if column is not None else line.find(section_name)
    if start < 0:
        return Range(
            start=Position(line=line_num, character=0),
            end=Position(line=line_num, character=utf8_col_to_utf16(line, len(line))),
        )
    return Range(
        start=Position(line=line_num, character=utf8_col_to_utf16(line, start)),
        end=Position(
            line=line_num,
            character=utf8_col_to_utf16(line, start + len(section_name)),
        ),
    )


def find_quoted_value_range(lines: list[str], line_num: int, value: str) -> Range | None:
    if line_num < 0 or line_num >= len(lines):
        return None
    quoted = f'"{value}"'
    line = lines[line_num]
    start = line.find(quoted)
    if start < 0:
        return None
    return Range(
        start=Position(line=line_num, character=utf8_col_to_utf16(line, start + 1)),
        end=Position(line=line_num, character=utf8_col_to_utf16(line, start + 1 + len(value))),
    )


def make_range(line: int, start: int, end: int) -> Range:
    return Range(
        start=Position(line=line, character=start),
        end=Position(line=line, character=end),
    )
