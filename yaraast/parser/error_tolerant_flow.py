"""Flow helpers for the error-tolerant parser."""

from __future__ import annotations

import re

from yaraast.ast.base import Location, YaraFile
from yaraast.ast.rules import Rule


def parse_with_recovery(parser) -> YaraFile:
    """Recover a YARA file by scanning line by line."""
    yara_file = YaraFile()
    yara_file.imports = []
    yara_file.includes = []
    yara_file.rules = []

    line_index = 0
    while line_index < len(parser.lines):
        line = parser.lines[line_index].strip()

        if not line or line.startswith(("//", "/*")):
            line_index += 1
            continue

        if line.startswith("import "):
            import_stmt = parser._parse_import_line(line, line_index)
            if import_stmt is not None:
                yara_file.imports.append(import_stmt)
            line_index += 1
            continue

        if line.startswith("include "):
            include_stmt = parser._parse_include_line(line, line_index)
            if include_stmt is not None:
                yara_file.includes.append(include_stmt)
            line_index += 1
            continue

        if line.startswith("rule ") or line.startswith("private ") or line.startswith("global "):
            rule, lines_consumed = parse_rule_with_recovery(parser, line_index)
            if rule is not None:
                yara_file.rules.append(rule)
                parser.recovered_rules.append(rule)
            line_index += lines_consumed
            continue

        parser._add_error(f"Unexpected line: {line}", line_index, 0)
        line_index += 1

    _set_yara_file_location(yara_file)
    return yara_file


def parse_rule_with_recovery(parser, start_line: int) -> tuple[Rule | None, int]:
    """Recover a single rule block."""
    line = parser.lines[start_line].strip()
    rule_name, tags, modifiers = extract_rule_header(parser, line, start_line)
    if not rule_name:
        return None, 1

    rule_body_lines, current_line = collect_rule_body(parser, start_line, line)
    rule = parser._create_rule_from_body(
        rule_name, tags, body_lines=rule_body_lines, start_line=start_line
    )
    rule.modifiers = Rule._normalize_modifiers(modifiers)
    return rule, current_line - start_line + 1


def extract_rule_header(parser, line: str, line_num: int) -> tuple[str | None, list, list[str]]:
    """Extract rule name and tags from a rule declaration."""
    match = re.match(
        r"(?P<modifiers>(?:(?:private|global)\s+)*)rule\s+(?P<name>\w+)"
        r"\s*(?:\:\s*(?P<tags>[^{]+))?\s*\{?",
        line,
        re.IGNORECASE,
    )
    if not match:
        parser._add_error(f"Invalid rule declaration: {line}", line_num, 0)
        return None, [], []

    rule_name = match.group("name")
    tags_str = match.group("tags")
    tags = [tag.strip() for tag in tags_str.split()] if tags_str else []
    modifiers = [modifier.lower() for modifier in match.group("modifiers").split()]
    return rule_name, tags, modifiers


def _skip_regex_literal(line: str, slash_index: int) -> int:
    """Return the index just past a ``/regex/`` literal opened at ``slash_index``."""
    i = slash_index + 1
    while i < len(line):
        ch = line[i]
        if ch == "\\" and i + 1 < len(line):
            i += 2
            continue
        if ch == "/":
            return i + 1
        i += 1
    return i


def _starts_regex_literal(line: str, slash_index: int) -> bool:
    """Decide whether a ``/`` opens a regex literal (``$id = /.../``) versus division."""
    preceding = line[:slash_index].rstrip()
    return preceding.endswith("=")


def _count_braces_outside_literals(line: str) -> int:
    """Count net brace balance ignoring braces inside strings, regexes, and comments."""
    count = 0
    in_string = False
    in_block_comment = False
    i = 0
    while i < len(line):
        ch = line[i]
        if in_block_comment:
            if ch == "*" and i + 1 < len(line) and line[i + 1] == "/":
                in_block_comment = False
                i += 2
                continue
        elif in_string:
            if ch == "\\" and i + 1 < len(line):
                i += 2
                continue
            if ch == '"':
                in_string = False
        elif ch == '"':
            in_string = True
        elif ch == "/" and i + 1 < len(line) and line[i + 1] == "/":
            break  # Rest of line is a line comment
        elif ch == "/" and i + 1 < len(line) and line[i + 1] == "*":
            in_block_comment = True
            i += 2
            continue
        elif ch == "/" and _starts_regex_literal(line, i):
            i = _skip_regex_literal(line, i)
            continue
        elif ch == "{":
            count += 1
        elif ch == "}":
            count -= 1
        i += 1
    return count


def collect_rule_body(parser, start_line: int, header_line: str) -> tuple[list[str], int]:
    """Collect all lines belonging to a rule body."""
    rule_body_lines: list[str] = []
    brace_count = _count_braces_outside_literals(header_line)
    current_line = start_line + 1

    while current_line < len(parser.lines) and (
        brace_count > 0 or (brace_count == 0 and not rule_body_lines)
    ):
        body_line = parser.lines[current_line]
        rule_body_lines.append(body_line)

        brace_count += _count_braces_outside_literals(body_line)
        if brace_count == 0:
            break
        current_line += 1

    return rule_body_lines, current_line


def _set_yara_file_location(yara_file: YaraFile) -> None:
    if not (yara_file.imports or yara_file.includes or yara_file.rules):
        return
    start_node = (
        yara_file.imports[0]
        if yara_file.imports
        else yara_file.includes[0] if yara_file.includes else yara_file.rules[0]
    )
    end_node = (
        yara_file.rules[-1]
        if yara_file.rules
        else yara_file.includes[-1] if yara_file.includes else yara_file.imports[-1]
    )
    start = start_node.location
    end = end_node.location
    if start is None or end is None:
        return
    yara_file.location = Location(
        line=start.line,
        column=start.column,
        end_line=end.end_line or end.line,
        end_column=end.end_column or (end.column + 1),
    )
