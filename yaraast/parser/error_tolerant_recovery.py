"""Recovery helpers for the error-tolerant parser."""

from __future__ import annotations

import re
from typing import Any

from yaraast.ast.base import Location
from yaraast.ast.expressions import BooleanLiteral, Identifier
from yaraast.ast.meta import Meta
from yaraast.ast.rules import Import, Include, Rule
from yaraast.ast.strings import PlainString


def parse_import_line(parser, line: str, line_num: int) -> Import | None:
    match = re.match(r'import\s+"([^"]+)"', line)
    if match:
        node = Import(match.group(1))
        node.location = Location(
            line=line_num + 1,
            column=match.start(1) + 1,
            end_line=line_num + 1,
            end_column=match.end(1) + 1,
        )
        return node
    match = re.match(r"import\s+(\w+)", line)
    if match:
        node = Import(match.group(1))
        node.location = Location(
            line=line_num + 1,
            column=match.start(1) + 1,
            end_line=line_num + 1,
            end_column=match.end(1) + 1,
        )
        return node
    parser._add_error(f"Invalid import statement: {line}", line_num, 0)
    return None


def parse_include_line(parser, line: str, line_num: int) -> Include | None:
    match = re.match(r'include\s+"([^"]+)"', line)
    if match:
        node = Include(match.group(1))
        node.location = Location(
            line=line_num + 1,
            column=match.start(1) + 1,
            end_line=line_num + 1,
            end_column=match.end(1) + 1,
        )
        return node
    parser._add_error(f"Invalid include statement: {line}", line_num, 0)
    return None


def create_rule_from_body(
    parser, name: str, tags: list[str], body_lines: list[str], start_line: int = 0
) -> Rule:
    rule = Rule(name=name, condition=BooleanLiteral(True))
    rule.tags = tags
    rule.meta = []
    rule.strings = []
    header_text = parser.lines[start_line] if 0 <= start_line < len(parser.lines) else ""
    name_column = header_text.find(name) + 1 if name in header_text else 1
    end_line = start_line + max(len(body_lines) - 1, 0)
    end_text = (
        parser.lines[end_line]
        if 0 <= end_line < len(parser.lines)
        else (body_lines[-1] if body_lines else header_text)
    )
    rule.location = Location(
        line=start_line + 1, column=name_column, end_line=end_line + 1, end_column=len(end_text) + 1
    )
    section = None
    for offset, body_line in enumerate(body_lines, start=1):
        section = parse_body_line(parser, rule, body_line, section, start_line + offset)
    return rule


def parse_body_line(
    parser, rule: Rule, body_line: str, current_section: str | None, line_num: int
) -> str | None:
    stripped = body_line.strip()
    if stripped.startswith("meta:"):
        return "meta"
    if stripped.startswith("strings:"):
        return "strings"
    if stripped.startswith("condition:"):
        condition_text = stripped[10:].strip()
        if condition_text:
            rule.condition = parse_condition(parser, condition_text, line_num, body_line)
        return "condition"
    if not stripped or stripped.startswith("}"):
        return current_section
    parse_section_content(parser, rule, stripped, current_section, line_num, body_line)
    return current_section


def parse_section_content(
    parser, rule: Rule, line: str, section: str | None, line_num: int, raw_line: str
) -> None:
    if section == "meta":
        meta_item = parse_meta_line(parser, line, line_num, raw_line)
        if meta_item:
            rule.meta.append(meta_item)
    elif section == "strings":
        string_def = parse_string_line(parser, line, line_num, raw_line)
        if string_def:
            rule.strings.append(string_def)
    elif section == "condition":
        rule.condition = parse_condition(parser, line, line_num, raw_line)


def parse_meta_line(
    parser, line: str, line_num: int | None = None, raw_line: str | None = None
) -> Meta | None:
    for pattern, converter in (
        (r'(\w+)\s*=\s*"([^"]*)"', lambda m: m.group(2)),
        (r"(\w+)\s*=\s*(\d+)", lambda m: int(m.group(2))),
        (r"(\w+)\s*=\s*(true|false)", lambda m: m.group(2).lower() == "true"),
    ):
        match = re.match(pattern, line, re.IGNORECASE)
        if match:
            node = Meta(match.group(1), converter(match))
            set_recovered_location(parser, node, line_num, raw_line, match.start(1), match.end(2))
            return node
    return None


def parse_string_line(
    parser, line: str, line_num: int | None = None, raw_line: str | None = None
) -> PlainString | None:
    for pattern in (
        r'(\$\w+)\s*=\s*"([^"]*)"',
        r"(\$\w+)\s*=\s*{([^}]+)}",
        r"(\$\w+)\s*=\s*/([^/]+)/",
    ):
        match = re.match(pattern, line)
        if match:
            node = PlainString(identifier=match.group(1), value=match.group(2))
            set_recovered_location(
                parser, node, line_num, raw_line, match.start(1), match.end(2) + 1
            )
            return node
    return None


def parse_condition(
    parser, condition_text: str, line_num: int | None = None, raw_line: str | None = None
) -> Any:
    condition_text = condition_text.strip()
    if condition_text == "true":
        node = BooleanLiteral(True)
    elif condition_text == "false":
        node = BooleanLiteral(False)
    else:
        node = Identifier(condition_text)
    start = raw_line.find(condition_text) if raw_line else 0
    set_recovered_location(parser, node, line_num, raw_line, start, start + len(condition_text))
    return node


def set_recovered_location(
    parser, node: Any, line_num: int | None, raw_line: str | None, start_col: int, end_col: int
) -> Any:
    if line_num is None:
        return node
    if 0 <= line_num < len(parser.lines):
        line_text = raw_line if raw_line is not None else parser.lines[line_num]
    else:
        line_text = raw_line or ""
    actual_start = max(0, start_col)
    actual_end = max(actual_start + 1, min(len(line_text), end_col))
    node.location = Location(
        line=line_num + 1, column=actual_start + 1, end_line=line_num + 1, end_column=actual_end + 1
    )
    return node
