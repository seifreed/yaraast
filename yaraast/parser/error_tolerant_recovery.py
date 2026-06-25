"""Recovery helpers for the error-tolerant parser."""

from __future__ import annotations

import re
from typing import Any, cast

from yaraast.ast.base import Location
from yaraast.ast.expressions import BooleanLiteral, Identifier
from yaraast.ast.meta import Meta
from yaraast.ast.modifiers import StringModifier
from yaraast.ast.rules import Import, Include, Rule, Tag
from yaraast.ast.strings import HexString, PlainString, RegexString
from yaraast.errors import YaraASTError
from yaraast.parser.hex_parser import HexParseError, HexStringParser


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
    rule.tags = [Tag(name=tag) for tag in tags]
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
    parser._condition_parsed = False
    section = None
    for offset, body_line in enumerate(body_lines, start=1):
        section = parse_body_line(parser, rule, body_line, section, start_line + offset)
    if not parser._condition_parsed:
        # The rule body had no condition expression, so the placeholder
        # condition above stands in for it. Record the error instead of
        # silently emitting an always-true rule, which would change semantics.
        parser._add_error(f'rule "{name}" has no condition', start_line, 0)
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
            parser._condition_parsed = True
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
        parser._condition_parsed = True
    else:
        parser._add_error(f"Unexpected line outside any section: {line}", line_num, 0)


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
    parser._add_error(f"Invalid meta definition: {line}", line_num or 0, 0)
    return None


def parse_string_line(
    parser, line: str, line_num: int | None = None, raw_line: str | None = None
) -> PlainString | HexString | RegexString | None:
    standard_node = parse_string_line_with_standard_parser(line)
    if standard_node is not None:
        set_recovered_location(parser, standard_node, line_num, raw_line, 0, len(line))
        return standard_node

    plain_match = re.match(r'(\$\w+)\s*=\s*"([^"]*)"', line)
    if plain_match:
        node = PlainString(identifier=plain_match.group(1), value=plain_match.group(2))
        set_recovered_location(
            parser, node, line_num, raw_line, plain_match.start(1), plain_match.end(2) + 1
        )
        return node

    hex_match = re.match(r"(\$\w+)\s*=\s*{([^}]*)}", line)
    if hex_match:
        try:
            tokens = HexStringParser().parse(hex_match.group(2))
        except HexParseError as exc:
            parser._add_error(str(exc), line_num or 0, hex_match.start(2))
            return None
        node = HexString(identifier=hex_match.group(1), tokens=tokens)
        set_recovered_location(
            parser, node, line_num, raw_line, hex_match.start(1), hex_match.end(2) + 1
        )
        return node

    regex_match = re.match(r"(\$\w+)\s*=\s*/((?:\\/|[^/])*)/([ism]*)", line)
    if regex_match:
        flag_modifiers = {
            "i": "nocase",
            "s": "dotall",
            "m": "multiline",
        }
        modifiers = [
            StringModifier.from_name_value(flag_modifiers[flag])
            for flag in regex_match.group(3)
            if flag in flag_modifiers
        ]
        node = RegexString(
            identifier=regex_match.group(1),
            regex=regex_match.group(2),
            modifiers=modifiers,
        )
        set_recovered_location(
            parser, node, line_num, raw_line, regex_match.start(1), regex_match.end(2) + 1
        )
        return node
    parser._add_error(f"Invalid string definition: {line}", line_num or 0, 0)
    return None


def parse_string_line_with_standard_parser(
    line: str,
) -> PlainString | HexString | RegexString | None:
    from yaraast.parser.parser import Parser

    snippet = f"rule recovered {{ strings:\n    {line}\n condition:\n    true\n}}"
    try:
        ast = Parser(snippet).parse()
    except YaraASTError:
        return None

    return cast(PlainString | HexString | RegexString, ast.rules[0].strings[0])


def parse_condition(
    parser, condition_text: str, line_num: int | None = None, raw_line: str | None = None
) -> Any:
    condition_text = condition_text.strip()
    node = _parse_recovered_condition_expression(condition_text)
    start = raw_line.find(condition_text) if raw_line else 0
    if start < 0:
        start = 0
    set_recovered_location(parser, node, line_num, raw_line, start, start + len(condition_text))
    return node


def _parse_recovered_condition_expression(condition_text: str) -> Any:
    if condition_text == "true":
        return BooleanLiteral(True)
    if condition_text == "false":
        return BooleanLiteral(False)

    from yaraast.parser.parser import Parser

    try:
        ast = Parser().parse(f"rule __recovered_condition {{ condition: {condition_text} }}")
    except (YaraASTError, ValueError):
        return Identifier(condition_text)
    return ast.rules[0].condition


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
