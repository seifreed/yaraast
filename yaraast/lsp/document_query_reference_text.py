"""Text-based fallback helpers for LSP references and renames."""

from __future__ import annotations

from collections.abc import Iterable

from lsprotocol.types import Position

from yaraast.lsp.document_query_common import whole_word_positions
from yaraast.lsp.structure import SECTION_NAMES, get_rule_text_range


def iter_reference_occurrences(
    ctx, variants: Iterable[str], *, allowed_sections: tuple[str, ...]
) -> Iterable[tuple[int, int, str, str | None]]:
    for rule_start, rule_end in iter_rule_text_ranges(ctx):
        for line_num in range(rule_start, rule_end + 1):
            masked_line = mask_non_code_segments(ctx.lines[line_num])
            for variant in variants:
                for col in whole_word_positions(masked_line, variant):
                    section_name = section_for_occurrence(ctx.lines, rule_start, line_num, col)
                    if section_name not in allowed_sections:
                        continue
                    yield line_num, col, variant, section_name


def iter_rule_text_ranges(ctx) -> Iterable[tuple[int, int]]:
    seen: set[tuple[int, int]] = set()
    for symbol in ctx._symbols_of_kind("rule_block"):
        start = symbol.range.start.line
        end = symbol.range.end.line
        key = (start, end)
        if key in seen:
            continue
        seen.add(key)
        rule_text_range = get_rule_text_range(ctx.text, start)
        if rule_text_range is not None:
            yield rule_text_range.start, rule_text_range.end
        else:
            yield start, end


def section_for_occurrence(
    lines: list[str], rule_start: int, line_num: int, col: int
) -> str | None:
    current: str | None = None
    for idx in range(rule_start, line_num):
        stripped = lines[idx].strip()
        for section_name in SECTION_NAMES:
            if stripped == f"{section_name}:":
                current = section_name
                break
    line = lines[line_num]
    inline_sections: list[tuple[int, str]] = []
    for section_name in SECTION_NAMES:
        marker = f"{section_name}:"
        marker_idx = line.find(marker)
        if marker_idx >= 0 and marker_idx <= col:
            inline_sections.append((marker_idx, section_name))
    if inline_sections:
        inline_sections.sort(key=lambda item: item[0])
        current = inline_sections[-1][1]
    return current


def mask_non_code_segments(line: str) -> str:
    chars = list(line)
    in_string = False
    escape = False
    for idx, char in enumerate(chars):
        if escape:
            chars[idx] = " "
            escape = False
            continue
        if char == "\\" and in_string:
            chars[idx] = " "
            escape = True
            continue
        if char == '"':
            chars[idx] = " "
            in_string = not in_string
            continue
        if in_string:
            chars[idx] = " "
            continue
        if char == "/" and idx + 1 < len(chars) and chars[idx + 1] == "/":
            for comment_idx in range(idx, len(chars)):
                chars[comment_idx] = " "
            break
    return "".join(chars)


def line_has_assignment(line: str, end_idx: int) -> bool:
    return line[end_idx:].lstrip().startswith("=")


def matches_resolved_symbol(
    ctx, position: Position, *, kind: str | tuple[str, ...], normalized_name: str
) -> bool:
    resolved = ctx.resolve_symbol(position)
    valid_kinds = (kind,) if isinstance(kind, str) else kind
    return bool(
        resolved is not None
        and resolved.kind in valid_kinds
        and resolved.normalized_name == normalized_name
    )
