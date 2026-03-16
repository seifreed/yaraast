"""Helpers for structured selection range discovery."""

from __future__ import annotations

from lsprotocol.types import Position, Range, SelectionRange

from yaraast.lsp.structure import find_section_range, get_rule_text_range


def line_range(lines: list[str], line: int) -> Range:
    return Range(
        start=Position(line=line, character=0),
        end=Position(line=line, character=len(lines[line])),
    )


def build_selection_parent(
    doc_text: str,
    position: Position,
    line_range_value: Range,
    find_rule_range_fn,
    find_section_range_fn,
) -> SelectionRange:
    """Build containment parents: line → section → rule (smallest to largest)."""
    rule_range = find_rule_range_fn(doc_text, position)
    section_range = find_section_range_fn(doc_text, position)

    # Build chain from outermost (rule) to innermost (line)
    rule_parent = SelectionRange(range=rule_range, parent=None) if rule_range is not None else None

    if section_range is not None and section_range != line_range_value:
        section_parent = SelectionRange(range=section_range, parent=rule_parent)
        # line → section → rule
        return SelectionRange(range=line_range_value, parent=section_parent)

    if rule_parent is not None and rule_parent.range != line_range_value:
        # line → rule (no section level)
        return SelectionRange(range=line_range_value, parent=rule_parent)

    # line only (no enclosing rule or section)
    return SelectionRange(range=line_range_value, parent=None)


def find_enclosing_rule_range(text: str, position: Position) -> Range | None:
    rule_text_range = get_rule_text_range(text, position.line)
    if rule_text_range is None:
        return None
    return Range(
        start=Position(line=rule_text_range.start, character=0),
        end=Position(
            line=rule_text_range.end, character=len(rule_text_range.lines[rule_text_range.end])
        ),
    )


def find_enclosing_section_range(text: str, position: Position) -> Range | None:
    rule_text_range = get_rule_text_range(text, position.line)
    if rule_text_range is None:
        return None
    lines = rule_text_range.lines
    for section_name in ("meta", "strings", "condition", "events", "match", "outcome", "options"):
        section_range = find_section_range(
            lines, section_name, rule_text_range.start, rule_text_range.end
        )
        if section_range is None:
            continue
        if section_range.start.line <= position.line <= section_range.end.line:
            return section_range
    return None
