"""Text search helpers for document highlight provider."""

from __future__ import annotations

from lsprotocol.types import DocumentHighlight, DocumentHighlightKind, Position, Range

from yaraast.lsp.structure import find_section_range, get_rule_text_range


def _is_identifier_boundary(line: str, start: int, end: int) -> bool:
    if start > 0 and (line[start - 1].isalnum() or line[start - 1] == "_"):
        return False
    return not (end < len(line) and (line[end].isalnum() or line[end] == "_"))


def simple_highlight(text: str, word: str) -> list[DocumentHighlight]:
    highlights = []
    lines = text.split("\n")
    for line_num, line in enumerate(lines):
        col = 0
        while True:
            idx = line.find(word, col)
            if idx == -1:
                break
            highlights.append(
                DocumentHighlight(
                    range=Range(
                        start=Position(line=line_num, character=idx),
                        end=Position(line=line_num, character=idx + len(word)),
                    ),
                    kind=DocumentHighlightKind.Text,
                )
            )
            col = idx + len(word)
    return highlights


def highlight_identifier(text: str, identifier: str) -> list[DocumentHighlight]:
    highlights = []
    lines = text.split("\n")
    for line_num, line in enumerate(lines):
        col = 0
        while True:
            idx = line.find(identifier, col)
            if idx == -1:
                break
            end_idx = idx + len(identifier)
            if not _is_identifier_boundary(line, idx, end_idx):
                col = idx + 1
                continue
            highlights.append(
                DocumentHighlight(
                    range=Range(
                        start=Position(line=line_num, character=idx),
                        end=Position(line=line_num, character=end_idx),
                    ),
                    kind=DocumentHighlightKind.Text,
                )
            )
            col = end_idx
    return highlights


def highlight_string_identifier(text: str, identifier: str) -> list[DocumentHighlight]:
    highlights = []
    lines = text.split("\n")
    base_id = identifier[1:] if identifier.startswith("$") else identifier
    patterns = [f"${base_id}", f"#{base_id}", f"@{base_id}", f"!{base_id}"]

    for line_num, line in enumerate(lines):
        for pattern in patterns:
            col = 0
            while True:
                idx = line.find(pattern, col)
                if idx == -1:
                    break
                end_idx = idx + len(pattern)
                if not _is_identifier_boundary(line, idx, end_idx):
                    col = end_idx
                    continue
                kind = DocumentHighlightKind.Read
                if pattern.startswith("$") and _is_string_definition_occurrence(
                    text, line_num, end_idx
                ):
                    kind = DocumentHighlightKind.Write
                highlights.append(
                    DocumentHighlight(
                        range=Range(
                            start=Position(line=line_num, character=idx),
                            end=Position(line=line_num, character=end_idx),
                        ),
                        kind=kind,
                    )
                )
                col = end_idx
    return highlights


def _is_string_definition_occurrence(text: str, line_num: int, end_idx: int) -> bool:
    rule_text_range = get_rule_text_range(text, line_num)
    if rule_text_range is None:
        return False
    section_range = find_section_range(
        rule_text_range.lines,
        "strings",
        rule_text_range.start,
        rule_text_range.end,
    )
    if section_range is None or not (
        section_range.start.line <= line_num <= section_range.end.line
    ):
        return False
    line = rule_text_range.lines[line_num]
    return line[end_idx:].lstrip().startswith("=")
