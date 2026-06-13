"""Leaf quick-fix builders for semantic code actions."""

from __future__ import annotations

import re
from types import SimpleNamespace

from lsprotocol.types import (
    CodeAction,
    CodeActionKind,
    Diagnostic,
    Position,
    Range,
    TextEdit,
    WorkspaceEdit,
)

from yaraast.lsp.document_query_resolution_text import position_is_in_non_code_segment
from yaraast.lsp.structure import _starts_regex_literal
from yaraast.lsp.utf16 import utf8_col_to_utf16, utf16_col_to_utf8


def _diagnostic_python_range(line: str, diagnostic: Diagnostic) -> tuple[int, int]:
    return (
        utf16_col_to_utf8(line, diagnostic.range.start.character),
        utf16_col_to_utf8(line, diagnostic.range.end.character),
    )


def _same_line_position(line_num: int, line: str, col: int) -> Position:
    return Position(line=line_num, character=utf8_col_to_utf16(line, col))


def _same_line_range(line_num: int, line: str, start: int, end: int) -> Range:
    return Range(
        start=_same_line_position(line_num, line, start),
        end=_same_line_position(line_num, line, end),
    )


def _scan_quoted_end(text: str, start: int, delimiter: str) -> int:
    escaped = False
    index = start + 1
    while index < len(text):
        char = text[index]
        if escaped:
            escaped = False
        elif char == "\\":
            escaped = True
        elif char == delimiter:
            return index
        index += 1
    return len(text) - 1


def _find_matching_call_close(line: str, open_paren: int) -> int | None:
    depth = 0
    index = open_paren
    while index < len(line):
        char = line[index]
        if char == '"':
            index = _scan_quoted_end(line, index, '"') + 1
            continue
        if char == "/" and _starts_regex_literal(line, index):
            index = _scan_quoted_end(line, index, "/") + 1
            continue
        if char == "(":
            depth += 1
        elif char == ")":
            depth -= 1
            if depth == 0:
                return index
        index += 1
    return None


def _find_matching_call_close_in_lines(
    lines: list[str], open_line: int, open_paren: int
) -> tuple[int, int] | None:
    depth = 0
    for line_num in range(open_line, len(lines)):
        line = lines[line_num]
        index = open_paren if line_num == open_line else 0
        while index < len(line):
            char = line[index]
            if char == '"':
                index = _scan_quoted_end(line, index, '"') + 1
                continue
            if char == "/" and _starts_regex_literal(line, index):
                index = _scan_quoted_end(line, index, "/") + 1
                continue
            if char == "(":
                depth += 1
            elif char == ")":
                depth -= 1
                if depth == 0:
                    return line_num, index
            index += 1
    return None


def _find_diagnostic_call(
    line: str,
    function_name: str,
    diagnostic: Diagnostic,
) -> tuple[int, int, int] | None:
    needle = f"{function_name}("
    range_start, range_end = _diagnostic_python_range(line, diagnostic)
    fallback: tuple[int, int, int] | None = None
    search_start = 0
    while True:
        start_col = line.find(needle, search_start)
        if start_col < 0:
            break
        open_paren = start_col + len(function_name)
        close_paren = _find_matching_call_close(line, open_paren)
        if close_paren is not None:
            call_span = (start_col, open_paren, close_paren)
            if fallback is None:
                fallback = call_span
            if start_col < range_end and close_paren + 1 > range_start:
                return call_span
        search_start = start_col + len(needle)
    return fallback


def _find_diagnostic_call_close(
    lines: list[str],
    function_name: str,
    diagnostic: Diagnostic,
) -> tuple[int, int, int, int] | None:
    line_num = diagnostic.range.start.line
    if line_num >= len(lines):
        return None
    line = lines[line_num]
    needle = f"{function_name}("
    range_start = utf16_col_to_utf8(line, diagnostic.range.start.character)
    range_end = (
        utf16_col_to_utf8(line, diagnostic.range.end.character)
        if diagnostic.range.end.line == line_num
        else len(line)
    )
    fallback: tuple[int, int, int, int] | None = None
    search_start = 0
    while True:
        start_col = line.find(needle, search_start)
        if start_col < 0:
            break
        open_paren = start_col + len(function_name)
        close = _find_matching_call_close_in_lines(lines, line_num, open_paren)
        if close is not None:
            close_line, close_col = close
            call_span = (start_col, open_paren, close_line, close_col)
            if fallback is None:
                fallback = call_span
            if start_col < range_end and (close_line > line_num or close_col + 1 > range_start):
                return call_span
        search_start = start_col + len(needle)
    return fallback


def _find_diagnostic_occurrence(line: str, needle: str, diagnostic: Diagnostic) -> int:
    if not needle:
        return -1
    range_start, range_end = _diagnostic_python_range(line, diagnostic)
    fallback = line.find(needle)
    if fallback < 0:
        return -1
    search_start = fallback
    while search_start >= 0:
        start_col = line.find(needle, search_start)
        if start_col < 0:
            break
        end_col = start_col + len(needle)
        if start_col < range_end and end_col > range_start:
            return start_col
        search_start = start_col + len(needle)
    return fallback


def _split_top_level_arguments(args_text: str) -> list[str]:
    parts: list[str] = []
    start = 0
    paren_depth = 0
    bracket_depth = 0
    brace_depth = 0
    index = 0
    while index < len(args_text):
        char = args_text[index]
        if char == '"':
            index = _scan_quoted_end(args_text, index, '"') + 1
            continue
        if char == "/" and _starts_regex_literal(args_text, index):
            index = _scan_quoted_end(args_text, index, "/") + 1
            continue
        if char == "(":
            paren_depth += 1
        elif char == ")":
            paren_depth = max(0, paren_depth - 1)
        elif char == "[":
            bracket_depth += 1
        elif char == "]":
            bracket_depth = max(0, bracket_depth - 1)
        elif char == "{":
            brace_depth += 1
        elif char == "}":
            brace_depth = max(0, brace_depth - 1)
        elif char == "," and paren_depth == 0 and bracket_depth == 0 and brace_depth == 0:
            parts.append(args_text[start:index].strip())
            start = index + 1
        index += 1
    tail = args_text[start:].strip()
    if tail or parts:
        parts.append(tail)
    return parts


def _call_arguments_text(
    lines: list[str],
    open_line: int,
    open_paren: int,
    close_line: int,
    close_paren: int,
) -> str:
    if open_line == close_line:
        return lines[open_line][open_paren + 1 : close_paren]
    parts = [lines[open_line][open_paren + 1 :]]
    parts.extend(lines[open_line + 1 : close_line])
    parts.append(lines[close_line][:close_paren])
    return "\n".join(parts)


def create_replace_module_function_actions(
    text: str,
    diagnostic: Diagnostic,
    uri: str,
    module_name: str,
    function_name: str,
    available_functions: list[str],
) -> list[CodeAction]:
    actions: list[CodeAction] = []
    if not available_functions:
        return actions

    lines = text.split("\n")
    line_num = diagnostic.range.start.line
    if line_num >= len(lines):
        return actions
    line = lines[line_num]
    needle = f"{module_name}.{function_name}"
    start_col = _find_diagnostic_occurrence(line, needle, diagnostic)
    if start_col < 0:
        return actions

    for replacement_name in available_functions[:3]:
        replacement = f"{module_name}.{replacement_name}"
        actions.append(
            CodeAction(
                title=f"Replace with {replacement}",
                kind=CodeActionKind.QuickFix,
                edit=WorkspaceEdit(
                    changes={
                        uri: [
                            TextEdit(
                                range=_same_line_range(
                                    line_num, line, start_col, start_col + len(needle)
                                ),
                                new_text=replacement,
                            )
                        ]
                    }
                ),
                diagnostics=[diagnostic],
            )
        )
    return actions


def create_replace_builtin_function_actions(
    text: str,
    diagnostic: Diagnostic,
    uri: str,
    function_name: str,
    suggested_functions: list[str],
) -> list[CodeAction]:
    actions: list[CodeAction] = []
    if not suggested_functions:
        return actions

    lines = text.split("\n")
    line_num = diagnostic.range.start.line
    if line_num >= len(lines):
        return actions

    line = lines[line_num]
    start_col = _find_diagnostic_occurrence(line, function_name, diagnostic)
    if start_col < 0:
        return actions

    for replacement_name in suggested_functions[:3]:
        actions.append(
            CodeAction(
                title=f"Replace with {replacement_name}()",
                kind=CodeActionKind.QuickFix,
                edit=WorkspaceEdit(
                    changes={
                        uri: [
                            TextEdit(
                                range=_same_line_range(
                                    line_num,
                                    line,
                                    start_col,
                                    start_col + len(function_name),
                                ),
                                new_text=replacement_name,
                            )
                        ]
                    }
                ),
                diagnostics=[diagnostic],
            )
        )

    return actions


def create_add_placeholder_argument_action(
    text: str,
    diagnostic: Diagnostic,
    uri: str,
    function_name: str,
) -> list[CodeAction]:
    lines = text.split("\n")
    line_num = diagnostic.range.start.line
    if line_num >= len(lines):
        return []
    line = lines[line_num]
    call_span = _find_diagnostic_call(line, function_name, diagnostic)
    if call_span is None:
        return []
    _start_col, open_paren, close_paren = call_span
    if close_paren != open_paren + 1:
        return []

    edit = TextEdit(
        range=Range(
            start=_same_line_position(line_num, line, open_paren + 1),
            end=_same_line_position(line_num, line, open_paren + 1),
        ),
        new_text="0",
    )
    return [
        CodeAction(
            title=f"Add placeholder argument to {function_name}()",
            kind=CodeActionKind.QuickFix,
            edit=WorkspaceEdit(changes={uri: [edit]}),
            diagnostics=[diagnostic],
        )
    ]


def create_add_missing_arguments_action(
    text: str,
    diagnostic: Diagnostic,
    uri: str,
    function_name: str,
    missing_count: int,
) -> list[CodeAction]:
    if missing_count <= 0:
        return []
    lines = text.split("\n")
    line_num = diagnostic.range.start.line
    if line_num >= len(lines):
        return []
    call_span = _find_diagnostic_call_close(lines, function_name, diagnostic)
    if call_span is None:
        return []
    _start_col, open_paren, close_line, close_paren = call_span
    insertion = ("0, " * missing_count).rstrip(", ")
    if close_line > line_num or close_paren > open_paren + 1:
        insertion = ", " + insertion
    close_line_text = lines[close_line]
    return [
        CodeAction(
            title=f"Add {missing_count} missing argument(s) to {function_name}()",
            kind=CodeActionKind.QuickFix,
            edit=WorkspaceEdit(
                changes={
                    uri: [
                        TextEdit(
                            range=Range(
                                start=_same_line_position(close_line, close_line_text, close_paren),
                                end=_same_line_position(close_line, close_line_text, close_paren),
                            ),
                            new_text=insertion,
                        )
                    ]
                }
            ),
            diagnostics=[diagnostic],
        )
    ]


def create_trim_arguments_action(
    text: str,
    diagnostic: Diagnostic,
    uri: str,
    function_name: str,
    keep_args: int,
) -> list[CodeAction]:
    lines = text.split("\n")
    line_num = diagnostic.range.start.line
    if line_num >= len(lines) or keep_args < 0:
        return []
    line = lines[line_num]
    call_span = _find_diagnostic_call_close(lines, function_name, diagnostic)
    if call_span is None:
        return []
    _start_col, open_paren, close_line, close_paren = call_span

    args_text = _call_arguments_text(lines, line_num, open_paren, close_line, close_paren)
    parts = _split_top_level_arguments(args_text)
    if len(parts) <= keep_args:
        return []
    replacement = ", ".join(parts[:keep_args])

    return [
        CodeAction(
            title=f"Remove extra argument(s) from {function_name}()",
            kind=CodeActionKind.QuickFix,
            edit=WorkspaceEdit(
                changes={
                    uri: [
                        TextEdit(
                            range=Range(
                                start=_same_line_position(line_num, line, open_paren + 1),
                                end=_same_line_position(
                                    close_line,
                                    lines[close_line],
                                    close_paren,
                                ),
                            ),
                            new_text=replacement,
                        )
                    ]
                }
            ),
            diagnostics=[diagnostic],
        )
    ]


def create_import_module_action(
    module_name: str, diagnostic: Diagnostic, uri: str
) -> list[CodeAction]:
    import_line = f'import "{module_name}"\n'
    insert_position = Position(line=0, character=0)
    edit = TextEdit(range=Range(start=insert_position, end=insert_position), new_text=import_line)
    return [
        CodeAction(
            title=f'Add import "{module_name}"',
            kind=CodeActionKind.QuickFix,
            edit=WorkspaceEdit(changes={uri: [edit]}),
            diagnostics=[diagnostic],
        )
    ]


def create_rename_duplicate_action(
    text: str,
    diagnostic: Diagnostic,
    uri: str,
    identifier: str,
) -> list[CodeAction]:
    base_name = identifier.removeprefix("$")
    if not base_name:
        return []

    lines = text.split("\n")
    ctx = SimpleNamespace(lines=lines)
    existing_ids = set()
    for line_num, line in enumerate(lines):
        for id_match in re.finditer(r"\$(\w+)\s*=", line):
            if position_is_in_non_code_segment(
                ctx,
                Position(
                    line=line_num,
                    character=utf8_col_to_utf16(line, id_match.start()),
                ),
            ):
                continue
            existing_ids.add(id_match.group(1))

    counter = 2
    while f"{base_name}_{counter}" in existing_ids:
        counter += 1
    new_name = f"${base_name}_{counter}"

    line_num = diagnostic.range.start.line
    if line_num < len(lines):
        line = lines[line_num]
        col = _find_diagnostic_occurrence(line, f"${base_name}", diagnostic)
        if col >= 0:
            edit = TextEdit(
                range=_same_line_range(line_num, line, col, col + len(f"${base_name}")),
                new_text=new_name,
            )
            return [
                CodeAction(
                    title=f"Rename to {new_name}",
                    kind=CodeActionKind.QuickFix,
                    edit=WorkspaceEdit(changes={uri: [edit]}),
                    diagnostics=[diagnostic],
                )
            ]
    return []
