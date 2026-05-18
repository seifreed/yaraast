"""Leaf quick-fix builders for semantic code actions."""

from __future__ import annotations

import re

from lsprotocol.types import (
    CodeAction,
    CodeActionKind,
    Diagnostic,
    Position,
    Range,
    TextEdit,
    WorkspaceEdit,
)

from yaraast.lsp.structure import _starts_regex_literal


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
    start_col = line.find(needle)
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
                                range=Range(
                                    start=Position(line=line_num, character=start_col),
                                    end=Position(line=line_num, character=start_col + len(needle)),
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
    start_col = line.find(function_name)
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
                                range=Range(
                                    start=Position(line=line_num, character=start_col),
                                    end=Position(
                                        line=line_num, character=start_col + len(function_name)
                                    ),
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
    needle = f"{function_name}()"
    start_col = line.find(needle)
    if start_col < 0:
        return []

    edit = TextEdit(
        range=Range(
            start=Position(line=line_num, character=start_col + len(function_name) + 1),
            end=Position(line=line_num, character=start_col + len(function_name) + 1),
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
    line = lines[line_num]
    start_col = line.find(f"{function_name}(")
    if start_col < 0:
        return []
    open_paren = start_col + len(function_name)
    close_paren = _find_matching_call_close(line, open_paren)
    if close_paren is None:
        return []
    insertion = ("0, " * missing_count).rstrip(", ")
    if close_paren > open_paren + 1:
        insertion = ", " + insertion
    return [
        CodeAction(
            title=f"Add {missing_count} missing argument(s) to {function_name}()",
            kind=CodeActionKind.QuickFix,
            edit=WorkspaceEdit(
                changes={
                    uri: [
                        TextEdit(
                            range=Range(
                                start=Position(line=line_num, character=close_paren),
                                end=Position(line=line_num, character=close_paren),
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
    start_col = line.find(f"{function_name}(")
    if start_col < 0:
        return []
    open_paren = start_col + len(function_name)
    close_paren = _find_matching_call_close(line, open_paren)
    if close_paren is None:
        return []

    args_text = line[open_paren + 1 : close_paren]
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
                                start=Position(line=line_num, character=open_paren + 1),
                                end=Position(line=line_num, character=close_paren),
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
    existing_ids = set()
    for line in lines:
        id_match = re.search(r"\$(\w+)\s*=", line)
        if id_match:
            existing_ids.add(id_match.group(1))

    counter = 2
    while f"{base_name}_{counter}" in existing_ids:
        counter += 1
    new_name = f"${base_name}_{counter}"

    line_num = diagnostic.range.start.line
    if line_num < len(lines):
        line = lines[line_num]
        col = line.find(f"${base_name}")
        if col >= 0:
            edit = TextEdit(
                range=Range(
                    start=Position(line=line_num, character=col),
                    end=Position(line=line_num, character=col + len(f"${base_name}")),
                ),
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
