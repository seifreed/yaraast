"""Utility functions for LSP implementation."""

from __future__ import annotations

from pathlib import Path

from lsprotocol.types import Position, Range

from yaraast.ast.base import ASTNode, Location
from yaraast.lsp.utf16 import utf8_col_to_utf16, utf16_col_to_utf8
from yaraast.shared.path_safety import path_is_symlink


def path_exists(path: Path) -> bool:
    try:
        return path.exists()
    except OSError:
        return False


def path_is_file(path: Path) -> bool:
    try:
        return path.is_file()
    except OSError:
        return False


def path_is_dir(path: Path) -> bool:
    try:
        return path.is_dir()
    except OSError:
        return False


def location_to_range(location: Location, source_text: str | None = None) -> Range:
    """Convert an AST Location to an LSP range with best-effort end estimation."""
    lines = source_text.split("\n") if source_text is not None else []
    start_line = max(0, location.line - 1)
    start_python = max(0, location.column - 1)
    start_character = _python_column_to_lsp(lines, start_line, start_python)
    start = Position(line=start_line, character=start_character)
    if location.end_line is not None and location.end_column is not None:
        end_line = max(0, location.end_line - 1)
        end_python = max(0, location.end_column - 1)
        end_character = _python_column_to_lsp(lines, end_line, end_python)
        if end_line == start_line:
            end_character = max(start_character + 1, end_character)
        return Range(
            start=start,
            end=Position(line=end_line, character=end_character),
        )
    span = _estimate_location_span(location, source_text)
    end_python = start_python + span
    end = Position(
        line=start_line,
        character=_python_column_to_lsp(lines, start_line, end_python),
    )
    return Range(start=start, end=end)


def find_node_at_position(
    ast: ASTNode,
    position: Position,
    source_text: str | None = None,
) -> ASTNode | None:
    """Find the deepest AST node containing the given position when spans exist.

    Falls back to start-line proximity for nodes that only expose a start
    location.
    """

    target_line: int = position.line + 1  # Convert to 1-based
    target_column: int = _position_to_location_column(position, source_text)
    best_match: tuple[int, int, int, int, ASTNode] | None = None

    def _search(node: ASTNode, depth: int) -> None:
        nonlocal best_match
        location = getattr(node, "location", None)
        if location is not None:
            if _location_contains_position(location, target_line, target_column):
                span_size = _location_span_size(location)
                candidate = (2, depth, -span_size, -location.column, node)
                if best_match is None or candidate > best_match:
                    best_match = candidate
            elif location.line == target_line:
                distance = abs(location.column - target_column)
                candidate = (1, depth, -distance, -location.column, node)
                if best_match is None or candidate > best_match:
                    best_match = candidate
        for child in node.children():
            _search(child, depth + 1)

    _search(ast, 0)
    return best_match[4] if best_match is not None else None


def _estimate_location_span(location: Location, source_text: str | None) -> int:
    line_text = _get_location_line_text(location, source_text)
    if line_text is None:
        return 1
    start = max(0, min(location.column - 1, len(line_text)))
    if start >= len(line_text):
        return 1
    if line_text[start] == '"':
        end = start + 1
        escaped = False
        while end < len(line_text):
            char = line_text[end]
            if escaped:
                escaped = False
            elif char == "\\":
                escaped = True
            elif char == '"':
                return max(1, end - start + 1)
            end += 1
        return max(1, len(line_text) - start)
    end = start
    while end < len(line_text) and (line_text[end].isalnum() or line_text[end] in "_$#@!."):
        end += 1
    return max(1, end - start)


def _get_location_line_text(location: Location, source_text: str | None) -> str | None:
    if source_text is not None:
        lines = source_text.split("\n")
        line_index = location.line - 1
        if 0 <= line_index < len(lines):
            return lines[line_index]
        return None
    if location.file:
        if "\x00" in location.file:
            return None
        path = Path(location.file)
        if path_is_symlink(path):
            return None
        if path_exists(path) and path_is_file(path):
            try:
                lines = path.read_text(encoding="utf-8").split("\n")
            except (OSError, UnicodeDecodeError):
                return None
            line_index = location.line - 1
            if 0 <= line_index < len(lines):
                return lines[line_index]
    return None


def _location_contains_position(location: Location, line: int, column: int) -> bool:
    end_line = location.end_line
    end_column = location.end_column
    if end_line is None or end_column is None:
        return False
    if not (location.line <= line <= end_line):
        return False
    if line == location.line and column < location.column:
        return False
    return not (line == end_line and column >= end_column)


def _location_span_size(location: Location) -> int:
    end_line = location.end_line or location.line
    end_column = location.end_column or (location.column + 1)
    return ((end_line - location.line) * 10_000) + max(1, end_column - location.column)


def _python_column_to_lsp(lines: list[str], line_index: int, column: int) -> int:
    if 0 <= line_index < len(lines):
        return utf8_col_to_utf16(lines[line_index], column)
    return column


def _position_to_location_column(position: Position, source_text: str | None) -> int:
    if source_text is not None:
        lines = source_text.split("\n")
        if 0 <= position.line < len(lines):
            return utf16_col_to_utf8(lines[position.line], position.character) + 1
    return position.character + 1
