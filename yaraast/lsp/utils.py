"""Utility functions for LSP implementation."""

from __future__ import annotations

from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from lsprotocol.types import Position, Range

    from yaraast.ast.base import ASTNode, Location
    from yaraast.lexer import Token


def token_to_range(token: Token) -> Range:
    """Convert a token to an LSP Range."""
    from lsprotocol.types import Position, Range

    start = Position(line=token.line - 1, character=token.column)
    # Estimate end position (token length)
    end = Position(line=token.line - 1, character=token.column + len(str(token.value)))
    return Range(start=start, end=end)


def location_to_range(location: Location) -> Range:
    """Convert an AST Location to an LSP Range."""
    from lsprotocol.types import Position, Range

    start = Position(line=location.line - 1, character=location.column)
    # Estimate end - for now, same line with some character offset
    end = Position(line=location.line - 1, character=location.column + 10)
    return Range(start=start, end=end)


def position_to_offset(text: str, position: Position) -> int:
    """Convert an LSP Position to a byte offset in the text."""
    lines = text.split("\n")
    offset = 0

    for i in range(position.line):
        if i < len(lines):
            offset += len(lines[i]) + 1  # +1 for newline

    if position.line < len(lines):
        offset += min(position.character, len(lines[position.line]))

    return offset


def offset_to_position(text: str, offset: int) -> Position:
    """Convert a byte offset to an LSP Position."""
    from lsprotocol.types import Position

    lines = text.split("\n")
    current_offset = 0

    for line_num, line in enumerate(lines):
        line_length = len(line) + 1  # +1 for newline
        if current_offset + line_length > offset:
            character = offset - current_offset
            return Position(line=line_num, character=character)
        current_offset += line_length

    # If offset is at the end
    return Position(line=len(lines) - 1, character=len(lines[-1]) if lines else 0)


def get_word_at_position(text: str, position: Position) -> tuple[str, Range]:
    """Get the word at a given position."""
    from lsprotocol.types import Position, Range

    lines = text.split("\n")
    if position.line >= len(lines):
        return "", Range(start=position, end=position)

    line = lines[position.line]
    if position.character >= len(line):
        return "", Range(start=position, end=position)

    # Find word boundaries
    start = position.character
    end = position.character

    # Move start backward to word boundary
    while start > 0 and (line[start - 1].isalnum() or line[start - 1] in "_$"):
        start -= 1

    # Move end forward to word boundary
    while end < len(line) and (line[end].isalnum() or line[end] in "_$"):
        end += 1

    word = line[start:end]
    word_range = Range(
        start=Position(line=position.line, character=start),
        end=Position(line=position.line, character=end),
    )

    return word, word_range


def find_node_at_position(
    ast: ASTNode,
    position: Position,
) -> ASTNode | None:
    """Find the AST node at a given position."""
    # This is a simplified implementation
    # In a real implementation, you'd traverse the AST and check location information

    from yaraast.visitor import ASTVisitor

    class NodeFinder(ASTVisitor):
        def __init__(self, target_line: int) -> None:
            self.target_line = target_line + 1  # Convert to 1-based
            self.found_node: ASTNode | None = None

        def visit(self, node: ASTNode) -> None:
            if hasattr(node, "location") and node.location:
                if node.location.line == self.target_line:
                    self.found_node = node
            super().visit(node)

    finder = NodeFinder(position.line)
    finder.visit(ast)
    return finder.found_node
