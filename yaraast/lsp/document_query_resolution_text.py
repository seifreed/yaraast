"""Text fallback helpers for LSP symbol resolution."""

from __future__ import annotations

from typing import TYPE_CHECKING, Any

from lsprotocol.types import Position

from yaraast.lsp.document_types import ResolvedSymbol
from yaraast.lsp.structure import _starts_regex_literal
from yaraast.lsp.text_utils import get_word_at_position
from yaraast.lsp.utf16 import utf16_col_to_utf8

if TYPE_CHECKING:
    from yaraast.lsp.document_context import DocumentContext


def _is_complete_dotted_word(word: str) -> bool:
    parts = word.split(".")
    return len(parts) > 1 and all(parts)


def resolve_symbol_from_text_fallback(
    ctx: DocumentContext,
    position: Position,
    *,
    allow_generic_identifier: bool = True,
) -> ResolvedSymbol | None:
    if position_is_in_non_code_segment(ctx, position):
        return None
    module_member = find_module_member_at_position(ctx, position)
    if module_member is not None:
        return module_member
    word, word_range = get_word_at_position(ctx.text, position)
    if not word:
        return None
    if word.startswith(("$", "#", "@", "!")):
        base_identifier = word.lstrip("#@!")
        if not base_identifier.startswith("$"):
            base_identifier = f"${base_identifier}"
        return ResolvedSymbol(ctx.uri, word, base_identifier, "string", word_range)
    if _is_complete_dotted_word(word):
        return ResolvedSymbol(ctx.uri, word, word, "module_member", word_range)
    if "." in word:
        return None
    if ctx.find_rule_definition(word) is not None:
        return ResolvedSymbol(ctx.uri, word, word, "rule", word_range)
    if not allow_generic_identifier:
        return None
    return ResolvedSymbol(ctx.uri, word, word, "identifier", word_range)


def position_is_in_non_code_segment(ctx: Any, position: Position) -> bool:
    if position.line >= len(ctx.lines):
        return False

    in_block_comment = False
    for line_num in range(position.line + 1):
        line = ctx.lines[line_num]
        target_character = (
            utf16_col_to_utf8(line, position.character) if line_num == position.line else len(line)
        )
        in_string = False
        in_regex = False
        escape = False
        idx = 0
        while idx < len(line):
            if line_num == position.line and idx >= target_character:
                return in_block_comment or in_string or in_regex

            char = line[idx]
            nxt = line[idx + 1] if idx + 1 < len(line) else ""

            if in_block_comment:
                if char == "*" and nxt == "/":
                    if line_num == position.line and target_character < idx + 2:
                        return True
                    in_block_comment = False
                    idx += 2
                    continue
                idx += 1
                continue

            if escape:
                escape = False
                idx += 1
                continue

            if char == "\\" and (in_string or in_regex):
                escape = True
                idx += 1
                continue

            if not in_string and not in_regex:
                if char == "/" and nxt == "/":
                    if line_num == position.line:
                        return target_character > idx
                    break
                if char == "/" and nxt == "*":
                    if line_num == position.line and target_character > idx:
                        comment_end = line.find("*/", idx + 2)
                        if comment_end < 0 or target_character < comment_end + 2:
                            return True
                    in_block_comment = True
                    idx += 2
                    continue

            if char == '"' and not in_regex:
                in_string = not in_string
            elif char == "/" and not in_string:
                starts_regex = _starts_regex_literal(line, idx)
                if in_regex:
                    in_regex = False
                elif starts_regex:
                    in_regex = True
            idx += 1

        if line_num == position.line:
            return in_block_comment or in_string or in_regex

    return False


def find_module_member_at_position(
    ctx: DocumentContext, position: Position
) -> ResolvedSymbol | None:
    word, word_range = get_word_at_position(ctx.text, position)
    if _is_complete_dotted_word(word):
        root, _sep, _rest = word.partition(".")
        imported_modules = {symbol.name for symbol in ctx.symbols() if symbol.kind == "import"}
        if root in imported_modules:
            return ResolvedSymbol(ctx.uri, word, word, "module_member", word_range)
    return None
