"""Token-based mmap helpers for the streaming parser."""

from __future__ import annotations

from collections.abc import Iterator
import mmap

from yaraast.lexer.lexer import Lexer
from yaraast.lexer.tokens import Token, TokenType


def iter_rule_text_spans_from_text(content: str) -> Iterator[tuple[str, int, int]]:
    """Yield complete rule texts and their character spans from YARA source text."""
    line_starts = [0]
    for index, char in enumerate(content):
        if char == "\n":
            line_starts.append(index + 1)

    def get_char_pos(line: int, column: int) -> int:
        return line_starts[line - 1] + (column - 1)

    tokens: list[Token] = Lexer[list[Token]](content).tokenize()
    index = 0
    while index < len(tokens):
        token = tokens[index]

        if token.type in (TokenType.IMPORT, TokenType.INCLUDE):
            index += 1
            while index < len(tokens) and tokens[index].type != TokenType.STRING:
                index += 1
            index += 1
            continue

        if token.type not in (TokenType.RULE, TokenType.PRIVATE, TokenType.GLOBAL):
            index += 1
            continue

        rule_start_token = token
        while index < len(tokens) and tokens[index].type != TokenType.RULE:
            index += 1
        if index >= len(tokens):
            break

        index += 1
        if index >= len(tokens) or tokens[index].type != TokenType.IDENTIFIER:
            index += 1
            continue

        index += 1
        if index < len(tokens) and tokens[index].type == TokenType.COLON:
            index += 1
            while index < len(tokens) and tokens[index].type == TokenType.IDENTIFIER:
                index += 1

        while index < len(tokens) and tokens[index].type != TokenType.LBRACE:
            index += 1
        if index >= len(tokens):
            break

        brace_count = 1
        index += 1
        while index < len(tokens) and brace_count > 0:
            if tokens[index].type == TokenType.LBRACE:
                brace_count += 1
            elif tokens[index].type == TokenType.RBRACE:
                brace_count -= 1
            index += 1

        if brace_count != 0:
            continue

        brace_end_token = tokens[index - 1]
        start_pos = get_char_pos(rule_start_token.line, rule_start_token.column)
        end_pos = get_char_pos(brace_end_token.line, brace_end_token.column) + 1
        yield content[start_pos:end_pos], start_pos, end_pos


def iter_rule_texts_from_text(content: str) -> Iterator[str]:
    """Yield complete rule texts from YARA source text."""
    for rule_text, _, _ in iter_rule_text_spans_from_text(content):
        yield rule_text


def iter_rule_texts_from_mmap(mmapped_file: mmap.mmap) -> Iterator[str]:
    """Yield complete rule texts from a memory-mapped YARA file."""
    for rule_text, _, _ in iter_rule_text_byte_spans_from_mmap(mmapped_file):
        yield rule_text


def iter_rule_text_byte_spans_from_mmap(
    mmapped_file: mmap.mmap,
) -> Iterator[tuple[str, int, int]]:
    """Yield complete rule texts and their byte spans from a memory-mapped YARA file."""
    content = mmapped_file.read().decode("utf-8", errors="replace")
    mmapped_file.seek(0)
    current_char_pos = 0
    current_byte_pos = 0
    for rule_text, start_pos, end_pos in iter_rule_text_spans_from_text(content):
        current_byte_pos += len(content[current_char_pos:start_pos].encode("utf-8"))
        start_byte_pos = current_byte_pos
        current_byte_pos += len(content[start_pos:end_pos].encode("utf-8"))
        yield rule_text, start_byte_pos, current_byte_pos
        current_char_pos = end_pos
