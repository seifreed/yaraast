"""Token-based mmap helpers for the streaming parser."""

from __future__ import annotations

from collections.abc import Iterator
import mmap

from yaraast.lexer.lexer import Lexer
from yaraast.lexer.tokens import TokenType


def iter_rule_texts_from_mmap(mmapped_file: mmap.mmap) -> Iterator[str]:
    """Yield complete rule texts from a memory-mapped YARA file."""
    content = mmapped_file.read().decode("utf-8", errors="replace")
    mmapped_file.seek(0)

    line_starts = [0]
    for index, char in enumerate(content):
        if char == "\n":
            line_starts.append(index + 1)

    def get_char_pos(line: int, column: int) -> int:
        return line_starts[line - 1] + (column - 1)

    tokens = list(Lexer(content).tokenize())
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
        yield content[start_pos:end_pos]
