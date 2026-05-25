"""Helpers for comment-aware parsing."""

from __future__ import annotations

from yaraast.ast.base import Location
from yaraast.ast.comments import Comment
from yaraast.lexer.tokens import Token, TokenType
from yaraast.parser._shared import parse_regex_value as parse_shared_regex_value


def extract_comment_tokens(tokens: list[Token]) -> tuple[list[Token], list[Token]]:
    comment_tokens = []
    non_comment_tokens = []
    for token in tokens:
        if token.type == TokenType.COMMENT:
            comment_tokens.append(token)
        else:
            non_comment_tokens.append(token)
    return non_comment_tokens, comment_tokens


def collect_leading_comments(comment_tokens: list[Token], end_line: int) -> list[Comment]:
    comments = []
    for token in comment_tokens:
        if token.line < end_line:
            comment = Comment(
                text=token.value,
                is_multiline=token.value.startswith("/*"),
            )
            comment.location = _comment_location(token)
            comments.append(comment)
    return comments


def collect_trailing_comment(
    comment_tokens: list[Token], start_line: int
) -> tuple[Comment | None, list[Token]]:
    for i, token in enumerate(comment_tokens):
        if token.line == start_line:
            comment = Comment(
                text=token.value,
                is_multiline=token.value.startswith("/*"),
            )
            comment.location = _comment_location(token)
            remaining = comment_tokens[:i] + comment_tokens[i + 1 :]
            return comment, remaining
    return None, comment_tokens


def _comment_location(token: Token) -> Location:
    lines = str(token.value).splitlines() or [str(token.value)]
    if len(lines) == 1:
        return Location(
            line=token.line,
            column=token.column,
            end_line=token.line,
            end_column=token.column + max(1, len(lines[0])),
        )
    return Location(
        line=token.line,
        column=token.column,
        end_line=token.line + len(lines) - 1,
        end_column=max(1, len(lines[-1])) + 1,
    )


def parse_hex_tokens(hex_content: str):
    from yaraast.parser.hex_parser import HexStringParser

    return HexStringParser().parse(hex_content)


def parse_regex_value(regex_val: str):
    return parse_shared_regex_value(regex_val)
