"""Token-based mmap helpers for the streaming parser."""

from __future__ import annotations

from collections.abc import Iterator
import mmap

_IDENTIFIER_CHARS = frozenset("_abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789")


def _is_identifier_char(char: str) -> bool:
    return char in _IDENTIFIER_CHARS


def _matches_keyword(content: str, index: int, keyword: str) -> bool:
    end = index + len(keyword)
    if not content.startswith(keyword, index):
        return False
    if index > 0 and _is_identifier_char(content[index - 1]):
        return False
    return end >= len(content) or not _is_identifier_char(content[end])


def _previous_identifier(content: str, index: int) -> str:
    index -= 1
    while index >= 0 and content[index].isspace():
        index -= 1
    end = index + 1
    while index >= 0 and _is_identifier_char(content[index]):
        index -= 1
    return content[index + 1 : end]


def _skip_whitespace(content: str, index: int) -> int:
    while index < len(content) and content[index].isspace():
        index += 1
    return index


def _skip_line_comment(content: str, index: int) -> int:
    newline = content.find("\n", index + 2)
    if newline == -1:
        return len(content)
    return newline + 1


def _skip_block_comment(content: str, index: int) -> int:
    end = content.find("*/", index + 2)
    if end == -1:
        return len(content)
    return end + 2


def _skip_quoted_string(content: str, index: int) -> int:
    index += 1
    escaped = False
    while index < len(content):
        char = content[index]
        if escaped:
            escaped = False
        elif char == "\\":
            escaped = True
        elif char == '"':
            return index + 1
        index += 1
    return index


def _skip_regex_literal(content: str, index: int) -> int:
    index += 1
    escaped = False
    in_class = False
    while index < len(content):
        char = content[index]
        if escaped:
            escaped = False
        elif char == "\\":
            escaped = True
        elif char == "[":
            in_class = True
        elif char == "]":
            in_class = False
        elif char == "/" and not in_class:
            return index + 1
        index += 1
    return index


def _skip_non_code(content: str, index: int) -> int | None:
    if content.startswith("//", index):
        return _skip_line_comment(content, index)
    if content.startswith("/*", index):
        return _skip_block_comment(content, index)
    if content[index] == '"':
        return _skip_quoted_string(content, index)
    if content[index] == "/":
        return _skip_regex_literal(content, index)
    return None


def _rule_start_at(content: str, index: int) -> int | None:
    if _previous_identifier(content, index) == "extern":
        return None
    if _matches_keyword(content, index, "rule"):
        return index
    modifier_length = 0
    if _matches_keyword(content, index, "private"):
        modifier_length = len("private")
    elif _matches_keyword(content, index, "global"):
        modifier_length = len("global")
    else:
        return None
    rule_index = _skip_whitespace(content, index + modifier_length)
    if _matches_keyword(content, rule_index, "rule"):
        return index
    return None


def _find_rule_body_start(content: str, index: int) -> int | None:
    while index < len(content):
        skipped = _skip_non_code(content, index)
        if skipped is not None:
            index = skipped
            continue
        if content[index] == "{":
            return index
        index += 1
    return None


def _find_rule_end(content: str, index: int) -> int | None:
    brace_count = 1
    index += 1
    while index < len(content):
        skipped = _skip_non_code(content, index)
        if skipped is not None:
            index = skipped
            continue
        if content[index] == "{":
            brace_count += 1
        elif content[index] == "}":
            brace_count -= 1
            if brace_count == 0:
                return index + 1
        index += 1
    return None


def iter_rule_text_spans_from_text(content: str) -> Iterator[tuple[str, int, int]]:
    """Yield complete rule texts and their character spans from YARA source text."""
    index = 0
    while index < len(content):
        skipped = _skip_non_code(content, index)
        if skipped is not None:
            index = skipped
            continue
        rule_start = _rule_start_at(content, index)
        if rule_start is None:
            index += 1
            continue
        body_start = _find_rule_body_start(content, rule_start)
        if body_start is None:
            break
        end_pos = _find_rule_end(content, body_start)
        if end_pos is None:
            break
        yield content[rule_start:end_pos], rule_start, end_pos
        index = end_pos


def iter_rule_texts_from_text(content: str) -> Iterator[str]:
    """Yield complete rule texts from YARA source text."""
    for rule_text, _, _ in iter_rule_text_spans_from_text(content):
        yield rule_text


def iter_rule_text_byte_spans_from_mmap(
    mmapped_file: mmap.mmap,
) -> Iterator[tuple[str, int, int]]:
    """Yield complete rule texts and their byte spans from a memory-mapped YARA file."""
    try:
        content = mmapped_file.read().decode("utf-8")
    except UnicodeDecodeError as exc:
        msg = "YARA file must contain valid UTF-8 text"
        raise ValueError(msg) from exc
    mmapped_file.seek(0)
    current_char_pos = 0
    current_byte_pos = 0
    for rule_text, start_pos, end_pos in iter_rule_text_spans_from_text(content):
        current_byte_pos += len(content[current_char_pos:start_pos].encode("utf-8"))
        start_byte_pos = current_byte_pos
        current_byte_pos += len(content[start_pos:end_pos].encode("utf-8"))
        yield rule_text, start_byte_pos, current_byte_pos
        current_char_pos = end_pos
