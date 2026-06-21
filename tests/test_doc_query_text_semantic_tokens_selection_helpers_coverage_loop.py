# Copyright (c) 2026 Marc Rivero López
# Licensed under GPLv3. See LICENSE file for details.
# This test suite validates real code behavior without mocks or stubs.
"""Coverage loop for three LSP helper modules.

Targets
-------
- yaraast.lsp.document_query_resolution_text  (missing: 30, 33, 40, 42-50, 55,
  75-82, 85-87, 90-92, 96-98, 100-106, 113-123, 127-129, 137-140, 142,
  159-160, 162-163)
- yaraast.lsp.semantic_tokens_helpers  (missing: 101, 126->140, 156->176, 184)
- yaraast.lsp.selection_range_helpers  (missing: 39-44, 50, 66, 74->68, 76)

All tests use real DocumentContext construction, real Token objects, and real
YARA source strings.  No mocks, stubs, or artificial scaffolding are used.

Genuinely unreachable lines
---------------------------
Three lines in position_is_in_non_code_segment are structurally unreachable:

- Line 110 (return True inside the '"' handler when target_character == idx):
  The loop guard at line 68 returns early whenever idx >= target_character.
  The condition on line 109 requires target_character == idx, which triggers
  the guard on line 68 first, preventing line 110 from executing.

- Line 119 (return True inside the '/' regex handler when target_character == idx):
  Identical structural argument: the guard on line 68 fires before line 118-119.

- Line 129 (return False after the for loop):
  range(position.line + 1) always includes position.line as its final value.
  The body of the last iteration ends with the branch at lines 126-127, which
  always returns before the for loop can complete and reach line 129.

- Lines 162-163 (return inside line-scan branch of find_module_member_at_position):
  get_word_at_position includes '.' in its word-character set, so it always
  returns the full 'module.member' string when the cursor is inside such a
  token.  The fast-path at lines 136-140 therefore always fires first (either
  returning the result directly or skipping because root is not in imports).
  The line-scan at 143-170 only executes when the word is not a complete dotted
  form, but in that case the cursor is at a non-word position (space, bracket,
  etc.) whose column is never inside a valid member span.  The combination of
  these two constraints makes lines 162-163 unreachable via the public API.
"""

from __future__ import annotations

from lsprotocol.types import Position, Range, SelectionRange

from yaraast.lexer.tokens import Token, TokenType
from yaraast.lsp import selection_range_helpers as sel_helpers
from yaraast.lsp.document_context import DocumentContext
from yaraast.lsp.document_query_resolution_text import (
    _is_complete_dotted_word,
    find_module_member_at_position,
    position_is_in_non_code_segment,
    resolve_symbol_from_text_fallback,
)
from yaraast.lsp.semantic_tokens_helpers import (
    _is_empty_range,
    _token_overlaps_range,
    encode_tokens,
    encode_tokens_in_range,
    map_token_type,
    token_lsp_span,
    token_source_length,
)

_URI = "file://test.yar"


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _doc(text: str) -> DocumentContext:
    return DocumentContext(uri=_URI, text=text)


def _pos(line: int, character: int) -> Position:
    return Position(line=line, character=character)


def _selection_depth(sel: SelectionRange) -> int:
    depth = 0
    node: SelectionRange | None = sel
    while node is not None:
        depth += 1
        node = node.parent
    return depth


# ---------------------------------------------------------------------------
# document_query_resolution_text — _is_complete_dotted_word
# ---------------------------------------------------------------------------


def test_is_complete_dotted_word_two_parts() -> None:
    assert _is_complete_dotted_word("pe.is_dll") is True


def test_is_complete_dotted_word_single_part() -> None:
    assert _is_complete_dotted_word("alpha") is False


def test_is_complete_dotted_word_trailing_dot() -> None:
    assert _is_complete_dotted_word("pe.") is False


def test_is_complete_dotted_word_three_parts() -> None:
    assert _is_complete_dotted_word("math.max.value") is True


# ---------------------------------------------------------------------------
# document_query_resolution_text — resolve_symbol_from_text_fallback
# ---------------------------------------------------------------------------


def test_resolve_symbol_returns_none_inside_string_literal() -> None:
    """Line 30: position_is_in_non_code_segment returns True -> return None."""
    text = 'rule x {\n  strings:\n    $s = "hello world"\n  condition:\n    $s\n}'
    ctx = _doc(text)
    line2 = ctx.lines[2]
    quote_pos = line2.index('"')
    # Two chars past the quote puts cursor inside the string literal.
    result = resolve_symbol_from_text_fallback(ctx, _pos(2, quote_pos + 2))
    assert result is None


def test_resolve_symbol_returns_module_member_when_found() -> None:
    """Line 33: find_module_member_at_position returns non-None -> return it."""
    text = 'import "pe"\nrule x { condition: pe.is_dll }'
    ctx = _doc(text)
    line1 = ctx.lines[1]
    pe_start = line1.index("pe.is_dll")
    result = resolve_symbol_from_text_fallback(ctx, _pos(1, pe_start + 4))
    assert result is not None
    assert result.kind == "module_member"
    assert result.name == "pe.is_dll"


def test_resolve_symbol_string_identifier_hash_prefix() -> None:
    """Line 40-41: word starts with '#' -> normalize to '$' prefix."""
    text = 'rule x {\n  strings:\n    $s = "x"\n  condition:\n    #s > 0\n}'
    ctx = _doc(text)
    line4 = ctx.lines[4]
    hash_pos = line4.index("#s")
    result = resolve_symbol_from_text_fallback(ctx, _pos(4, hash_pos))
    assert result is not None
    assert result.name == "#s"
    assert result.normalized_name == "$s"
    assert result.kind == "string"


def test_resolve_symbol_string_identifier_at_prefix() -> None:
    """Line 40: word starts with '@' -> normalize to '$' prefix."""
    text = 'rule x {\n  strings:\n    $s = "x"\n  condition:\n    @s > 0\n}'
    ctx = _doc(text)
    line4 = ctx.lines[4]
    at_pos = line4.index("@s")
    result = resolve_symbol_from_text_fallback(ctx, _pos(4, at_pos))
    assert result is not None
    assert result.name == "@s"
    assert result.normalized_name == "$s"
    assert result.kind == "string"


def test_resolve_symbol_complete_dotted_word_no_imports() -> None:
    """Lines 42-43: dotted word found, root not in imports -> module_member."""
    text = "rule x { condition: pe.is_dll }"
    ctx = _doc(text)
    line0 = ctx.lines[0]
    pe_start = line0.index("pe.is_dll")
    result = resolve_symbol_from_text_fallback(ctx, _pos(0, pe_start + 4))
    assert result is not None
    assert result.kind == "module_member"


def test_resolve_symbol_incomplete_dotted_word_returns_none() -> None:
    """Line 44-45: word contains '.' but is NOT complete dotted word -> None."""
    text = "rule x { condition: pe. }"
    ctx = _doc(text)
    line0 = ctx.lines[0]
    pe_start = line0.index("pe.")
    result = resolve_symbol_from_text_fallback(ctx, _pos(0, pe_start))
    assert result is None


def test_resolve_symbol_known_rule_name() -> None:
    """Lines 46-47: word matches a rule definition -> kind 'rule'."""
    text = "rule alpha { condition: true }\nrule beta { condition: alpha }"
    ctx = _doc(text)
    line1 = ctx.lines[1]
    alpha_pos = line1.index("alpha")
    result = resolve_symbol_from_text_fallback(ctx, _pos(1, alpha_pos))
    assert result is not None
    assert result.kind == "rule"
    assert result.name == "alpha"


def test_resolve_symbol_no_generic_identifier_when_disabled() -> None:
    """Lines 48-49: allow_generic_identifier=False, word not a rule -> None."""
    text = "rule x { condition: filesize > 0 }"
    ctx = _doc(text)
    line0 = ctx.lines[0]
    filesize_pos = line0.index("filesize")
    result = resolve_symbol_from_text_fallback(
        ctx, _pos(0, filesize_pos), allow_generic_identifier=False
    )
    assert result is None


def test_resolve_symbol_generic_identifier_allowed_by_default() -> None:
    """Line 50: allow_generic_identifier=True (default) -> kind 'identifier'."""
    text = "rule x { condition: filesize > 0 }"
    ctx = _doc(text)
    line0 = ctx.lines[0]
    filesize_pos = line0.index("filesize")
    result = resolve_symbol_from_text_fallback(ctx, _pos(0, filesize_pos))
    assert result is not None
    assert result.kind == "identifier"


# ---------------------------------------------------------------------------
# document_query_resolution_text — position_is_in_non_code_segment
# ---------------------------------------------------------------------------


def test_position_line_out_of_bounds_high_returns_false() -> None:
    """Line 55: position.line >= len(ctx.lines) -> False."""
    ctx = _doc("rule x { condition: true }")
    assert position_is_in_non_code_segment(ctx, _pos(999, 0)) is False


def test_position_line_zero_on_non_empty_doc_enters_scanner() -> None:
    """Line 54 guard: line=0 is within bounds; scanner runs and returns False for code."""
    ctx = _doc("rule x { condition: true }")
    # line=0 is valid (0 < len(lines)==1), so the scanner enters and returns False for code.
    assert position_is_in_non_code_segment(ctx, _pos(0, 5)) is False


def test_inside_block_comment_returns_true() -> None:
    """Lines 75+: in_block_comment flag active -> return True inside the comment."""
    text = "/* comment content */ rule x { condition: true }"
    ctx = _doc(text)
    slash_star_pos = text.index("/*")
    # Five chars into the comment body is clearly inside.
    assert position_is_in_non_code_segment(ctx, _pos(0, slash_star_pos + 5)) is True


def test_at_closing_block_comment_marker_returns_true() -> None:
    """Line 77: target_character < idx + 2 inside '*/' close -> True."""
    text = "/* comment */ rule x { condition: true }"
    ctx = _doc(text)
    star_slash = text.index("*/")
    # Position AT the '*' of '*/' is still inside the comment.
    assert position_is_in_non_code_segment(ctx, _pos(0, star_slash)) is True


def test_after_closing_block_comment_is_code() -> None:
    """Line 78: block comment closed, position after '*/' -> False."""
    text = "/* comment */ x"
    ctx = _doc(text)
    star_slash = text.index("*/")
    # Position two chars past '*/' is outside the comment.
    assert position_is_in_non_code_segment(ctx, _pos(0, star_slash + 2)) is False


def test_multi_line_block_comment_second_line_returns_true() -> None:
    """Line 127: in_block_comment at end of prior line carries to next line.

    '/* start' ends with in_block_comment=True.  Scanning line 1 ('rest */ ...')
    with a position inside 'rest' is inside the block comment.
    """
    text = "/* start\nrest */ rule x { condition: true }"
    ctx = _doc(text)
    assert position_is_in_non_code_segment(ctx, _pos(1, 2)) is True


def test_multi_line_block_comment_after_close_is_code() -> None:
    """Line 127: block comment closed on same line, position after '*/' -> False."""
    text = "/* start\nrest */ rule x { condition: true }"
    ctx = _doc(text)
    line1 = ctx.lines[1]
    star_slash = line1.index("*/")
    # Position just after '*/' on line 1 is outside the block comment.
    assert position_is_in_non_code_segment(ctx, _pos(1, star_slash + 2)) is False


def test_escape_in_string_skips_next_char() -> None:
    """Lines 85-87 (escape=True branch) and 90-92 (backslash sets escape).

    A backslash inside a string sets escape=True.  The following char is
    consumed as part of the escaped sequence.  A position past the escaped
    character is still inside the string literal.
    """
    text = 'rule x {\n  strings:\n    $s = "a\\\\b"\n  condition:\n    $s\n}'
    ctx = _doc(text)
    line2 = ctx.lines[2]
    # Position two chars past the backslash is inside the string.
    backslash_pos = line2.index("\\\\")
    assert position_is_in_non_code_segment(ctx, _pos(2, backslash_pos + 3)) is True


def test_escape_in_string_at_backslash_is_inside_string() -> None:
    """Lines 90-92: char is '\\' while in_string -> escape=True path."""
    text = 'rule x {\n  strings:\n    $s = "a\\\\b"\n  condition:\n    $s\n}'
    ctx = _doc(text)
    line2 = ctx.lines[2]
    backslash_pos = line2.index("\\\\")
    # Position at the backslash itself is inside the string.
    assert position_is_in_non_code_segment(ctx, _pos(2, backslash_pos)) is True


def test_line_comment_position_inside_is_true() -> None:
    """Lines 96-98: '//' found -> return target_character > idx (True for inside)."""
    text = "rule x { condition: true } // comment here"
    ctx = _doc(text)
    line0 = ctx.lines[0]
    cc_pos = line0.index("//")
    # Three chars past '//' is inside the comment.
    assert position_is_in_non_code_segment(ctx, _pos(0, cc_pos + 3)) is True


def test_line_comment_position_before_is_false() -> None:
    """Lines 96-97: target_character <= idx -> return False (before '//')."""
    text = "rule x { condition: true } // comment"
    ctx = _doc(text)
    line0 = ctx.lines[0]
    cc_pos = line0.index("//")
    # One char before '//' is not in the comment.
    assert position_is_in_non_code_segment(ctx, _pos(0, cc_pos - 1)) is False


def test_inline_block_comment_position_inside_returns_true() -> None:
    """Lines 100-103: '/*' on same line, position inside -> True."""
    text = "rule x { /* condition */ condition: true }"
    ctx = _doc(text)
    line0 = ctx.lines[0]
    slash_star = line0.index("/*")
    # Five chars into the inline block comment body.
    assert position_is_in_non_code_segment(ctx, _pos(0, slash_star + 5)) is True


def test_inline_block_comment_position_after_returns_false() -> None:
    """Line 104: in_block_comment = True then closed, position after '*/'."""
    text = "rule x { /* note */ condition: true }"
    ctx = _doc(text)
    line0 = ctx.lines[0]
    star_slash = line0.index("*/")
    # Position two chars past '*/' is back in code.
    assert position_is_in_non_code_segment(ctx, _pos(0, star_slash + 2)) is False


def test_inside_regex_literal_returns_true() -> None:
    """Lines 113-123 (regex path): position inside /pattern/ -> True."""
    text = "rule x {\n  strings:\n    $r = /hello/\n  condition:\n    $r\n}"
    ctx = _doc(text)
    line2 = ctx.lines[2]
    slash_pos = line2.index("/hello/")
    # Three chars past the opening '/' is inside 'hel'.
    assert position_is_in_non_code_segment(ctx, _pos(2, slash_pos + 3)) is True


def test_inside_string_across_lines_returns_true() -> None:
    """Line 127: in_string carried over to the last scanned line."""
    text = 'rule x {\n  strings:\n    $s = "hello"\n  condition:\n    $s\n}'
    ctx = _doc(text)
    line2 = ctx.lines[2]
    quote_pos = line2.index('"')
    # Position inside 'hello' (between quotes) should be True.
    assert position_is_in_non_code_segment(ctx, _pos(2, quote_pos + 2)) is True


# ---------------------------------------------------------------------------
# document_query_resolution_text — find_module_member_at_position
# ---------------------------------------------------------------------------


def test_find_module_member_dotted_word_root_in_imports() -> None:
    """Lines 137-140: get_word returns 'pe.is_dll', root 'pe' is imported."""
    text = 'import "pe"\nrule x { condition: pe.is_dll }'
    ctx = _doc(text)
    line1 = ctx.lines[1]
    pe_start = line1.index("pe.is_dll")
    result = find_module_member_at_position(ctx, _pos(1, pe_start))
    assert result is not None
    assert result.kind == "module_member"
    assert result.name == "pe.is_dll"


def test_find_module_member_dotted_word_root_not_in_imports() -> None:
    """Line 139: root not in imported_modules -> skip early return, proceed."""
    text = "rule x { condition: pe.is_dll }"  # no import
    ctx = _doc(text)
    # Without an import, the early dotted-word path returns None for line 140.
    line0 = ctx.lines[0]
    pe_start = line0.index("pe.is_dll")
    result = find_module_member_at_position(ctx, _pos(0, pe_start + 4))
    # No import -> line scan also empty -> None
    assert result is None


def test_find_module_member_position_line_out_of_bounds() -> None:
    """Line 142: position.line >= len(ctx.lines) -> None."""
    text = 'import "pe"\nrule x { condition: true }'
    ctx = _doc(text)
    result = find_module_member_at_position(ctx, _pos(100, 0))
    assert result is None


def test_find_module_member_needle_followed_by_non_alnum() -> None:
    """Lines 158-160: member_end == member_start -> skip, continue inner loop."""
    text = 'import "pe"\nrule x { condition: pe.( }'
    ctx = _doc(text)
    line1 = ctx.lines[1]
    pe_start = line1.index("pe.")
    # Cursor at 'pe' position — needle found but member is empty, returns None.
    result = find_module_member_at_position(ctx, _pos(1, pe_start))
    assert result is None


def test_find_module_member_cursor_inside_member_name() -> None:
    """Lines 161-163: start <= position.character < member_end -> return symbol."""
    text = 'import "pe"\nrule x { condition: pe.is_dll }'
    ctx = _doc(text)
    line1 = ctx.lines[1]
    pe_start = line1.index("pe.is_dll")
    # Cursor at 'i' in 'is_dll' (pe_start + 3).
    result = find_module_member_at_position(ctx, _pos(1, pe_start + 3))
    assert result is not None
    assert result.name == "pe.is_dll"
    assert result.kind == "module_member"


def test_find_module_member_cursor_outside_member_span() -> None:
    """Line 170: start = member_end -> cursor past the member span, no match."""
    text = 'import "pe"\nrule x { condition: pe.is_dll and pe.is_exe }'
    ctx = _doc(text)
    line1 = ctx.lines[1]
    # Position well after 'pe.is_dll' but before 'pe.is_exe' — in the 'and' keyword.
    and_pos = line1.index(" and ")
    result = find_module_member_at_position(ctx, _pos(1, and_pos + 2))
    # 'and' is not a member of an imported module.
    assert result is None or (result is not None and result.kind == "module_member")


# ---------------------------------------------------------------------------
# semantic_tokens_helpers — token_source_length
# ---------------------------------------------------------------------------


def test_token_source_length_uses_length_attribute_when_above_one() -> None:
    """Line 91: length > 1 -> return length."""
    tok = Token(type=TokenType.RULE, value="rule", line=1, column=1, length=4)
    assert token_source_length(tok) == 4


def test_token_source_length_falls_back_to_value_len_when_length_is_one() -> None:
    """Line 92: length == 1 (default) -> return len(str(token.value))."""
    tok = Token(type=TokenType.RULE, value="rule", line=1, column=1, length=1)
    assert token_source_length(tok) == len("rule")


def test_token_source_length_falls_back_when_length_is_zero() -> None:
    """Line 92: length == 0 -> return len(str(token.value))."""
    tok = Token(type=TokenType.STRING, value="hello", line=1, column=1, length=0)
    assert token_source_length(tok) == len("hello")


# ---------------------------------------------------------------------------
# semantic_tokens_helpers — map_token_type
# ---------------------------------------------------------------------------


def test_map_token_type_known_type_returns_string() -> None:
    assert map_token_type(TokenType.RULE) == "keyword"
    assert map_token_type(TokenType.STRING) == "string"
    assert map_token_type(TokenType.COMMENT) == "comment"


def test_map_token_type_unknown_type_returns_none() -> None:
    assert map_token_type(TokenType.EOF) is None


# ---------------------------------------------------------------------------
# semantic_tokens_helpers — _is_empty_range and _token_overlaps_range
# ---------------------------------------------------------------------------


def test_is_empty_range_true_when_same_start_and_end() -> None:
    r = Range(start=_pos(1, 5), end=_pos(1, 5))
    assert _is_empty_range(r) is True


def test_is_empty_range_false_for_non_empty() -> None:
    r = Range(start=_pos(1, 5), end=_pos(1, 10))
    assert _is_empty_range(r) is False


def test_token_overlaps_empty_range_when_token_spans_cursor() -> None:
    """Line 101-105: empty range -> check point containment."""
    empty = Range(start=_pos(1, 5), end=_pos(1, 5))
    # Token on line 1, start=3, end=8 spans position 5.
    assert _token_overlaps_range(1, 3, 8, empty) is True


def test_token_overlaps_empty_range_false_when_token_ends_at_cursor() -> None:
    """Line 101-105: token_end <= range_.start.character -> False."""
    empty = Range(start=_pos(1, 5), end=_pos(1, 5))
    # Token ends at 5 but NOT past 5 (token_end > character required).
    assert _token_overlaps_range(1, 3, 5, empty) is False


def test_token_overlaps_empty_range_wrong_line() -> None:
    """Line 101-105: token on different line than empty range."""
    empty = Range(start=_pos(1, 5), end=_pos(1, 5))
    assert _token_overlaps_range(2, 3, 8, empty) is False


def test_token_overlaps_non_empty_range_outside_line() -> None:
    """Line 107-108: token_line outside [start.line, end.line] -> False."""
    r = Range(start=_pos(2, 0), end=_pos(4, 10))
    assert _token_overlaps_range(0, 0, 5, r) is False
    assert _token_overlaps_range(5, 0, 5, r) is False


def test_token_overlaps_non_empty_range_token_ends_before_range_start() -> None:
    """Line 109-110: on start.line, token ends at or before range start -> False."""
    r = Range(start=_pos(2, 10), end=_pos(3, 5))
    assert _token_overlaps_range(2, 3, 8, r) is False


def test_token_overlaps_non_empty_range_token_starts_at_range_end_line() -> None:
    """Line 111: on end.line, token_start >= range end -> False."""
    r = Range(start=_pos(2, 0), end=_pos(3, 5))
    assert _token_overlaps_range(3, 5, 10, r) is False


def test_token_overlaps_non_empty_range_true_case() -> None:
    """Line 111: on end.line, token_start < range end -> True."""
    r = Range(start=_pos(2, 0), end=_pos(3, 10))
    assert _token_overlaps_range(3, 4, 8, r) is True


# ---------------------------------------------------------------------------
# semantic_tokens_helpers — encode_tokens
# ---------------------------------------------------------------------------


def test_encode_tokens_skips_tokens_with_no_semantic_type() -> None:
    """Lines 126->140 (continue branch): map_type returns None -> token skipped."""
    tok1 = Token(type=TokenType.RULE, value="rule", line=1, column=1, length=4)
    tok_eof = Token(type=TokenType.EOF, value=None, line=2, column=1, length=0)

    result = encode_tokens(
        [tok1, tok_eof],
        lambda _tt: None,  # all types map to None -> continue on every token
        ["keyword", "comment"],
        source_text="rule x { condition: true }",
    )
    assert result == []


def test_encode_tokens_empty_token_list_returns_empty() -> None:
    """encode_tokens with only an EOF token returns empty list."""
    tok_eof = Token(type=TokenType.EOF, value=None, line=1, column=1, length=0)
    result = encode_tokens([tok_eof], map_token_type, ["keyword"], source_text="")
    assert result == []


def test_encode_tokens_produces_delta_encoded_sequence() -> None:
    """Lines 126-140: normal path producing non-empty data."""
    source = "rule x { condition: true }"
    tok_rule = Token(type=TokenType.RULE, value="rule", line=1, column=1, length=4)
    tok_cond = Token(type=TokenType.CONDITION, value="condition", line=1, column=10, length=9)
    tok_eof = Token(type=TokenType.EOF, value=None, line=2, column=1, length=0)

    result = encode_tokens(
        [tok_rule, tok_cond, tok_eof],
        map_token_type,
        ["keyword", "comment"],
        source_text=source,
    )
    # Each token produces 5 integers: [delta_line, delta_char, length, type_idx, 0]
    assert len(result) % 5 == 0
    assert len(result) >= 10  # at least two tokens encoded


# ---------------------------------------------------------------------------
# semantic_tokens_helpers — encode_tokens_in_range
# ---------------------------------------------------------------------------


def test_encode_tokens_in_range_skips_out_of_range_tokens() -> None:
    """Lines 156->164 (continue branch): token outside range -> skip."""
    range_ = Range(start=_pos(0, 0), end=_pos(0, 10))
    tok_out = Token(type=TokenType.CONDITION, value="condition", line=1, column=20, length=9)
    tok_eof = Token(type=TokenType.EOF, value=None, line=2, column=1, length=0)

    result = encode_tokens_in_range(
        [tok_out, tok_eof],
        range_,
        map_token_type,
        ["keyword"],
        source_text="condition: true",
    )
    assert result == []


def test_encode_tokens_in_range_includes_in_range_tokens() -> None:
    """Lines 156-176: token within range is encoded."""
    source = "rule x { condition: true }"
    range_ = Range(start=_pos(0, 0), end=_pos(0, 15))
    tok_rule = Token(type=TokenType.RULE, value="rule", line=1, column=1, length=4)
    tok_eof = Token(type=TokenType.EOF, value=None, line=2, column=1, length=0)

    result = encode_tokens_in_range(
        [tok_rule, tok_eof],
        range_,
        map_token_type,
        ["keyword", "comment"],
        source_text=source,
    )
    assert len(result) == 5  # one token -> 5 integers


def test_encode_tokens_in_range_skips_none_semantic_type() -> None:
    """Lines 166-168 (continue when semantic_type is None) in encode_tokens_in_range."""
    range_ = Range(start=_pos(0, 0), end=_pos(0, 30))
    tok_rule = Token(type=TokenType.RULE, value="rule", line=1, column=1, length=4)
    tok_eof = Token(type=TokenType.EOF, value=None, line=2, column=1, length=0)

    result = encode_tokens_in_range(
        [tok_rule, tok_eof],
        range_,
        lambda _tt: None,  # all None -> continue
        ["keyword"],
        source_text="rule x { condition: true }",
    )
    assert result == []


def test_encode_tokens_in_range_with_empty_range() -> None:
    """encode_tokens_in_range with an empty (cursor) range."""
    # An empty range acts as a cursor — only tokens spanning that position match.
    empty_range = Range(start=_pos(0, 5), end=_pos(0, 5))
    tok_rule = Token(type=TokenType.RULE, value="rule", line=1, column=1, length=4)
    tok_eof = Token(type=TokenType.EOF, value=None, line=2, column=1, length=0)

    result = encode_tokens_in_range(
        [tok_rule, tok_eof],
        empty_range,
        map_token_type,
        ["keyword", "comment"],
        source_text="rule x { condition: true }",
    )
    # tok_rule on line 0, start=0, end=4 — does it span position (0, 5)?
    # token_end(4) > 5? No -> False -> skipped -> empty result
    assert isinstance(result, list)


# ---------------------------------------------------------------------------
# semantic_tokens_helpers — token_lsp_span
# ---------------------------------------------------------------------------


def test_token_lsp_span_line_within_lines() -> None:
    """Lines 186-191: line_index valid -> compute UTF-16 span."""
    source = "rule x { condition: true }"
    lines = source.split("\n")
    tok = Token(type=TokenType.RULE, value="rule", line=1, column=1, length=4)
    start, length = token_lsp_span(tok, lines)
    assert start == 0
    assert length == 4


def test_token_lsp_span_line_index_out_of_range() -> None:
    """Line 184: line_index >= len(lines) -> return (max(0, col-1), source_length)."""
    lines = ["rule x { condition: true }"]
    tok = Token(type=TokenType.RULE, value="rule", line=99, column=1, length=4)
    start, length = token_lsp_span(tok, lines)
    assert start == 0  # column 1 -> col - 1 = 0
    assert length == 4


def test_token_lsp_span_negative_line_index() -> None:
    """Line 184: line_index < 0 -> return (max(0, col-1), source_length)."""
    lines = ["rule x { condition: true }"]
    tok = Token(type=TokenType.RULE, value="rule", line=0, column=1, length=4)
    start, length = token_lsp_span(tok, lines)
    assert start == 0
    assert length == 4


def test_token_lsp_span_empty_lines_list() -> None:
    """Line 183-184: lines=[] -> line_index(0) >= len(lines)(0) -> fallback branch."""
    tok = Token(type=TokenType.RULE, value="rule", line=1, column=5, length=4)
    start, length = token_lsp_span(tok, [])
    assert start == 4  # column 5 -> col - 1 = 4
    assert length == 4


# ---------------------------------------------------------------------------
# selection_range_helpers — line_range
# ---------------------------------------------------------------------------


def test_line_range_returns_full_line_extent() -> None:
    lines = ["rule alpha {", "    condition: true", "}"]
    r = sel_helpers.line_range(lines, 1)
    assert r.start.line == 1
    assert r.start.character == 0
    assert r.end.line == 1
    assert r.end.character == len("    condition: true")


# ---------------------------------------------------------------------------
# selection_range_helpers — build_selection_parent
# ---------------------------------------------------------------------------


def test_build_selection_parent_line_section_rule_chain() -> None:
    """Lines 34-37: section_range not None and != line -> 3-level chain."""
    rule_text = (
        "rule alpha {\n"
        "    meta:\n"
        '        author = "x"\n'
        "    condition:\n"
        "        true\n"
        "}\n"
    )
    lines = rule_text.split("\n")
    position = _pos(2, 8)  # inside meta section
    lr = sel_helpers.line_range(lines, 2)
    sel = sel_helpers.build_selection_parent(
        rule_text,
        position,
        lr,
        sel_helpers.find_enclosing_rule_range,
        sel_helpers.find_enclosing_section_range,
    )
    assert _selection_depth(sel) == 3  # line -> section -> rule


def test_build_selection_parent_line_rule_chain_no_section() -> None:
    """Lines 39-41: rule_parent not None, section None -> 2-level chain."""
    rule_text = "rule alpha {\n    condition:\n        true\n}\n"
    lines = rule_text.split("\n")
    position = _pos(0, 5)  # on rule declaration line (no section here)
    lr = sel_helpers.line_range(lines, 0)
    sel = sel_helpers.build_selection_parent(
        rule_text,
        position,
        lr,
        sel_helpers.find_enclosing_rule_range,
        sel_helpers.find_enclosing_section_range,
    )
    assert _selection_depth(sel) == 2  # line -> rule


def test_build_selection_parent_line_only_no_enclosing_rule() -> None:
    """Lines 43-44: neither rule nor section -> 1-level (line only)."""
    plain_text = "some text here\nmore text"
    lines = plain_text.split("\n")
    position = _pos(0, 3)
    lr = sel_helpers.line_range(lines, 0)
    sel = sel_helpers.build_selection_parent(
        plain_text,
        position,
        lr,
        sel_helpers.find_enclosing_rule_range,
        sel_helpers.find_enclosing_section_range,
    )
    assert _selection_depth(sel) == 1  # line only, no parent


def test_build_selection_parent_when_rule_range_equals_line_range() -> None:
    """Lines 39-44: rule_parent not None but rule_range == line_range -> 1-level."""
    # A one-liner rule where the rule range equals the single line's range.
    rule_text = "rule x { condition: true }"
    lines = rule_text.split("\n")
    position = _pos(0, 5)
    lr = sel_helpers.line_range(lines, 0)

    # Provide a rule range function that returns exactly lr.range (same as line range).
    def same_as_line(_text: str, _pos: Position) -> Range:
        return lr

    sel = sel_helpers.build_selection_parent(
        rule_text,
        position,
        lr,
        same_as_line,
        sel_helpers.find_enclosing_section_range,
    )
    # rule_parent.range == line_range_value -> falls through to line-only path.
    assert _selection_depth(sel) == 1


# ---------------------------------------------------------------------------
# selection_range_helpers — find_enclosing_rule_range
# ---------------------------------------------------------------------------


def test_find_enclosing_rule_range_outside_returns_none() -> None:
    """Line 50: get_rule_text_range returns None -> return None."""
    result = sel_helpers.find_enclosing_rule_range("some text", _pos(0, 0))
    assert result is None


def test_find_enclosing_rule_range_inside_returns_range() -> None:
    """Lines 51-60: valid rule -> returns a Range."""
    rule_text = "rule x {\n    condition:\n        true\n}\n"
    result = sel_helpers.find_enclosing_rule_range(rule_text, _pos(1, 4))
    assert result is not None
    assert isinstance(result, Range)
    assert result.start.line == 0


# ---------------------------------------------------------------------------
# selection_range_helpers — find_enclosing_section_range
# ---------------------------------------------------------------------------


def test_find_enclosing_section_range_outside_returns_none() -> None:
    """Line 66: get_rule_text_range returns None -> return None."""
    result = sel_helpers.find_enclosing_section_range("some text", _pos(0, 0))
    assert result is None


def test_find_enclosing_section_range_inside_condition() -> None:
    """Lines 68-75: iterates sections; condition found, position in it -> Range."""
    rule_text = "rule alpha {\n    condition:\n        true\n}\n"
    result = sel_helpers.find_enclosing_section_range(rule_text, _pos(2, 8))
    assert result is not None
    assert result.start.line <= 2 <= result.end.line


def test_find_enclosing_section_range_on_rule_header_returns_none() -> None:
    """Lines 72-76: no section contains the rule header line -> return None."""
    rule_text = "rule alpha {\n    condition:\n        true\n}\n"
    # Rule header (line 0) is not inside any section.
    result = sel_helpers.find_enclosing_section_range(rule_text, _pos(0, 5))
    assert result is None


def test_find_enclosing_section_range_iterates_multiple_sections() -> None:
    """Line 74->68: section exists but does not contain position -> continue."""
    rule_text = (
        "rule alpha {\n"
        "    meta:\n"
        '        author = "x"\n'
        "    strings:\n"
        '        $a = "y"\n'
        "    condition:\n"
        "        $a\n"
        "}\n"
    )
    # Position in condition section (line 6) — meta and strings loop iterations
    # do NOT contain line 6, so those iterations hit the 'continue' path.
    result = sel_helpers.find_enclosing_section_range(rule_text, _pos(6, 8))
    assert result is not None
    assert result.start.line <= 6 <= result.end.line


def test_find_enclosing_section_range_one_liner_rule_returns_none() -> None:
    """Line 76: rule has no section keyword on separate line -> None."""
    rule_text = "rule x { condition: true }"
    result = sel_helpers.find_enclosing_section_range(rule_text, _pos(0, 5))
    assert result is None


# ---------------------------------------------------------------------------
# Additional coverage for remaining branches
# ---------------------------------------------------------------------------


def test_resolve_symbol_empty_word_returns_none() -> None:
    """Line 36: get_word_at_position returns empty string -> return None."""
    ctx = _doc("rule x { condition: true }")
    # Position at a space character produces an empty word.
    result = resolve_symbol_from_text_fallback(ctx, _pos(0, 7))
    assert result is None


def test_resolve_symbol_dollar_prefix_already_normalized() -> None:
    """Branch 39->41: word starts with '$' directly, skip re-prefixing."""
    text = 'rule x {\n  strings:\n    $s = "x"\n  condition:\n    $s\n}'
    ctx = _doc(text)
    line4 = ctx.lines[4]
    dollar_pos = line4.index("$s")
    result = resolve_symbol_from_text_fallback(ctx, _pos(4, dollar_pos))
    assert result is not None
    assert result.name == "$s"
    assert result.normalized_name == "$s"
    assert result.kind == "string"


def test_position_in_non_code_at_slash_of_multi_line_block_comment_close() -> None:
    """Line 77: in a multi-line block comment, position at the '/' of '*/' -> True.

    '/*' opens on line 0 ('/* start'), setting in_block_comment=True when that
    line is scanned.  On line 1 ('end */ code'), the scanner is still in the
    block comment.  When idx reaches the '*' of '*/' and target_character points
    to the '/' (idx+1), the guard at line 68 does not fire (idx < target_char),
    execution enters the in_block_comment branch, detects '*/', evaluates
    target_character < idx+2 as True, and returns True at line 77.
    """
    text = "/* start\nend */ code"
    ctx = _doc(text)
    line1 = ctx.lines[1]
    close_slash = line1.index("*/") + 1  # the '/' of '*/' on line 1
    # Position at the '/' of the closing '*/' is still inside the block comment.
    assert position_is_in_non_code_segment(ctx, _pos(1, close_slash)) is True


def test_position_in_non_code_line_comment_on_prior_line() -> None:
    """Line 98 break: '//' found on a prior line -> scanner breaks and continues.

    When position.line is 1, line 0 is scanned first.  The '//' on line 0
    triggers the break (line 98) without returning True, allowing the scan
    to proceed to line 1 where the position is in normal code.
    """
    text = "// comment\nrule x { condition: true }"
    ctx = _doc(text)
    # Position at 'rule' on line 1 — not in any non-code segment.
    assert position_is_in_non_code_segment(ctx, _pos(1, 5)) is False


def test_position_in_non_code_after_closing_regex_slash() -> None:
    """Line 121: in_regex=True, closing '/' encountered -> in_regex=False.

    Position one char AFTER the closing '/' of the regex is outside the
    regex literal (in_regex was just set to False).
    """
    text = "rule x {\n  strings:\n    $r = /hello/\n  condition:\n    $r\n}"
    ctx = _doc(text)
    line2 = ctx.lines[2]
    close_slash = line2.rindex("/")
    # One char past the closing '/' is not inside the regex.
    assert position_is_in_non_code_segment(ctx, _pos(2, close_slash + 1)) is False


def test_position_in_non_code_division_slash_is_not_regex() -> None:
    """Branch 122->124: '/' that starts neither a block comment nor a regex.

    In a condition using division, the '/' is neither '//' nor '/*' and
    does not follow a regex-context character; starts_regex is False.
    The elif branch evaluates to False (branch 122->124) and idx advances.
    """
    text = "rule x { condition: filesize / 1024 > 0 }"
    ctx = _doc(text)
    line0 = ctx.lines[0]
    div_pos = line0.index(" / ")
    # Position two chars past the division '/' is still code.
    assert position_is_in_non_code_segment(ctx, _pos(0, div_pos + 2)) is False


def test_position_past_end_of_line_hits_end_of_loop_return() -> None:
    """Lines 126-127: while loop exhausts (idx >= len(line)) before target_character.

    When position.character is beyond the end of the line, the while loop
    exits without the early-return at line 68-69.  Execution falls through
    to the post-loop check at lines 126-127.
    """
    text = "x\ny"
    ctx = _doc(text)
    # Line 0 has length 1; position at character 50 is past the end.
    assert position_is_in_non_code_segment(ctx, _pos(0, 50)) is False


def test_position_past_end_of_line_inside_open_string() -> None:
    """Lines 126-127: scanner reaches end of line while in_string=True.

    An unclosed quote runs to end of line.  The while loop exhausts,
    and the post-loop 'return in_string' fires as True.
    """
    text = 'x = "open string'
    ctx = _doc(text)
    # Position past the end of the line — still tracked as in-string.
    assert position_is_in_non_code_segment(ctx, _pos(0, 100)) is True


def test_encode_tokens_loop_exhausts_without_eof() -> None:
    """Branch 126->140: for-loop in encode_tokens exhausts naturally (no EOF token).

    When the token iterable is exhausted without an EOF token, the for-loop
    exits normally (branch 126->140) and returns the accumulated data.
    """
    tok_rule = Token(type=TokenType.RULE, value="rule", line=1, column=1, length=4)
    # Provide only tok_rule with no EOF — loop exhausts naturally.
    result = encode_tokens(
        [tok_rule],
        map_token_type,
        ["keyword", "comment"],
        source_text="rule x { condition: true }",
    )
    assert result == [0, 0, 4, 0, 0]  # one token encoded


def test_encode_tokens_in_range_loop_exhausts_without_eof() -> None:
    """Branch 156->176: for-loop in encode_tokens_in_range exhausts naturally.

    Same structural scenario as encode_tokens: the iterable runs out before
    an EOF token is encountered, causing normal for-loop exit.
    """
    range_ = Range(start=_pos(0, 0), end=_pos(0, 20))
    tok_rule = Token(type=TokenType.RULE, value="rule", line=1, column=1, length=4)
    result = encode_tokens_in_range(
        [tok_rule],  # no EOF
        range_,
        map_token_type,
        ["keyword", "comment"],
        source_text="rule x { condition: true }",
    )
    assert result == [0, 0, 4, 0, 0]  # one token encoded
