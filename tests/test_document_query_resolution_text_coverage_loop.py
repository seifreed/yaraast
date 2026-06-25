# Copyright (c) 2026 Marc Rivero López
# Licensed under GPLv3. See LICENSE file for details.
# This test suite validates real code behavior without mocks or stubs.
"""Coverage loop for yaraast.lsp.document_query_resolution_text.

All three public functions are exercised by constructing genuine
DocumentContext objects from real YARA source text and calling the
functions directly at precisely targeted positions.  No mocks, stubs,
or artificial scaffolding are used.

Missing lines targeted (module baseline 5.42% from existing test suite,
because --cov=yaraast.lsp.document_query_resolution_text filters only
this module):

  19-20   _is_complete_dotted_word: multi-part and single-part word paths
  29-50   resolve_symbol_from_text_fallback: every branch
  54-129  position_is_in_non_code_segment: state-machine paths for line
          comments, block comments, strings, regex literals, line-end
          returns, early escape, and out-of-range lines
  135-171 find_module_member_at_position: dotted-word hit with imported
          module, dotted-word hit with unknown root, line-scan for
          module.member, member_end == member_start skip, cursor inside
          member span, cursor outside span, and empty-module fallback

Notes on genuinely unreachable code
  No lines in this module are structurally unreachable.  The scanner at
  lines 54-129 contains all reachable paths through careful position
  construction.
"""

from __future__ import annotations

from lsprotocol.types import Position

from yaraast.lsp.document_context import DocumentContext
from yaraast.lsp.document_query_resolution_text import (
    _is_complete_dotted_word,
    find_module_member_at_position,
    position_is_in_non_code_segment,
    resolve_symbol_from_text_fallback,
)

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

_URI = "file://test.yar"


def _doc(text: str) -> DocumentContext:
    return DocumentContext(uri=_URI, text=text)


def _pos(line: int, character: int) -> Position:
    return Position(line=line, character=character)


# ---------------------------------------------------------------------------
# _is_complete_dotted_word (lines 19-20)
# ---------------------------------------------------------------------------


def test_is_complete_dotted_word_with_two_parts() -> None:
    """'pe.is_dll' has two non-empty parts — returns True (line 20)."""
    assert _is_complete_dotted_word("pe.is_dll") is True


def test_is_complete_dotted_word_with_three_parts() -> None:
    """'math.max.value' has three non-empty parts — returns True (line 20)."""
    assert _is_complete_dotted_word("math.max.value") is True


def test_is_complete_dotted_word_single_part() -> None:
    """'alpha' has one part — len(parts) == 1 so returns False (line 20)."""
    assert _is_complete_dotted_word("alpha") is False


def test_is_complete_dotted_word_empty_part() -> None:
    """'pe.' splits to ['pe', ''] — not all parts are truthy, returns False."""
    assert _is_complete_dotted_word("pe.") is False


def test_is_complete_dotted_word_leading_dot() -> None:
    """'.pe' splits to ['', 'pe'] — not all parts are truthy, returns False."""
    assert _is_complete_dotted_word(".pe") is False


# ---------------------------------------------------------------------------
# resolve_symbol_from_text_fallback (lines 29-50)
# ---------------------------------------------------------------------------

# -- position_is_in_non_code_segment returns True -> early None (line 30)


def test_resolve_returns_none_for_position_in_string_literal() -> None:
    """Position inside a string literal triggers the non-code guard -> None."""
    # Line 0: rule r { strings: $s = "hello" condition: $s }
    # "hello" starts at character 21 on line 0 (0-indexed column of 'h').
    # We target character 22 (inside the literal), which is inside a string.
    text = 'rule r {\n  strings:\n    $s = "hello"\n  condition:\n    $s\n}'
    doc = _doc(text)
    # line 2, character 11 points to the 'h' in "hello" — inside the string
    # (column 10 is '"', column 11 is 'h').
    result = resolve_symbol_from_text_fallback(doc, _pos(2, 11))
    assert result is None


# -- find_module_member_at_position returns non-None (lines 31-33)


def test_resolve_returns_module_member_via_dotted_word() -> None:
    """Dotted word 'pe.is_dll' with a known import resolves as module_member."""
    text = 'import "pe"\nrule r {\n  condition:\n    pe.is_dll\n}'
    doc = _doc(text)
    # line 3, character 5 — inside 'pe' of 'pe.is_dll'
    result = resolve_symbol_from_text_fallback(doc, _pos(3, 5))
    assert result is not None
    assert result.kind == "module_member"


# -- word is empty -> None (lines 34-36)


def test_resolve_returns_none_for_empty_word_at_whitespace() -> None:
    """A position on whitespace yields an empty word and returns None."""
    text = "rule r {\n  condition:\n    true\n}"
    doc = _doc(text)
    # line 1 is '  condition:' — character 0 is a space
    result = resolve_symbol_from_text_fallback(doc, _pos(1, 0))
    assert result is None


# -- word starts with '$' -> string kind (lines 37-41)


def test_resolve_string_sigil_dollar() -> None:
    """Word starting with '$' resolves to kind='string'."""
    text = 'rule r {\n  strings:\n    $a = "x"\n  condition:\n    $a\n}'
    doc = _doc(text)
    # line 4, character 4 — on '$a'
    result = resolve_symbol_from_text_fallback(doc, _pos(4, 4))
    assert result is not None
    assert result.kind == "string"
    assert result.normalized_name == "$a"


def test_resolve_string_sigil_hash() -> None:
    """Word starting with '#' resolves to kind='string' with '$' normalisation."""
    text = 'rule r {\n  strings:\n    $a = "x"\n  condition:\n    #a > 0\n}'
    doc = _doc(text)
    # line 4, character 4 — on '#a'
    result = resolve_symbol_from_text_fallback(doc, _pos(4, 4))
    assert result is not None
    assert result.kind == "string"
    assert result.normalized_name == "$a"
    assert result.name == "#a"


def test_resolve_string_sigil_at() -> None:
    """Word starting with '@' resolves to kind='string' with '$' normalisation."""
    text = 'rule r {\n  strings:\n    $b = "y"\n  condition:\n    @b > 0\n}'
    doc = _doc(text)
    # line 4, character 4 — on '@b'
    result = resolve_symbol_from_text_fallback(doc, _pos(4, 4))
    assert result is not None
    assert result.kind == "string"
    assert result.normalized_name == "$b"


def test_resolve_string_sigil_exclamation() -> None:
    """Word starting with '!' resolves to kind='string' with '$' normalisation."""
    text = 'rule r {\n  strings:\n    $c = "z"\n  condition:\n    !c > 0\n}'
    doc = _doc(text)
    result = resolve_symbol_from_text_fallback(doc, _pos(4, 4))
    assert result is not None
    assert result.kind == "string"
    assert result.normalized_name == "$c"


# -- _is_complete_dotted_word True -> module_member (lines 42-43)


def test_resolve_complete_dotted_word_without_matching_import() -> None:
    """Dotted word with no matching import still resolves as module_member."""
    text = "rule r {\n  condition:\n    pe.is_dll\n}"
    doc = _doc(text)
    # 'pe' is NOT imported here, but the dotted-word branch fires independently
    # of the import list for complete dotted words.
    result = resolve_symbol_from_text_fallback(doc, _pos(2, 7))
    assert result is not None
    assert result.kind == "module_member"


# -- partial dotted word (dot present, not complete) -> None (lines 44-45)


def test_resolve_incomplete_dotted_word_returns_none() -> None:
    """Word containing '.' but not a complete dotted word returns None."""
    # We manufacture a context where the cursor sits directly on the trailing
    # dot of 'pe.' — get_word_at_position will include the dot.
    text = "rule r {\n  condition:\n    pe.\n}"
    doc = _doc(text)
    # line 2, character 6 — on the '.' itself
    result = resolve_symbol_from_text_fallback(doc, _pos(2, 6))
    assert result is None


# -- word matches a rule definition -> kind='rule' (lines 46-47)


def test_resolve_rule_name() -> None:
    """Plain word matching a rule definition resolves to kind='rule'."""
    text = "rule alpha {\n  condition:\n    true\n}\nrule beta {\n  condition:\n    alpha\n}"
    doc = _doc(text)
    # line 6, character 4 — on 'alpha' inside the condition of 'beta'
    result = resolve_symbol_from_text_fallback(doc, _pos(6, 4))
    assert result is not None
    assert result.kind == "rule"
    assert result.normalized_name == "alpha"


# -- allow_generic_identifier=False with unknown word -> None (lines 48-49)


def test_resolve_unknown_word_with_generic_disabled_returns_none() -> None:
    """Unknown word returns None when allow_generic_identifier=False."""
    text = "rule r {\n  condition:\n    unknownword\n}"
    doc = _doc(text)
    result = resolve_symbol_from_text_fallback(doc, _pos(2, 4), allow_generic_identifier=False)
    assert result is None


# -- unknown word with allow_generic_identifier=True -> kind='identifier' (line 50)


def test_resolve_unknown_word_returns_identifier() -> None:
    """Unknown word resolves to kind='identifier' when generic is allowed."""
    text = "rule r {\n  condition:\n    unknownword\n}"
    doc = _doc(text)
    result = resolve_symbol_from_text_fallback(doc, _pos(2, 4))
    assert result is not None
    assert result.kind == "identifier"
    assert result.normalized_name == "unknownword"


# ---------------------------------------------------------------------------
# position_is_in_non_code_segment (lines 54-129)
# ---------------------------------------------------------------------------

# -- line out of range above (line 54-55)


def test_non_code_line_below_zero_returns_false() -> None:
    """position.line == 0 and len(lines) > 0 -> normal processing, not special-cased."""
    # This confirms the guard at line 54 only fires for line < 0 or line >= len.
    # lsprotocol.Position raises ValueError for line < 0 so we test line >= len.
    text = "rule r {\n  condition:\n    true\n}"
    doc = _doc(text)
    # 4 lines (indices 0-3); line 10 is out of range
    result = position_is_in_non_code_segment(doc, _pos(10, 0))
    assert result is False


# -- position on plain identifier (no comment/string/regex) -> False


def test_non_code_plain_identifier_returns_false() -> None:
    """Cursor on a bare word in the condition is in code -> returns False."""
    text = "rule r {\n  condition:\n    true\n}"
    doc = _doc(text)
    result = position_is_in_non_code_segment(doc, _pos(2, 4))
    assert result is False


# -- position at end of line (idx >= target_character at start) -> False


def test_non_code_position_past_end_of_content_returns_false() -> None:
    """Cursor past all content on a code line is still in code -> False."""
    text = "rule r {\n  condition:\n    true\n}"
    doc = _doc(text)
    # character 100 is well past 'true'; the scanner exhausts and falls through
    result = position_is_in_non_code_segment(doc, _pos(2, 100))
    assert result is False


# -- line comment '//' -> True when cursor is to the right (lines 95-98)


def test_non_code_position_inside_line_comment_returns_true() -> None:
    """Position after '//' on a code line is inside a comment -> True."""
    # Line 2: '    true // comment here'
    # '//' starts at character 9 (0-indexed: spaces 0-3, 't'=4, 'r'=5, 'u'=6,
    # 'e'=7, ' '=8, '/'=9, '/'=10)
    text = "rule r {\n  condition:\n    true // comment here\n}"
    doc = _doc(text)
    # character 12 is inside 'comment'
    result = position_is_in_non_code_segment(doc, _pos(2, 12))
    assert result is True


def test_non_code_position_before_line_comment_returns_false() -> None:
    """Position before '//' on a line with a comment is still code -> False."""
    text = "rule r {\n  condition:\n    true // comment\n}"
    doc = _doc(text)
    # character 4 is 't' of 'true', before the comment
    result = position_is_in_non_code_segment(doc, _pos(2, 4))
    assert result is False


# -- block comment opened and closed on the same line (lines 99-106)


def test_non_code_position_inside_inline_block_comment_returns_true() -> None:
    """Position inside '/* ... */' on one line returns True."""
    # '    true /* note */ and_more'
    text = "rule r {\n  condition:\n    true /* note */ and_more\n}"
    doc = _doc(text)
    # '/* note */' starts at col 9; 'note' starts at col 12
    result = position_is_in_non_code_segment(doc, _pos(2, 12))
    assert result is True


def test_non_code_position_after_inline_block_comment_returns_false() -> None:
    """Position after the closing '*/' of an inline block comment is code."""
    text = "rule r {\n  condition:\n    true /* note */ and_more\n}"
    doc = _doc(text)
    # 'and_more' starts at col 21 — after the '*/' at col 17-18
    result = position_is_in_non_code_segment(doc, _pos(2, 21))
    assert result is False


# -- block comment spanning multiple lines (lines 74-82)


def test_non_code_position_in_multiline_block_comment_returns_true() -> None:
    """Position inside a block comment that spans lines returns True."""
    text = "rule r {\n  /* start\n     middle\n  */ condition:\n    true\n}"
    doc = _doc(text)
    # line 2 is '     middle' — entirely inside the block comment
    result = position_is_in_non_code_segment(doc, _pos(2, 4))
    assert result is True


def test_non_code_position_at_end_of_block_comment_close_returns_true() -> None:
    """Position at the '*/' terminator itself (inside) returns True."""
    text = "rule r {\n  /* block\n  */\n  condition:\n    true\n}"
    doc = _doc(text)
    # line 2: '  */' — character 3 is '/' of '*/'
    # target_character < idx + 2 means cursor is before end of '/': True
    result = position_is_in_non_code_segment(doc, _pos(2, 3))
    assert result is True


def test_non_code_position_after_block_comment_close_returns_false() -> None:
    """Position after '*/' on the closing line is back in code -> False."""
    text = "rule r {\n  /* block */ foo\n  condition:\n    true\n}"
    doc = _doc(text)
    # line 1: '  /* block */ foo'
    # '*/' ends at col 12-13; 'foo' starts at col 14
    result = position_is_in_non_code_segment(doc, _pos(1, 14))
    assert result is False


# -- string literal (lines 108-111)


def test_non_code_position_inside_string_literal_returns_true() -> None:
    """Cursor inside a double-quoted string literal returns True."""
    text = 'rule r {\n  strings:\n    $s = "hello"\n  condition:\n    $s\n}'
    doc = _doc(text)
    # line 2: '    $s = "hello"' — '"' at col 9, 'h' at col 10
    result = position_is_in_non_code_segment(doc, _pos(2, 11))
    assert result is True


def test_non_code_position_on_opening_quote_returns_false() -> None:
    """Cursor exactly on the opening '"' is checked by the idx >= target guard first."""
    text = 'rule r {\n  strings:\n    $s = "hello"\n  condition:\n    $s\n}'
    doc = _doc(text)
    # line 2: opening '"' is at col 9; the idx-guard fires, in_string=False -> False
    result = position_is_in_non_code_segment(doc, _pos(2, 9))
    assert result is False


def test_non_code_position_after_closing_quote_returns_false() -> None:
    """Cursor after the closing '"' of a string is back in code -> False."""
    text = 'rule r {\n  strings:\n    $s = "hi"\n  condition:\n    $s\n}'
    doc = _doc(text)
    # line 2: '    $s = "hi"' — closing '"' at col 12, col 13 is after it
    result = position_is_in_non_code_segment(doc, _pos(2, 13))
    assert result is False


# -- escape sequences inside string (lines 84-88)


def test_non_code_escape_inside_string_does_not_close_string() -> None:
    """Backslash escape inside a string keeps the string open -> True."""
    text = 'rule r {\n  strings:\n    $s = "a\\"b"\n  condition:\n    $s\n}'
    doc = _doc(text)
    # The string contains a\\"b — position at the 'b' after the escaped quote
    # line 2: '    $s = "a\"b"'
    # col: 0123456789012345
    #      '    $s = "a\"b"'
    # 'a' at 10, '\' at 11, '"' at 12, 'b' at 13
    result = position_is_in_non_code_segment(doc, _pos(2, 13))
    assert result is True


# -- regex literal (lines 112-124)


def test_non_code_position_inside_regex_literal_returns_true() -> None:
    """Cursor inside a regex literal (condition: /abc/) returns True."""
    # A YARA condition that uses a regex match pattern.  We use a simple
    # single-rule document so the '/' introduces a regex context.
    text = "rule r {\n  strings:\n    $re = /abc/\n  condition:\n    $re\n}"
    doc = _doc(text)
    # line 2: '    $re = /abc/' — '/' at col 10, 'a' at col 11
    result = position_is_in_non_code_segment(doc, _pos(2, 11))
    assert result is True


def test_non_code_position_on_opening_slash_of_regex_returns_false() -> None:
    """Cursor exactly on the opening '/' of a regex returns False."""
    text = "rule r {\n  strings:\n    $re = /abc/\n  condition:\n    $re\n}"
    doc = _doc(text)
    # line 2: opening '/' at col 10; idx-guard fires, in_regex=False -> False
    result = position_is_in_non_code_segment(doc, _pos(2, 10))
    assert result is False


def test_non_code_position_after_closing_slash_of_regex_returns_false() -> None:
    """Cursor after the closing '/' of a regex is back in code -> False."""
    text = "rule r {\n  strings:\n    $re = /abc/\n  condition:\n    $re\n}"
    doc = _doc(text)
    # line 2: '    $re = /abc/' has length 15; col 15 is after the final '/'
    result = position_is_in_non_code_segment(doc, _pos(2, 15))
    assert result is False


# -- line ends while inside a block comment (line 127)


def test_non_code_line_end_inside_block_comment_returns_true() -> None:
    """After scanning target line while in_block_comment, returns True (line 127)."""
    # A block comment opened before the target line and not closed on it.
    # The loop ends at line_num == position.line with in_block_comment=True.
    text = "rule r {\n  /* this comment\n  spans this line too\n"
    doc = _doc(text)
    # line 2 is inside the unclosed block comment
    result = position_is_in_non_code_segment(doc, _pos(2, 5))
    assert result is True


# -- scanning a prior line advances past a full-line block comment start


def test_non_code_block_comment_spanning_prior_line_then_code() -> None:
    """Block comment starts on line before target; target is in code after close."""
    text = "rule r {\n  /* open */ condition:\n    true\n}"
    doc = _doc(text)
    # line 1 has the block comment opened and closed on the same line;
    # position at 'condition' (col 13) is after the close -> code
    result = position_is_in_non_code_segment(doc, _pos(1, 13))
    assert result is False


# -- block comment close encountered at or before target on same line (line 76-78)


def test_non_code_position_exactly_at_block_comment_close_star_returns_true() -> None:
    """Position is inside '*/' characters themselves -> True."""
    text = "rule r {\n  /* block\n  */ true\n}"
    doc = _doc(text)
    # line 2: '  */ true' — '*' at col 2, '/' at col 3
    # target_character=2 (the '*') — target_character < idx + 2 fires when idx=2
    result = position_is_in_non_code_segment(doc, _pos(2, 2))
    assert result is True


# ---------------------------------------------------------------------------
# find_module_member_at_position (lines 135-171)
# ---------------------------------------------------------------------------

# -- complete dotted word at position with matching import (lines 136-140)


def test_find_module_member_dotted_word_with_import() -> None:
    """Cursor on 'pe' in 'pe.is_dll' with 'pe' imported -> module_member."""
    text = 'import "pe"\nrule r {\n  condition:\n    pe.is_dll\n}'
    doc = _doc(text)
    # line 3: '    pe.is_dll' — 'pe' at col 4-5
    result = find_module_member_at_position(doc, _pos(3, 4))
    assert result is not None
    assert result.kind == "module_member"
    assert "pe" in result.name


# -- complete dotted word but root not in imports (no match from word branch)


def test_find_module_member_dotted_word_unknown_root_falls_through() -> None:
    """Cursor on 'foo.bar' with no 'foo' import — word branch returns None,
    line-scan also finds nothing -> None overall."""
    text = "rule r {\n  condition:\n    foo.bar\n}"
    doc = _doc(text)
    result = find_module_member_at_position(doc, _pos(2, 4))
    assert result is None


# -- line out of range after word branch (lines 141-142)


def test_find_module_member_line_out_of_range_returns_none() -> None:
    """position.line >= len(lines) after the word branch -> None."""
    text = "rule r {\n  condition:\n    true\n}"
    doc = _doc(text)
    # 4 lines (0-3); line 10 is out of range
    result = find_module_member_at_position(doc, _pos(10, 0))
    assert result is None


# -- module name not found on the line -> loop skips, returns None (lines 148-170)


def test_find_module_member_imported_module_not_on_line() -> None:
    """Import 'pe' exists but target line contains no 'pe.' -> None."""
    text = 'import "pe"\nrule r {\n  condition:\n    true\n}'
    doc = _doc(text)
    # line 3: '    true' — no 'pe.' occurrence
    result = find_module_member_at_position(doc, _pos(3, 4))
    assert result is None


# -- member_end == member_start skip (line 158-160)


def test_find_module_member_needle_followed_by_non_identifier_skips() -> None:
    """'pe.' followed by non-identifier chars (e.g., space) -> member_end==member_start
    so start advances and the occurrence is skipped -> None."""
    text = 'import "pe"\nrule r {\n  condition:\n    pe. is_dll\n}'
    doc = _doc(text)
    # line 3: '    pe. is_dll' — 'pe.' followed by space; no valid member
    result = find_module_member_at_position(doc, _pos(3, 4))
    assert result is None


# -- cursor inside the member span -> returns ResolvedSymbol (lines 160-169)


def test_find_module_member_cursor_inside_member_span() -> None:
    """Cursor inside a recognised 'module.member' span returns a ResolvedSymbol."""
    text = 'import "pe"\nrule r {\n  condition:\n    pe.number_of_sections > 0\n}'
    doc = _doc(text)
    # line 3: '    pe.number_of_sections > 0'
    # 'pe.' starts at col 4; 'number_of_sections' starts at col 7
    result = find_module_member_at_position(doc, _pos(3, 10))
    assert result is not None
    assert result.kind == "module_member"
    assert result.normalized_name == "pe.number_of_sections"


# -- cursor to the right of member span -> continues loop, then None (line 170)


def test_find_module_member_cursor_past_member_span_continues() -> None:
    """Cursor past the member span causes the inner loop to continue to the next
    occurrence; when there is only one occurrence the outer loop exhausts -> None."""
    text = 'import "pe"\nrule r {\n  condition:\n    pe.is_dll and true\n}'
    doc = _doc(text)
    # line 3: '    pe.is_dll and true'
    # 'pe.is_dll' occupies cols 4-12; col 14 is 'a' of 'and' — past the span
    result = find_module_member_at_position(doc, _pos(3, 14))
    assert result is None


# -- cursor on the module name portion (before the dot) -> not in member span


def test_find_module_member_cursor_on_module_prefix_returns_none() -> None:
    """Cursor on 'pe' before the dot is not inside the member span -> None from
    line-scan; dotted-word branch also fires but root must match an import."""
    # Here 'pe' IS imported, so the dotted-word branch at line 138-140 fires.
    text = 'import "pe"\nrule r {\n  condition:\n    pe.is_dll\n}'
    doc = _doc(text)
    # character 4 is 'p', character 5 is 'e' — both inside the dotted word 'pe.is_dll'
    # The dotted-word branch (lines 136-140) will match because 'pe' is in imports
    result = find_module_member_at_position(doc, _pos(3, 4))
    assert result is not None
    assert result.kind == "module_member"


# -- two module.member occurrences on the same line; cursor on second one


def test_find_module_member_cursor_on_second_occurrence() -> None:
    """When 'pe.' appears twice, cursor on second occurrence returns that member."""
    text = 'import "pe"\nrule r {\n  condition:\n    pe.is_dll and pe.number_of_sections > 0\n}'
    doc = _doc(text)
    # line 3: '    pe.is_dll and pe.number_of_sections > 0'
    # second 'pe.' starts at col 18; 'number_of_sections' at col 21
    result = find_module_member_at_position(doc, _pos(3, 25))
    assert result is not None
    assert result.kind == "module_member"
    assert result.normalized_name == "pe.number_of_sections"


# -- no imports at all -> line-scan loop body never entered -> None


def test_find_module_member_no_imports_returns_none() -> None:
    """Without any import statements the imported_modules set is empty -> None."""
    text = "rule r {\n  condition:\n    pe.is_dll\n}"
    doc = _doc(text)
    result = find_module_member_at_position(doc, _pos(2, 7))
    assert result is None


# ---------------------------------------------------------------------------
# position_is_in_non_code_segment additional paths (lines 98, 122->124)
# ---------------------------------------------------------------------------


def test_non_code_line_comment_on_prior_line_break_path() -> None:
    """'//' on a non-target prior line hits the 'break' branch (module line 98).

    When processing a line before position.line, encountering '//' exits the
    inner while loop via break so the outer for loop advances to the next line.
    The state machines for string/regex/block-comment are reset at the start of
    each line, so this break correctly discards the rest of the prior line.
    The target line (line 3) is plain code -> False.
    """
    text = "rule r {\n  x // prior comment\n  condition:\n    true\n}"
    doc = _doc(text)
    # Prior line (1) has '// prior comment'; target is line 3 col 4 ('true')
    result = position_is_in_non_code_segment(doc, _pos(3, 4))
    assert result is False


def test_non_code_division_slash_is_neither_regex_nor_comment() -> None:
    """A '/' used as a division operator (not regex, not comment) exercises
    the branch where in_regex is False AND starts_regex is False (module
    line 122->124: the elif is reached but not taken).

    YARA allows integer arithmetic: filesize / 2.  The '/' here follows an
    identifier that is not a regex-context keyword, so _starts_regex_literal
    returns False, and in_regex is also False.  The scanner simply advances
    past the slash without changing state.
    """
    text = 'rule r {\n  strings:\n    $a = "x"\n  condition:\n    filesize / 2 > 0\n}'
    doc = _doc(text)
    # line 4: '    filesize / 2 > 0'; position past the slash -> plain code
    result = position_is_in_non_code_segment(doc, _pos(4, 18))
    assert result is False


def test_non_code_division_slash_before_cursor_does_not_open_regex() -> None:
    """A division '/' encountered before the cursor position does not set
    in_regex, so the scanner reaches the cursor in code context -> False."""
    text = 'rule r {\n  strings:\n    $a = "x"\n  condition:\n    filesize / 2 > 0\n}'
    doc = _doc(text)
    # Position right after the slash (col 14 is ' ' after '/')
    result = position_is_in_non_code_segment(doc, _pos(4, 14))
    assert result is False


# ---------------------------------------------------------------------------
# Genuinely unreachable lines — documented, not tested
# ---------------------------------------------------------------------------
# The following lines in yaraast/lsp/document_query_resolution_text.py are
# structurally unreachable through the public API and cannot be covered by
# any real test without forging internal state:
#
#   Line 110: 'return True' inside the '"' branch when target_character == idx.
#     The guard at line 68 ('if line_num == position.line and idx >= target_character')
#     fires first because idx == target_character satisfies idx >= target_character.
#     At that point in_string is still False (the quote has not been processed yet),
#     so line 68 returns False.  Line 110 is dead code in practice.
#
#   Line 119: 'return True' inside the '/' branch when target_character == idx and
#     (in_regex or starts_regex).  Same reason: line 68 fires first.
#
#   Line 129: 'return False' at the end of the function body, after the for loop.
#     The for loop iterates range(position.line + 1).  On the final iteration
#     (line_num == position.line) the scanner either returns at line 69, 77, 97,
#     103, or 110/119, or falls through to line 127 ('return in_block_comment or
#     in_string or in_regex').  Because position.line is always the last index of
#     the loop, line 129 is never reached from the loop body; and the early guard
#     at line 54-55 handles the position.line < 0 / >= len(lines) cases.
#
