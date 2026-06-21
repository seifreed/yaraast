"""Regression tests targeting uncovered lines in yaraast/lsp/signature_help.py.

Copyright (c) 2026 Marc Rivero López
Licensed under GPLv3. See LICENSE file for details.
This test suite validates real code behavior without mocks or stubs.

Lines targeted (78.21% -> closer to 100%):
  14       _function_name_before_open_paren: whitespace-before-paren path (end -= 1)
  201-202  get_signature_help: TypeError for non-string text argument
  204-205  get_signature_help: TypeError for non-Position position argument
  215      get_signature_help: function name found in context but absent from signatures dict
  248-255  _find_call_context_at_position: in_block_comment handling (found/not-found branches)
  257-259  _find_call_context_at_position: escaped character inside string/regex (escaped=False path)
  261-263  _find_call_context_at_position: backslash while in_string or in_regex (escaped=True path)
  275-277  _find_call_context_at_position: // line comment on the cursor line -> return None
  281-284  _find_call_context_at_position: /* without */ on cursor line or non-cursor line
  297-298  _find_call_context_at_position: ')' with empty stack (no-op branch)
"""

from __future__ import annotations

from typing import Any, cast

from lsprotocol.types import Position
import pytest

from yaraast.lsp.signature_help import SignatureHelpProvider, _function_name_before_open_paren


def _pos(line: int, char: int) -> Position:
    return Position(line=line, character=char)


# ---------------------------------------------------------------------------
# Line 14: _function_name_before_open_paren — whitespace before the open paren
# ---------------------------------------------------------------------------


def test_function_name_before_open_paren_skips_leading_whitespace() -> None:
    """Whitespace between the function name and '(' must be skipped.

    The caller passes paren_index pointing at '(' in a string like
    'uint32 ('.  The while-loop at line 13 decrements end past the space
    before extracting the name.  Lines 13-14 execute only when the character
    immediately before the paren is whitespace.
    """
    # paren_index=7: line[7]='(' and line[6]=' ' (one space)
    result = _function_name_before_open_paren("uint32 (", 7)

    assert result == "uint32"


def test_function_name_before_open_paren_multiple_spaces_before_paren() -> None:
    """Multiple spaces between name and '(' are all skipped before extraction."""
    # paren_index=9: '(' at index 9, spaces at 6, 7, 8
    result = _function_name_before_open_paren("uint32   (", 9)

    assert result == "uint32"


def test_function_name_before_open_paren_no_whitespace_unchanged() -> None:
    """When there is no whitespace before '(' the name is extracted without touching line 14."""
    result = _function_name_before_open_paren("uint32(", 6)

    assert result == "uint32"


# ---------------------------------------------------------------------------
# Lines 201-202, 204-205: get_signature_help TypeError guards
# ---------------------------------------------------------------------------


@pytest.mark.parametrize("bad_text", [None, 42, b"uint32(", object()])
def test_get_signature_help_raises_type_error_for_non_string_text(bad_text: Any) -> None:
    """Non-string text argument raises TypeError with the expected message.

    Lines 200-202 guard the public API: they run before any parsing logic
    so the error is purely about the argument type, not document content.
    """
    provider = SignatureHelpProvider()

    with pytest.raises(TypeError, match="Signature help text must be a string"):
        provider.get_signature_help(cast(str, bad_text), _pos(0, 0))


@pytest.mark.parametrize("bad_pos", [None, 0, "0:0", (0, 0), object()])
def test_get_signature_help_raises_type_error_for_non_position_argument(bad_pos: Any) -> None:
    """Non-Position position argument raises TypeError with the expected message.

    Lines 203-205 guard the position parameter.  The check happens after the
    text guard, so a valid string must be supplied as the first argument.
    """
    provider = SignatureHelpProvider()

    with pytest.raises(TypeError, match="position must be an LSP Position"):
        provider.get_signature_help("uint32(", cast(Position, bad_pos))


# ---------------------------------------------------------------------------
# Line 215: function name resolved in context but absent from signatures dict
# ---------------------------------------------------------------------------


def test_get_signature_help_returns_none_for_unregistered_function_name() -> None:
    """A call expression whose function name is not in function_signatures yields None.

    _find_call_context_at_position returns a (name, param_index) tuple for any
    open parenthesis that has an identifier before it.  When that name is not a
    known YARA module function, line 215 (return None) fires.
    """
    provider = SignatureHelpProvider()

    # 'custom_function(' is a valid call-expression syntactically but the name
    # is not registered in _SIGNATURE_SPECS / function_signatures.
    result = provider.get_signature_help("custom_function(", _pos(0, 16))

    assert result is None


def test_get_signature_help_returns_none_for_dotted_unregistered_name() -> None:
    """Dotted names not in the spec (e.g., 'some.module.call(') also return None."""
    provider = SignatureHelpProvider()

    result = provider.get_signature_help("some.module.call(", _pos(0, 17))

    assert result is None


# ---------------------------------------------------------------------------
# Lines 248-255: in_block_comment handling in _find_call_context_at_position
# ---------------------------------------------------------------------------


def test_block_comment_spanning_lines_resolved_before_cursor_column() -> None:
    """Block comment opened on a prior line and closed before char_pos on cursor line.

    Line 248: we enter the in_block_comment branch (set on a prior non-cursor line).
    Lines 249-250: end >= 0 and end < char_pos — the closing '*/' is found before the
    cursor column, so neither 'return None' nor 'break' fires.
    Lines 253-255: in_block_comment=False, index advances past '*/', continue.
    The function call after the comment is then parsed normally.
    """
    provider = SignatureHelpProvider()

    # Line 0: '/*' opens block comment; no '*/' on same line -> in_block_comment=True
    # Line 1: '*/ uint32(' — '*/' at col 0 is before char_pos (len of entire line)
    text = "/*\n*/ uint32("
    result = provider.get_signature_help(text, _pos(1, len("*/ uint32(")))

    assert result is not None
    assert "uint32" in result.signatures[0].label
    assert result.active_parameter == 0


def test_block_comment_spanning_three_lines_resolved_on_third() -> None:
    """Block comment across three lines: in_block_comment persists until '*/' found.

    On lines 0 and 1 the comment is not closed (in_block_comment stays True via
    the break at line 252).  On line 2 (the cursor line) '*/' appears before
    char_pos, so lines 253-255 fire and execution continues past the comment.
    """
    provider = SignatureHelpProvider()

    text = "/*\nstill in comment\n*/ uint32("
    result = provider.get_signature_help(text, _pos(2, len("*/ uint32(")))

    assert result is not None
    assert "uint32" in result.signatures[0].label


def test_block_comment_not_closed_before_char_pos_on_cursor_line_returns_none() -> None:
    """Block comment opened on a prior line and not closed before char_pos yields None.

    in_block_comment=True entering the cursor line; end < 0 (no '*/' anywhere)
    so the condition at line 249 is true; line_number == position.line is true
    at line 250; line 251 fires: return None.
    """
    provider = SignatureHelpProvider()

    # Line 0 opens '/*' without closing; line 1 is all inside the comment.
    text = "/*\nstill in block comment uint32("
    result = provider.get_signature_help(text, _pos(1, len("still in block comment uint32(")))

    assert result is None


def test_block_comment_closes_after_char_pos_on_cursor_line_returns_none() -> None:
    """Block comment whose '*/' falls at or after char_pos on the cursor line yields None.

    in_block_comment=True; end >= char_pos so line 249's condition is true
    and line_number == position.line is true, triggering return None at line 251.
    """
    provider = SignatureHelpProvider()

    # Line 0 opens '/*'; line 1 has '*/' at col 6 but cursor is at col 3 (before the close).
    text = "/*\n   */ uint32("
    # char_pos = 3; '*/' is at index 3 so end (3) >= char_pos (3) -> return None
    result = provider.get_signature_help(text, _pos(1, 3))

    assert result is None


def test_block_comment_not_closed_on_non_cursor_line_sets_in_block_comment() -> None:
    """'/*' without '*/' on a non-cursor line sets in_block_comment=True via lines 283-284.

    The non-cursor line hits line 280 (end < 0 or end >= char_pos True), then
    line 281 (line_number != position.line), so it skips return None and falls
    through to line 283 (in_block_comment=True) and line 284 (break).
    The next line is the cursor line; if in_block_comment is True and '*/' is
    not found before char_pos there, the call returns None (line 251).
    """
    provider = SignatureHelpProvider()

    # '/* no close' on line 0 sets in_block_comment=True; line 1 has no '*/'.
    text = "uint32( /*\nuint32("
    result = provider.get_signature_help(text, _pos(1, len("uint32(")))

    assert result is None


# ---------------------------------------------------------------------------
# Lines 257-259: escaped character processed (escaped=False path)
# ---------------------------------------------------------------------------


def test_escaped_character_inside_string_does_not_end_string() -> None:
    """An escape sequence inside a quoted string does not terminate the string.

    Lines 256-259: when 'escaped' is True, the next character is consumed
    without special handling (escaped=False, index advances).  This prevents
    '\"' after '\\' from closing the string prematurely, which would mis-count
    commas as parameter separators.
    """
    provider = SignatureHelpProvider()

    # 'pe.imports("a\\b", ' — the '\\' inside the string is followed by 'b'.
    # Without the escape handler the '"' after '\\' would close the string and
    # the 'b' would be outside, but that cannot happen here with a real backslash.
    # The real scenario: the YARA source text contains a literal backslash in a string.
    # In Python source: "\"a\\b\"" represents the string: "a\b"
    text = 'pe.imports("a\\b", '
    result = provider.get_signature_help(text, _pos(0, len(text)))

    assert result is not None
    assert "imports" in result.signatures[0].label
    # The comma after the closing '"' is the first parameter separator, so
    # cursor is at parameter index 1.
    assert result.active_parameter == 1


# ---------------------------------------------------------------------------
# Lines 261-263: backslash sets escaped=True while in_string or in_regex
# ---------------------------------------------------------------------------


def test_backslash_inside_string_argument_sets_escaped_flag() -> None:
    """Backslash inside a quoted string triggers lines 260-263 (escaped=True).

    When char == '\\' and in_string is True, escaped is set to True and the
    parser skips the next character.  Without this, a '\"' following '\\' would
    incorrectly terminate the string and expose internal commas as separators.
    """
    provider = SignatureHelpProvider()

    # Two backslashes in the string: the first sets escaped=True, the second
    # is consumed as the escaped char (lines 257-259), leaving in_string True.
    # Then the real '"' closes the string.  The trailing ', ' moves to param 1.
    text = 'pe.imports("a\\\\b", '
    result = provider.get_signature_help(text, _pos(0, len(text)))

    assert result is not None
    assert result.active_parameter == 1


def test_backslash_inside_regex_argument_sets_escaped_flag() -> None:
    """Backslash inside a regex literal also triggers lines 260-263.

    YARA-L uses '/' as the regex delimiter.  A '\\/' inside the regex would
    be a false end-of-regex without the escape handler.
    """
    provider = SignatureHelpProvider()

    # 'pe.imports("x" matches /a\/b/' — the '\\/' inside the regex is an
    # escaped forward-slash and must not terminate the regex.
    # In Python string: /a\/b/ as chars: / a \ / b /
    text = 'pe.imports("x" matches /a\\/b/'
    result = provider.get_signature_help(text, _pos(0, len(text)))

    assert result is not None
    assert "imports" in result.signatures[0].label
    # Still at the first argument (no real comma separator encountered)
    assert result.active_parameter == 0


# ---------------------------------------------------------------------------
# Lines 275-277: // line comment on the cursor line -> return None
# ---------------------------------------------------------------------------


def test_line_comment_on_cursor_line_returns_none() -> None:
    """A '//' comment encountered on the cursor line causes return None (lines 275-277).

    Once the scanner hits '//' on the line where the cursor lives, all
    subsequent characters on that line are a comment.  The parser cannot
    determine whether the cursor is inside an argument, so it returns None.
    """
    provider = SignatureHelpProvider()

    # The cursor is at the end of the line, which is inside the comment.
    text = "uint32( // this is a comment"
    result = provider.get_signature_help(text, _pos(0, len(text)))

    assert result is None


def test_line_comment_on_cursor_line_returns_none_even_with_open_paren_before() -> None:
    """Even with a valid open-paren before it, '//' on the cursor line stops parsing."""
    provider = SignatureHelpProvider()

    text = "pe.imports( // comment"
    result = provider.get_signature_help(text, _pos(0, len(text)))

    assert result is None


def test_line_comment_on_non_cursor_line_does_not_affect_result() -> None:
    """'//' on a non-cursor line only breaks out of the inner while (line 277 break).

    The stack built before the '//' is preserved and the next line (the cursor
    line) continues scanning from an empty inner loop (char_pos=0 at line 1,
    char 0).  The function call opened on line 0 remains on the stack.
    """
    provider = SignatureHelpProvider()

    # Line 0: 'uint32( // comment' — '(' pushes ('uint32', 0); '//' breaks the loop.
    # Line 1: cursor at char 0 -> char_pos=0 -> inner while never runs.
    # Stack is [('uint32', 0)], so signature help is returned.
    text = "uint32( // comment\n"
    result = provider.get_signature_help(text, _pos(1, 0))

    assert result is not None
    assert "uint32" in result.signatures[0].label


# ---------------------------------------------------------------------------
# Lines 278-286: /* ... */ block comment opened on a line
# ---------------------------------------------------------------------------


def test_block_comment_opened_and_closed_on_same_line_before_func_call() -> None:
    """'/* ... */' fully on one line is skipped; the function call after is parsed.

    Lines 279-286: end >= 0 and end < char_pos, so neither return-None nor
    in_block_comment=True fires.  index jumps to end+2 and parsing continues.
    """
    provider = SignatureHelpProvider()

    text = "/* comment */ uint32("
    result = provider.get_signature_help(text, _pos(0, len(text)))

    assert result is not None
    assert "uint32" in result.signatures[0].label


def test_block_comment_without_close_on_cursor_line_returns_none() -> None:
    """'/*' with no '*/' found before char_pos on the cursor line yields None.

    Lines 278-284: end < 0 (line.find returns -1) so condition at 280 is true.
    line_number == position.line is true at line 281, so return None fires at 282.
    """
    provider = SignatureHelpProvider()

    # The '/*' opens a comment but there is no '*/' before the end of the line.
    text = "uint32( /* unclosed comment"
    result = provider.get_signature_help(text, _pos(0, len(text)))

    assert result is None


def test_block_comment_without_close_on_non_cursor_line_continues_to_next() -> None:
    """'/*' with no '*/' on a non-cursor line sets in_block_comment=True (lines 283-284).

    line_number != position.line at line 281, so instead of returning None the
    parser sets in_block_comment=True (line 283) and breaks (line 284), letting
    the next line be processed with in_block_comment=True.
    """
    provider = SignatureHelpProvider()

    # Line 0: 'uint32( /*' — '(' pushes uint32; '/*' opens comment; no '*/' -> in_block_comment=True.
    # Line 1 (cursor): still inside the comment (no '*/' before char_pos) -> return None.
    text = "uint32( /*\ncursor is here"
    result = provider.get_signature_help(text, _pos(1, len("cursor is here")))

    assert result is None


# ---------------------------------------------------------------------------
# Lines 297-298: ')' with an empty stack (no-op branch)
# ---------------------------------------------------------------------------


def test_closing_paren_with_empty_stack_is_ignored() -> None:
    """An unmatched ')' when the stack is empty does not crash; lines 297-298 no-op.

    The elif at line 296 ('char == ")"') checks 'if stack' at line 297.  When
    the stack is empty the pop is skipped.  Parsing continues and subsequent
    function calls are still detected.
    """
    provider = SignatureHelpProvider()

    # The leading ')' is unmatched (stack is empty at that point).
    # Afterwards 'uint32(' pushes a valid entry.
    text = ") uint32("
    result = provider.get_signature_help(text, _pos(0, len(text)))

    assert result is not None
    assert "uint32" in result.signatures[0].label
    assert result.active_parameter == 0


def test_closing_paren_after_block_reset_is_ignored() -> None:
    """After '{' resets the stack, ')' is again unmatched and silently skipped."""
    provider = SignatureHelpProvider()

    # 'uint32(' pushes entry; '{' resets stack; ')' finds empty stack; pe.imports( opens new entry.
    text = "uint32( { ) pe.imports("
    result = provider.get_signature_help(text, _pos(0, len(text)))

    assert result is not None
    assert "imports" in result.signatures[0].label
    assert result.active_parameter == 0


# ---------------------------------------------------------------------------
# Combination scenarios that exercise multiple uncovered paths together
# ---------------------------------------------------------------------------


def test_whitespace_before_paren_gives_correct_signature() -> None:
    """Space between function name and '(' still resolves the correct signature.

    This exercises line 14 (_function_name_before_open_paren) via the full
    public API: get_signature_help -> _find_call_context_at_position ->
    _function_name_before_open_paren.
    """
    provider = SignatureHelpProvider()

    # YARA allows whitespace before the open paren in module calls.
    text = "uint32 (0)"
    result = provider.get_signature_help(text, _pos(0, 9))

    assert result is not None
    assert "uint32" in result.signatures[0].label
    assert result.active_parameter == 0


def test_block_comment_before_multi_param_call_counts_parameters_correctly() -> None:
    """Block comment skipped on prior line; param index is still correct afterwards."""
    provider = SignatureHelpProvider()

    # Line 0: '/*' opens block comment; no close.
    # Line 1: '*/' closes comment; 'pe.imports("k32.dll", ' opens call at param 1.
    text = '/*\n*/ pe.imports("k32.dll", '
    result = provider.get_signature_help(text, _pos(1, len('*/ pe.imports("k32.dll", ')))

    assert result is not None
    assert "imports" in result.signatures[0].label
    assert result.active_parameter == 1


def test_line_comment_hides_comma_so_earlier_param_index_is_used() -> None:
    """A comma inside a '//' comment on a prior line does not advance param index.

    The '//' on a non-cursor line triggers the break at line 277, discarding
    the comma that follows it within that line.  The cursor on the next line
    therefore sees only the parameters accumulated before the comment.
    """
    provider = SignatureHelpProvider()

    # Line 0: 'pe.imports( // "k32.dll",' — the comma is inside the comment; break fires.
    # Line 1: cursor at char 0 — stack has [('pe.imports', 0)] with no comma counted.
    text = 'pe.imports( // "k32.dll",\n'
    result = provider.get_signature_help(text, _pos(1, 0))

    assert result is not None
    assert "imports" in result.signatures[0].label
    assert result.active_parameter == 0


# ---------------------------------------------------------------------------
# Line 271: regex literal closed by '/' while in_regex=True
# ---------------------------------------------------------------------------


def test_regex_literal_closed_by_slash_advances_past_regex() -> None:
    """A closing '/' while in_regex=True clears the flag (line 271) and continues parsing.

    When the scanner sets in_regex=True at the opening '/', subsequent characters
    are consumed without special treatment until another '/' is found.  Line 270
    detects that '/' and line 271 sets in_regex=False so that subsequent commas
    and parentheses are interpreted normally.
    """
    provider = SignatureHelpProvider()

    # 'pe.imports("x" matches /abc/, ' — the regex /abc/ is opened then closed.
    # After the closing '/' the comma is processed as a parameter separator.
    text = 'pe.imports("x" matches /abc/, '
    result = provider.get_signature_help(text, _pos(0, len(text)))

    assert result is not None
    assert "imports" in result.signatures[0].label
    # The comma after /abc/ is the first real separator so cursor is at param 1.
    assert result.active_parameter == 1
