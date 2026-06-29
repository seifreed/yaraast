# Copyright (c) 2026 Marc Rivero López
# Licensed under GPLv3. See LICENSE file for details.
# This test suite validates real code behavior without mocks or stubs.
"""Regression tests that drive CommentPreservingLexer along every previously
uncovered code path identified by coverage analysis.

Missing lines targeted (full-suite baseline):
  20           - tokenize(text=...) with an explicit text argument
  54-66        - _strip_comments: // line-comment detection and token emission
  69-85        - _strip_comments: /* */ block-comment detection and token emission
  88-90        - _strip_comments: lone / dispatch to _read_regex_text
  107->132     - _read_quoted_string_text: loop body entered (branch exercised)
  112-113      - _read_quoted_string_text: literal newline inside string body
                 NOTE: only reachable via _strip_comments(); the full tokenize()
                 path crashes the base lexer on unterminated strings, making
                 this a partial dead-code path from the public API.
  118-126      - _read_quoted_string_text: backslash escape sequence
  136-168      - _read_regex_text: entire method including flags and escapes
  172-179      - _read_line_comment_text: entire method
  183-199      - _read_block_comment_text: entire method
  219          - get_comments()
  223          - set_preserve_comments()
"""

from __future__ import annotations

from yaraast.lexer.comment_preserving_lexer import CommentPreservingLexer
from yaraast.lexer.tokens import Token, TokenType

# ---------------------------------------------------------------------------
# Helper
# ---------------------------------------------------------------------------


def _comment_values(tokens: list[Token]) -> list[str]:
    result = []
    for t in tokens:
        if t.type == TokenType.COMMENT:
            assert isinstance(t.value, str)
            result.append(t.value)
    return result


# ---------------------------------------------------------------------------
# Line 20 - tokenize(text=...) with explicit argument
# ---------------------------------------------------------------------------


def test_tokenize_accepts_explicit_text_argument() -> None:
    """tokenize() must accept an optional text parameter and replace self.text.

    Line 20 (self.text = text) executes only when the caller supplies the
    text keyword argument.
    """
    # Arrange: lexer initialised with empty string, real YARA source provided later.
    lexer = CommentPreservingLexer("")
    yara_source = "rule r { condition: true }"

    # Act
    tokens = lexer.tokenize(text=yara_source)

    # Assert: the rule keyword must appear; an empty-string run yields only EOF.
    token_types = [t.type for t in tokens]
    assert TokenType.RULE in token_types
    assert TokenType.EOF in token_types


def test_tokenize_text_argument_replaces_stored_text() -> None:
    """A second call to tokenize() with a different text argument must use the
    new source rather than the previously stored one."""
    lexer = CommentPreservingLexer("// old\nrule old { condition: false }")
    lexer.tokenize()

    tokens = lexer.tokenize(text="rule new { condition: true }")

    comment_tokens = [t for t in tokens if t.type == TokenType.COMMENT]
    assert not comment_tokens
    rule_tokens = [t for t in tokens if t.type == TokenType.RULE]
    assert len(rule_tokens) == 1


# ---------------------------------------------------------------------------
# Lines 54-66 - _strip_comments: // line comment emission
# ---------------------------------------------------------------------------


def test_line_comment_is_extracted_and_emitted_as_token() -> None:
    """A // line comment must be stripped from the token stream and stored as
    a COMMENT token with the correct text, line, and column.

    Lines 54-66 are the branch detecting '//' and appending a COMMENT token.
    """
    source = "// this is a line comment\nrule r { condition: true }"
    lexer = CommentPreservingLexer(source)

    tokens = lexer.tokenize()

    comment_tokens = [t for t in tokens if t.type == TokenType.COMMENT]
    assert len(comment_tokens) == 1
    assert comment_tokens[0].value == "// this is a line comment"
    assert comment_tokens[0].line == 1
    assert comment_tokens[0].column == 1


def test_multiple_line_comments_are_all_preserved() -> None:
    """Each // comment line must produce exactly one COMMENT token."""
    source = "// first\n// second\nrule r { condition: true }"
    lexer = CommentPreservingLexer(source)

    tokens = lexer.tokenize()

    comments = _comment_values(tokens)
    assert comments == ["// first", "// second"]


def test_line_comment_trailing_after_keyword() -> None:
    """A trailing // comment after YARA code must be captured while leaving
    the preceding keyword token intact."""
    source = "rule r { // inline comment\ncondition: true }"
    lexer = CommentPreservingLexer(source)

    tokens = lexer.tokenize()

    comments = _comment_values(tokens)
    assert len(comments) == 1
    assert comments[0].startswith("// inline comment")
    assert any(t.type == TokenType.RULE for t in tokens)


# ---------------------------------------------------------------------------
# Lines 69-85 - _strip_comments: /* */ block comment emission
# ---------------------------------------------------------------------------


def test_block_comment_is_extracted_and_emitted_as_token() -> None:
    """A /* */ block comment must be stripped and emitted as a COMMENT token
    that includes the opening and closing delimiters.

    Lines 69-85 record the start position, call _read_block_comment_text,
    and append the COMMENT token.
    """
    source = "rule r { /* block comment */ condition: true }"
    lexer = CommentPreservingLexer(source)

    tokens = lexer.tokenize()

    comments = [t for t in tokens if t.type == TokenType.COMMENT]
    assert len(comments) == 1
    assert comments[0].value == "/* block comment */"


def test_multiline_block_comment_preserves_start_position() -> None:
    """The COMMENT token for a /* */ comment spanning multiple lines must
    record the opening-delimiter position, not the closing one."""
    source = "/* line1\nline2\nline3 */rule r { condition: true }"
    lexer = CommentPreservingLexer(source)

    tokens = lexer.tokenize()

    comments = [t for t in tokens if t.type == TokenType.COMMENT]
    assert len(comments) == 1
    assert comments[0].line == 1
    assert comments[0].column == 1
    comment_val = comments[0].value
    assert isinstance(comment_val, str)
    assert "line1" in comment_val
    assert "line3" in comment_val


def test_block_comment_newlines_keep_subsequent_token_line_numbers_accurate() -> None:
    """Newlines inside a block comment must be preserved as newlines in the
    replacement text (lines 83-84) so subsequent token lines stay accurate."""
    source = "/* a\nb */\nrule r { condition: true }"
    lexer = CommentPreservingLexer(source)

    tokens = lexer.tokenize()

    rule_tokens = [t for t in tokens if t.type == TokenType.RULE]
    assert len(rule_tokens) == 1
    assert rule_tokens[0].line == 3


# ---------------------------------------------------------------------------
# Lines 88-90 - _strip_comments: lone / dispatches to _read_regex_text
# ---------------------------------------------------------------------------


def test_regex_in_condition_does_not_trigger_comment_parsing() -> None:
    """A '/' that is not followed by '/' or '*' must be treated as the start
    of a regex literal.

    Lines 88-90 delegate to _read_regex_text and extend the output buffer.
    """
    source = "rule r { strings: $re = /foo/ condition: $re }"
    lexer = CommentPreservingLexer(source)

    tokens = lexer.tokenize()

    assert not any(t.type == TokenType.COMMENT for t in tokens)
    regex_tokens = [t for t in tokens if t.type == TokenType.REGEX]
    assert len(regex_tokens) == 1
    regex_val = regex_tokens[0].value
    assert isinstance(regex_val, str)
    assert "foo" in regex_val


# ---------------------------------------------------------------------------
# Lines 107->132 branch + 118-126 - _read_quoted_string_text
# ---------------------------------------------------------------------------


def test_quoted_string_loop_body_is_entered() -> None:
    """The while loop in _read_quoted_string_text (line 107) must execute its
    body when a non-empty string is present, covering the 107->132 branch."""
    source = 'rule r { strings: $s = "hello" condition: $s }'
    lexer = CommentPreservingLexer(source)

    tokens = lexer.tokenize()

    string_tokens = [t for t in tokens if t.type == TokenType.STRING]
    assert len(string_tokens) == 1
    assert string_tokens[0].value == "hello"


def test_backslash_escape_in_string_covers_lines_118_to_126() -> None:
    """A backslash escape sequence inside a quoted string must cause
    _read_quoted_string_text to enter the escape block (lines 118-126).

    The '\\n' escape is valid YARA and produces a newline in the string value.
    """
    source = r'rule r { strings: $s = "foo\nbar" condition: $s }'
    lexer = CommentPreservingLexer(source)

    tokens = lexer.tokenize()

    string_tokens = [t for t in tokens if t.type == TokenType.STRING]
    assert len(string_tokens) == 1
    str_val = string_tokens[0].value
    assert isinstance(str_val, str)
    assert "\n" in str_val


def test_escaped_quote_in_string_is_part_of_value() -> None:
    """The '\\\"' escape inside a string must be consumed without closing the
    string early, exercising the escape branch at lines 118-126."""
    source = r'rule r { strings: $s = "say \"hi\"" condition: $s }'
    lexer = CommentPreservingLexer(source)

    tokens = lexer.tokenize()

    string_tokens = [t for t in tokens if t.type == TokenType.STRING]
    assert len(string_tokens) == 1
    str_val = string_tokens[0].value
    assert isinstance(str_val, str)
    assert '"hi"' in str_val


def test_comment_markers_inside_string_are_not_parsed_as_comments() -> None:
    """Comment delimiters // and /* inside a quoted string must not generate
    any COMMENT token — _read_quoted_string_text keeps them as literals."""
    source = 'rule r { strings: $s = "url: http://host/*path*/" condition: $s }'
    lexer = CommentPreservingLexer(source)

    tokens = lexer.tokenize()

    assert not any(t.type == TokenType.COMMENT for t in tokens)
    string_tokens = [t for t in tokens if t.type == TokenType.STRING]
    assert any(isinstance(t.value, str) and "http://host/*path*/" in t.value for t in string_tokens)


def test_strip_comments_handles_literal_newline_inside_string_body() -> None:
    """_strip_comments() must handle a literal newline inside a quoted string
    (lines 111-113) without raising an exception.

    NOTE: This path can only be exercised via _strip_comments() directly.
    The full tokenize() pipeline rejects raw newlines inside strings at the
    base-lexer stage; that is a separate, documented limitation.  The
    comment-stripping pass itself must be robust against them.
    """
    literal_newline = chr(10)
    source = f'$s = "foo{literal_newline}bar"'
    lexer = CommentPreservingLexer(source)

    comment_tokens, text_parts = lexer._strip_comments()

    joined = "".join(text_parts)
    assert literal_newline in joined
    assert len(comment_tokens) == 0


# ---------------------------------------------------------------------------
# Lines 136-168 - _read_regex_text
# ---------------------------------------------------------------------------


def test_regex_token_is_fully_consumed_with_case_insensitive_flag() -> None:
    """_read_regex_text must consume the regex body, its closing '/', and the
    'i' modifier that immediately follows (lines 162-165)."""
    source = "rule r { strings: $re = /pattern/i condition: $re }"
    lexer = CommentPreservingLexer(source)

    tokens = lexer.tokenize()

    regex_tokens = [t for t in tokens if t.type == TokenType.REGEX]
    assert len(regex_tokens) == 1
    regex_val = regex_tokens[0].value
    assert isinstance(regex_val, str)
    assert "pattern" in regex_val


def test_regex_with_s_flag_is_fully_consumed() -> None:
    """The 's' modifier after a closing '/' must be absorbed (line 162)."""
    source = "rule r { strings: $re = /pat/s condition: $re }"
    lexer = CommentPreservingLexer(source)

    tokens = lexer.tokenize()

    regex_tokens = [t for t in tokens if t.type == TokenType.REGEX]
    assert len(regex_tokens) == 1


def test_regex_with_is_flags_is_fully_consumed() -> None:
    """Both 'i' and 's' modifiers must be absorbed after the closing '/'."""
    source = "rule r { strings: $re = /pat/is condition: $re }"
    lexer = CommentPreservingLexer(source)

    tokens = lexer.tokenize()

    regex_tokens = [t for t in tokens if t.type == TokenType.REGEX]
    assert len(regex_tokens) == 1


def test_regex_backslash_escape_inside_pattern() -> None:
    """A backslash inside a regex body (lines 150-160) must consume the next
    character without breaking out of the regex early."""
    source = r"rule r { strings: $re = /foo\/bar/ condition: $re }"
    lexer = CommentPreservingLexer(source)

    tokens = lexer.tokenize()

    regex_tokens = [t for t in tokens if t.type == TokenType.REGEX]
    assert len(regex_tokens) == 1
    regex_val = regex_tokens[0].value
    assert isinstance(regex_val, str)
    assert "foo" in regex_val


def test_strip_comments_handles_regex_newline_termination() -> None:
    """A newline encountered inside a regex body (lines 144-147) must
    terminate the regex scan in _strip_comments() without raising.

    NOTE: Full tokenize() on such source fails at the base-lexer stage
    ("Unterminated regex"). This test verifies the comment-strip pass itself
    is safe, which is its isolated responsibility.
    """
    literal_newline = chr(10)
    source = f"$re = /foo{literal_newline}bar/"
    lexer = CommentPreservingLexer(source)

    comment_tokens, text_parts = lexer._strip_comments()

    joined = "".join(text_parts)
    assert literal_newline in joined
    assert len(comment_tokens) == 0


def test_strip_comments_handles_regex_backslash_newline() -> None:
    """A backslash followed by a literal newline inside a regex body must
    terminate the scan (lines 154-157 of _read_regex_text)."""
    bslash = chr(92)
    literal_newline = chr(10)
    source = f"$re = /foo{bslash}{literal_newline}bar/"
    lexer = CommentPreservingLexer(source)

    comment_tokens, text_parts = lexer._strip_comments()

    joined = "".join(text_parts)
    assert literal_newline in joined
    assert len(comment_tokens) == 0


# ---------------------------------------------------------------------------
# Lines 172-179 - _read_line_comment_text
# ---------------------------------------------------------------------------


def test_line_comment_text_stops_at_newline() -> None:
    """_read_line_comment_text must consume only up to but not including the
    terminating newline (lines 175-178)."""
    source = "// comment text\nrule r { condition: true }"
    lexer = CommentPreservingLexer(source)

    tokens = lexer.tokenize()

    comments = _comment_values(tokens)
    assert len(comments) == 1
    assert comments[0] == "// comment text"
    assert "\n" not in comments[0]


def test_line_comment_at_eof_without_trailing_newline() -> None:
    """A // comment at the very end of the source without a trailing newline
    must be fully consumed without an index error."""
    source = "rule r { condition: true } // trailing comment"
    lexer = CommentPreservingLexer(source)

    tokens = lexer.tokenize()

    comments = _comment_values(tokens)
    assert len(comments) == 1
    assert "trailing comment" in comments[0]


def test_empty_line_comment_value() -> None:
    """A '//' with nothing after it before the newline must produce a COMMENT
    token whose value is exactly '//'."""
    source = "//\nrule r { condition: true }"
    lexer = CommentPreservingLexer(source)

    tokens = lexer.tokenize()

    comments = _comment_values(tokens)
    assert len(comments) == 1
    assert comments[0] == "//"


# ---------------------------------------------------------------------------
# Lines 183-199 - _read_block_comment_text
# ---------------------------------------------------------------------------


def test_block_comment_text_includes_both_delimiters() -> None:
    """_read_block_comment_text must return the full comment including '/*'
    and '*/' delimiters (lines 183-184 initialise with '/*'; 188-191 append
    '*/')."""
    source = "rule r { /* annotated */ condition: true }"
    lexer = CommentPreservingLexer(source)

    tokens = lexer.tokenize()

    comments = _comment_values(tokens)
    assert len(comments) == 1
    assert comments[0].startswith("/*")
    assert comments[0].endswith("*/")
    assert "annotated" in comments[0]


def test_block_comment_spanning_lines_updates_line_counter() -> None:
    """Newlines inside a block comment must increment the line counter via
    lines 192-195 of _read_block_comment_text."""
    source = "/* first\nsecond\nthird */rule r { condition: true }"
    lexer = CommentPreservingLexer(source)

    tokens = lexer.tokenize()

    rule_token = next(t for t in tokens if t.type == TokenType.RULE)
    assert rule_token.line == 3


def test_block_comment_interior_asterisks_do_not_terminate_early() -> None:
    """Asterisks inside a block comment not followed by '/' must not close
    the comment (line 187 requires '*/' as a two-char sentinel)."""
    source = "/* a * b ** c */rule r { condition: true }"
    lexer = CommentPreservingLexer(source)

    tokens = lexer.tokenize()

    comments = _comment_values(tokens)
    assert len(comments) == 1
    assert "a * b ** c" in comments[0]


def test_block_comment_immediately_adjacent_to_rule_keyword() -> None:
    """A block comment directly followed by a keyword without whitespace must
    not prevent the keyword from being tokenised."""
    source = "/* c */rule r { condition: true }"
    lexer = CommentPreservingLexer(source)

    tokens = lexer.tokenize()

    assert any(t.type == TokenType.RULE for t in tokens)
    comments = _comment_values(tokens)
    assert len(comments) == 1


# ---------------------------------------------------------------------------
# Line 219 - get_comments()
# ---------------------------------------------------------------------------


def test_get_comments_returns_independent_copy() -> None:
    """get_comments() must return a fresh list copy so that mutations by the
    caller do not affect the lexer's internal state (line 219: return list(...)).
    """
    source = "// c1\nrule r { condition: true }"
    lexer = CommentPreservingLexer(source)
    lexer.tokenize()

    copy1 = lexer.get_comments()
    copy1.clear()

    copy2 = lexer.get_comments()
    assert len(copy2) == 1
    assert copy2[0].value == "// c1"


def test_get_comments_empty_before_tokenize() -> None:
    """get_comments() must return an empty list when tokenize() has not yet
    been called."""
    lexer = CommentPreservingLexer("rule r { condition: true }")

    assert lexer.get_comments() == []


def test_get_comments_matches_comment_tokens_in_stream() -> None:
    """get_comments() must return exactly the same tokens that appear as
    COMMENT type in the tokenize() output."""
    source = "/* a */\n// b\nrule r { condition: true }"
    lexer = CommentPreservingLexer(source)
    tokens = lexer.tokenize()

    stream_comments = [t for t in tokens if t.type == TokenType.COMMENT]
    stored_comments = lexer.get_comments()

    assert stream_comments == stored_comments


# ---------------------------------------------------------------------------
# Line 223 - set_preserve_comments()
# ---------------------------------------------------------------------------


def test_set_preserve_comments_false_suppresses_comment_tokens() -> None:
    """When preserve_comments is set to False, tokenize() must not emit any
    COMMENT tokens (line 223: self.preserve_comments = preserve)."""
    source = "// dropped\nrule r { condition: true }"
    lexer = CommentPreservingLexer(source)

    lexer.set_preserve_comments(False)
    tokens = lexer.tokenize()

    assert not any(t.type == TokenType.COMMENT for t in tokens)
    assert lexer.get_comments() == []


def test_set_preserve_comments_true_restores_emission() -> None:
    """Toggling preserve_comments back to True must re-enable COMMENT token
    emission on the next tokenize() call."""
    source = "/* kept */rule r { condition: true }"
    lexer = CommentPreservingLexer(source)

    lexer.set_preserve_comments(False)
    tokens_without = lexer.tokenize()
    assert not any(t.type == TokenType.COMMENT for t in tokens_without)

    lexer.set_preserve_comments(True)
    tokens_with = lexer.tokenize()
    comments = [t for t in tokens_with if t.type == TokenType.COMMENT]
    assert len(comments) == 1
    assert comments[0].value == "/* kept */"


def test_set_preserve_comments_false_also_suppresses_block_comments() -> None:
    """Both line and block comments must be suppressed when preserve_comments
    is False."""
    source = "// line\n/* block */\nrule r { condition: true }"
    lexer = CommentPreservingLexer(source)

    lexer.set_preserve_comments(False)
    tokens = lexer.tokenize()

    assert not any(t.type == TokenType.COMMENT for t in tokens)


# ---------------------------------------------------------------------------
# Integration: combined comment types in a realistic YARA rule
# ---------------------------------------------------------------------------


def test_mixed_comments_in_realistic_yara_rule() -> None:
    """A realistic YARA rule combining line comments, block comments, string
    literals with escape sequences, and a regex pattern must produce the
    correct token stream."""
    source = (
        "// Rule metadata\n"
        "rule detect_pattern {\n"
        "  /* author: security team */\n"
        "  strings:\n"
        '    $url = "https:\\x2f\\x2fexample.com"  // URL pattern\n'
        "    $re = /malware[0-9]+/i\n"
        "  condition:\n"
        "    $url or $re\n"
        "}"
    )
    lexer = CommentPreservingLexer(source)

    tokens = lexer.tokenize()

    comments = [t for t in tokens if t.type == TokenType.COMMENT]
    assert len(comments) == 3
    comment_values = _comment_values(tokens)
    assert any("Rule metadata" in v for v in comment_values)
    assert any("author" in v for v in comment_values)
    assert any("URL pattern" in v for v in comment_values)

    string_tokens = [t for t in tokens if t.type == TokenType.STRING]
    assert len(string_tokens) == 1
    regex_tokens = [t for t in tokens if t.type == TokenType.REGEX]
    assert len(regex_tokens) == 1


def test_comment_tokens_are_merged_in_source_order() -> None:
    """All COMMENT tokens must appear in ascending line/column order in the
    merged token stream (_merge_comment_tokens sorts by (line, column))."""
    source = "// alpha\nrule r {\n  /* beta */\n  condition: true  // gamma\n}"
    lexer = CommentPreservingLexer(source)

    tokens = lexer.tokenize()

    comment_tokens = [t for t in tokens if t.type == TokenType.COMMENT]
    assert len(comment_tokens) == 3
    positions = [(t.line, t.column) for t in comment_tokens]
    assert positions == sorted(positions)


# ---------------------------------------------------------------------------
# Remaining branch misses
# ---------------------------------------------------------------------------


def test_empty_string_literal_does_not_enter_loop_body() -> None:
    """An empty string literal '\"\"' must be tokenised correctly.

    This exercises the 107->132 branch: the while-loop in
    _read_quoted_string_text is entered but the first char is the closing
    quote so the opening-quote flag prevents an immediate break — the loop
    runs at least once but exits on the closing quote.
    """
    source = 'rule r { strings: $s = "" condition: $s }'
    lexer = CommentPreservingLexer(source)

    tokens = lexer.tokenize()

    string_tokens = [t for t in tokens if t.type == TokenType.STRING]
    assert len(string_tokens) == 1
    assert string_tokens[0].value == ""


def test_empty_block_comment_covers_while_loop_skip_branch() -> None:
    """An empty block comment /**/ must be parsed correctly.

    This exercises the 186->199 branch: the while-loop in
    _read_block_comment_text sees '*/' immediately and exits on the first
    iteration rather than running its body.
    """
    source = "/**/ rule r { condition: true }"
    lexer = CommentPreservingLexer(source)

    tokens = lexer.tokenize()

    comments = [t for t in tokens if t.type == TokenType.COMMENT]
    assert len(comments) == 1
    assert comments[0].value == "/**/"


def test_strip_comments_backslash_plus_literal_newline_in_string() -> None:
    """A backslash immediately followed by a literal newline inside a quoted
    string must cause _read_quoted_string_text to increment the line counter
    (lines 122-123: line += 1; col = 1) and then continue scanning.

    NOTE: Full tokenize() on this input fails at the base-lexer stage.  The
    comment-stripping pass (exercised here via _strip_comments()) is
    independently responsible for tracking positions correctly.
    """
    bslash = chr(92)
    newline = chr(10)
    source = f'"foo{bslash}{newline}bar"'
    lexer = CommentPreservingLexer(source)

    comment_tokens, text_parts = lexer._strip_comments()

    joined = "".join(text_parts)
    assert newline in joined
    assert len(comment_tokens) == 0


def test_strip_comments_unterminated_string_at_eof_skips_loop_body() -> None:
    """An opening quote at the very end of the source causes the while loop in
    _read_quoted_string_text to start with i >= len(self.text), covering the
    107->132 branch where the loop body is never entered.

    NOTE: Only reachable via _strip_comments(); a bare '\"' is not valid YARA
    so tokenize() would fail at the base-lexer stage.
    """
    source = '"'
    lexer = CommentPreservingLexer(source)

    comment_tokens, text_parts = lexer._strip_comments()

    assert len(comment_tokens) == 0
    assert "".join(text_parts) == '"'


def test_strip_comments_unterminated_block_comment_at_eof_skips_loop_body() -> None:
    """A '/*' at the very end of the source (no closing '*/') causes the while
    loop in _read_block_comment_text to exhaust the input, covering the
    186->199 branch where the loop terminates without finding a closing delimiter.

    NOTE: Only reachable via _strip_comments(); tokenize() on bare '/*' would
    fail at the base-lexer stage.
    """
    source = "/*"
    lexer = CommentPreservingLexer(source)

    comment_tokens, text_parts = lexer._strip_comments()

    assert len(comment_tokens) == 1
    assert comment_tokens[0].value == "/*"
    assert "".join(text_parts) == "  "


def test_preserve_false_then_rerun_same_lexer_instance() -> None:
    """A single lexer instance must produce consistent results across multiple
    tokenize() calls when preserve_comments changes between calls."""
    source = "/* comment */rule r { condition: true }"
    lexer = CommentPreservingLexer(source)

    tokens_with = lexer.tokenize()
    comments_with = [t for t in tokens_with if t.type == TokenType.COMMENT]

    lexer.set_preserve_comments(False)
    tokens_without = lexer.tokenize()
    comments_without = [t for t in tokens_without if t.type == TokenType.COMMENT]

    assert len(comments_with) == 1
    assert len(comments_without) == 0
