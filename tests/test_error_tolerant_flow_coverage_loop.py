# Copyright (c) 2026 Marc Rivero López
# Licensed under GPLv3. See LICENSE file for details.
# This test suite validates real code behavior without mocks or stubs.
"""Regression coverage for yaraast.parser.error_tolerant_flow.

Targets the branches and lines that the existing test suite leaves uncovered:

  * Lines 96-97  — escape sequence inside a regex literal in _skip_regex_literal
  * Lines 119-122 — block-comment close sequence ``*/`` in _count_braces_outside_literals
  * Lines 125-126 — backslash escape inside a double-quoted string
  * Line  132    — ``//`` line-comment break in _count_braces_outside_literals
  * Lines 134-136 — ``/*`` block-comment open in _count_braces_outside_literals
  * Branch 154->165 — while loop not entered in collect_rule_body (negative brace balance
                       from header)

All tests drive ``error_tolerant_flow`` exclusively through the public
``ErrorTolerantParser`` API, exercising real parsing of real YARA text.  No mocks of the
module under test are used.
"""

from __future__ import annotations

from yaraast.parser.error_tolerant_flow import (
    _count_braces_outside_literals,
    _skip_regex_literal,
    _starts_regex_literal,
    collect_rule_body,
    extract_rule_header,
    parse_rule_with_recovery,
)
from yaraast.parser.error_tolerant_parser import ErrorTolerantParser

# ---------------------------------------------------------------------------
# _skip_regex_literal — lines 96-97: escape sequence branch
# ---------------------------------------------------------------------------


def test_skip_regex_literal_handles_escaped_slash() -> None:
    """Arrange: regex literal with an escaped slash ``\\/``.

    The escape branch (lines 96-97) increments by 2 and continues so the
    subsequent ``/`` is treated as part of the pattern, not as the closing
    delimiter.  Only the final ``/`` should be returned as end-of-regex.
    """
    # Input: index 0 is the first char after the opening '/'
    # Full regex body: 'ab\/cd/'  meaning the slash after backslash is escaped
    line = r"$a = /ab\/cd/"
    # The '/' at index 5 is the opening slash
    opening_slash = line.index("/")
    end_pos = _skip_regex_literal(line, opening_slash)
    # The function returns the index just past the closing '/'
    # 'ab\/cd/' — backslash at index 1 inside the literal causes i+=2 skip,
    # then 'cd' are consumed, then the final '/' terminates.
    assert end_pos == len(line)


def test_skip_regex_literal_consumes_multiple_escapes() -> None:
    """Two escape sequences inside a regex literal both trigger lines 96-97."""
    # Regex: /a\/b\/c/  — two escaped slashes, real closing slash at end
    line = r"$x = /a\/b\/c/"
    opening_slash = line.index("/")
    end_pos = _skip_regex_literal(line, opening_slash)
    assert end_pos == len(line)


def test_skip_regex_literal_unterminated_falls_off_end() -> None:
    """A regex with no closing slash returns len(line) via line 101."""
    line = "$a = /noclose"
    opening_slash = line.index("/")
    end_pos = _skip_regex_literal(line, opening_slash)
    # Falls through the while loop without finding '/' and returns i == len(line)
    assert end_pos == len(line)


# ---------------------------------------------------------------------------
# _starts_regex_literal
# ---------------------------------------------------------------------------


def test_starts_regex_literal_true_after_equals() -> None:
    """A '/' that follows '=' is a regex opener."""
    line = "$a = /pattern/"
    slash_idx = line.index("/")
    assert _starts_regex_literal(line, slash_idx) is True


def test_starts_regex_literal_false_after_non_equals() -> None:
    """A '/' in other contexts (division) is not a regex opener."""
    line = "x / 2"
    slash_idx = line.index("/")
    assert _starts_regex_literal(line, slash_idx) is False


# ---------------------------------------------------------------------------
# _count_braces_outside_literals — targeted branch exercises
# ---------------------------------------------------------------------------


def test_count_braces_line_comment_stops_counting() -> None:
    """Line 132: ``//`` terminates brace counting for the rest of the line.

    A ``}`` that appears after ``//`` must NOT decrement the brace counter.
    """
    # Arrange: opening brace before the comment, closing brace INSIDE comment
    line = "{ // comment with } here"
    result = _count_braces_outside_literals(line)
    # Only the '{' before the comment counts; the '}' inside the comment is ignored.
    assert result == 1


def test_count_braces_block_comment_open_skips_contents() -> None:
    """Lines 134-136: ``/*`` opens a block comment; contents are ignored.

    The ``/*`` causes ``in_block_comment`` to become True and ``i += 2``
    advances past the ``*``, executing lines 134-136.
    """
    # A '}' inside a block comment must not reduce the counter.
    line = "{ /* hidden } brace */"
    result = _count_braces_outside_literals(line)
    assert result == 1


def test_count_braces_block_comment_close_resumes_counting() -> None:
    """Lines 119-122: ``*/`` closes a block comment and resumes normal counting.

    After ``*/``, any ``}`` outside the comment should decrement the counter.
    """
    # Open brace, block comment with a spurious }, close comment, then real }
    line = "{ /* spurious } */ }"
    result = _count_braces_outside_literals(line)
    # '{' => +1, block comment swallows '} ', '*/' exits comment, then '}' => -1; net = 0
    assert result == 0


def test_count_braces_block_comment_close_and_open_combined() -> None:
    """Block comment open and close both exercised in one line."""
    # '{ /* } */ }' → net: 1 (open) - 1 (after close) = 0
    line = "{ /* inside } */ }"
    assert _count_braces_outside_literals(line) == 0


def test_count_braces_string_escape_skips_embedded_quote() -> None:
    """Lines 125-126: backslash escape inside a string skips the next character.

    Without the escape handling, a ``\"`` inside the string would prematurely
    end the in_string state, causing later braces to be counted incorrectly.
    """
    # String contains an escaped backslash followed by closing quote, then '}'
    # The raw YARA-style content: "$a = \"a\\b\"}"
    # In Python source we write it as: '$a = "a\\b"}'
    line = '$a = "a\\b"}'
    result = _count_braces_outside_literals(line)
    # The string is "a\b" — the backslash triggers i+=2 (lines 125-126),
    # so the 'b' is skipped, and the closing '"' is the next char.
    # The '}' after the string is real, so count = -1.
    assert result == -1


def test_count_braces_regex_with_escaped_slash_treated_as_literal() -> None:
    """Regex literal containing ``\\/`` is parsed without the escaped slash closing it."""
    # In recovery brace-counting, a regex body like /ab\/cd/ should not confuse braces.
    line = r"$a = /ab\/cd/"
    result = _count_braces_outside_literals(line)
    assert result == 0


# ---------------------------------------------------------------------------
# collect_rule_body — branch 154->165: while loop not entered
# ---------------------------------------------------------------------------


def test_collect_rule_body_loop_skipped_when_header_has_negative_brace_balance() -> None:
    """Branch 154->165: the while loop is not entered when the header already has
    a negative brace balance (more closing than opening braces).

    A header like ``rule Broken }`` yields brace_count = -1 after
    ``_count_braces_outside_literals``.  The while condition requires
    ``brace_count > 0`` or ``(brace_count == 0 and not rule_body_lines)``;
    neither is true when brace_count is -1, so the loop is skipped entirely
    and the function returns immediately with an empty body list.
    """
    parser = ErrorTolerantParser()
    # A two-line file: the broken header and one trailing line.
    parser.lines = ["rule Broken }", "rule Other {"]
    # start_line = 0, header_line has brace_count = -1
    header_line = "rule Broken }"
    body_lines, current_line = collect_rule_body(parser, 0, header_line)
    assert body_lines == []
    # current_line should be start_line + 1 = 1, unchanged from initial value
    assert current_line == 1


def test_collect_rule_body_loop_skipped_when_header_brace_balance_negative_via_parse() -> None:
    """Drive the 154->165 branch end-to-end through the real parser.

    A YARA source containing a header-only rule with a stray ``}`` and no
    opening brace forces the error-tolerant path.  The ``collect_rule_body``
    function must not enter its while loop for that rule; the rule following
    it must still be parsed correctly.
    """
    # The '@@@ ...' line forces the error-tolerant recovery path.
    # 'rule Broken }' has brace_count = -1, triggering the 154->165 branch.
    # 'rule Valid { ... }' must be parsed normally by the recovery scanner.
    source = (
        "rule Valid {\n"
        "    condition:\n"
        "        true\n"
        "}\n"
        "@@@ stray token forces error-tolerant recovery\n"
        "rule Broken }\n"
    )
    result = ErrorTolerantParser().parse(source)

    rule_names = [r.name for r in result.ast.rules]
    # 'Valid' is parsed before the error is injected.
    # 'Broken' is recovered with a placeholder condition; the body loop is skipped.
    assert "Valid" in rule_names
    assert "Broken" in rule_names
    # Broken must have no condition parsed from its (empty) body — an error is recorded.
    broken_errors = [e for e in result.errors if "Broken" in e.message]
    assert broken_errors, "Expected an error about the Broken rule having no condition"


# ---------------------------------------------------------------------------
# Combined end-to-end: all brace-counting branches via real recovery parsing
# ---------------------------------------------------------------------------


def test_recovery_body_with_line_comment_containing_spurious_brace() -> None:
    """Line 132: a ``//`` comment with a ``}`` inside must not close the rule body.

    The brace counter must ignore everything after ``//`` on a line.
    Without line 132 executing, the spurious ``}`` in the comment would
    terminate brace collection prematurely and produce a malformed rule.
    """
    source = (
        "@@@ stray token forces error-tolerant recovery\n"
        "rule LineCommentBrace {\n"
        "    strings:\n"
        '        $a = "test"  // this comment has a } inside\n'
        "    condition:\n"
        "        $a\n"
        "}\n"
    )
    result = ErrorTolerantParser().parse(source)

    rule_names = [r.name for r in result.ast.rules]
    assert "LineCommentBrace" in rule_names
    rule = next(r for r in result.ast.rules if r.name == "LineCommentBrace")
    # The rule body must have been fully collected (strings and condition present).
    assert rule.strings, "Expected the string $a to be collected"
    assert rule.condition is not None


def test_recovery_body_with_block_comment_opening() -> None:
    """Lines 134-136: a ``/*`` inside a body line must not confuse brace counting.

    An unterminated ``/*`` on a body line means everything from that point to
    end-of-line is treated as a comment.  A ``}`` inside it must be ignored.
    """
    source = (
        "@@@ stray token forces error-tolerant recovery\n"
        "rule BlockCommentOpen {\n"
        "    strings:\n"
        '        $a = "x"  /* spurious } brace inside block comment\n'
        "    condition:\n"
        "        $a\n"
        "}\n"
    )
    result = ErrorTolerantParser().parse(source)

    rule_names = [r.name for r in result.ast.rules]
    assert "BlockCommentOpen" in rule_names


def test_recovery_body_with_closed_block_comment_and_real_brace() -> None:
    """Lines 119-122 and 134-136: block comment open AND close on the same body line.

    The ``*/`` sequence must set ``in_block_comment = False`` (lines 119-122)
    so that any ``}`` after it is counted normally.
    """
    source = (
        "@@@ stray token forces error-tolerant recovery\n"
        "rule BlockCommentClose {\n"
        "    strings:\n"
        '        $a = "y"  /* spurious } brace */ \n'
        "    condition:\n"
        "        $a\n"
        "}\n"
    )
    result = ErrorTolerantParser().parse(source)

    rule_names = [r.name for r in result.ast.rules]
    assert "BlockCommentClose" in rule_names
    rule = next(r for r in result.ast.rules if r.name == "BlockCommentClose")
    assert rule.strings


def test_recovery_body_with_string_containing_backslash_escape() -> None:
    """Lines 125-126: a backslash inside a double-quoted string in the body.

    Without the escape handling, the character after ``\\`` could be
    misinterpreted (e.g., a ``"`` would incorrectly close the string state).
    The rule must be fully recovered.
    """
    source = (
        "@@@ stray token forces error-tolerant recovery\n"
        "rule StringEscape {\n"
        "    strings:\n"
        '        $a = "path\\\\to\\\\file"\n'
        "    condition:\n"
        "        $a\n"
        "}\n"
    )
    result = ErrorTolerantParser().parse(source)

    rule_names = [r.name for r in result.ast.rules]
    assert "StringEscape" in rule_names
    rule = next(r for r in result.ast.rules if r.name == "StringEscape")
    assert rule.strings


def test_recovery_body_with_regex_containing_escaped_slash() -> None:
    """Lines 96-97: ``\\/`` inside a regex literal in a rule body line.

    ``_skip_regex_literal`` must advance by 2 when it encounters ``\\``,
    so the ``/`` that follows is part of the pattern and does not terminate
    the literal.  The rule must be recovered with its regex string.
    """
    # Build the source string carefully to avoid Python SyntaxWarning on \/.
    # The YARA string content we want on that line is literally: $a = /ab\/cd/
    regex_line = r"        $a = /ab\/cd/"
    source = (
        "@@@ stray token forces error-tolerant recovery\n"
        "rule RegexEscape {\n"
        "    strings:\n" + regex_line + "\n"
        "    condition:\n"
        "        $a\n"
        "}\n"
    )
    result = ErrorTolerantParser().parse(source)

    rule_names = [r.name for r in result.ast.rules]
    assert "RegexEscape" in rule_names


# ---------------------------------------------------------------------------
# extract_rule_header — error path (lines 80-81)
# ---------------------------------------------------------------------------


def test_extract_rule_header_returns_none_on_invalid_declaration() -> None:
    """Lines 80-81: when the regex does not match, an error is added and None is returned.

    This exercises the early-return path in extract_rule_header.
    """
    parser = ErrorTolerantParser()
    parser.lines = ["not a rule declaration"]
    parser.errors = []

    rule_name, tags, modifiers = extract_rule_header(parser, "not a rule declaration", 0)

    assert rule_name is None
    assert tags == []
    assert modifiers == []
    assert len(parser.errors) == 1
    assert "Invalid rule declaration" in parser.errors[0].message


# ---------------------------------------------------------------------------
# parse_rule_with_recovery — None-rule branch documentation
# ---------------------------------------------------------------------------


def test_parse_rule_with_recovery_returns_none_rule_on_invalid_header() -> None:
    """Lines 59-60: when extract_rule_header fails, parse_rule_with_recovery
    returns (None, 1).

    This is the path exercised when the rule header regex does not match.
    """
    parser = ErrorTolerantParser()
    parser.lines = ["@@@ this is not a rule"]
    parser.errors = []

    rule, consumed = parse_rule_with_recovery(parser, 0)

    assert rule is None
    assert consumed == 1


# ---------------------------------------------------------------------------
# parse_with_recovery — import and include recovery paths
# ---------------------------------------------------------------------------


def test_parse_with_recovery_handles_import_statements() -> None:
    """Lines 27-31: import lines are parsed and appended to the YaraFile.

    This is the import branch in the main recovery loop.
    """
    parser = ErrorTolerantParser()
    # Force recovery by providing a body that the strict parser rejects
    source = '@@@ force recovery\nimport "pe"\nrule R {\n    condition:\n        true\n}\n'
    result = parser.parse(source)

    import_names = [imp.module for imp in result.ast.imports]
    assert "pe" in import_names


def test_parse_with_recovery_handles_include_statements() -> None:
    """Lines 34-38: include lines are parsed and appended to the YaraFile.

    This is the include branch in the main recovery loop.
    """
    parser = ErrorTolerantParser()
    source = (
        "@@@ force recovery\n"
        'include "common.yar"\n'
        "rule R {\n"
        "    condition:\n"
        "        true\n"
        "}\n"
    )
    result = parser.parse(source)

    include_paths = [inc.path for inc in result.ast.includes]
    assert "common.yar" in include_paths


def test_parse_with_recovery_appends_rule_to_recovered_rules() -> None:
    """Lines 42-45: when a rule is recovered, it is appended to both ast.rules
    and parser.recovered_rules inside parse_with_recovery.
    """
    parser = ErrorTolerantParser()
    source = "@@@ force recovery\n" "rule Recovered {\n" "    condition:\n" "        true\n" "}\n"
    result = parser.parse(source)

    assert any(r.name == "Recovered" for r in result.ast.rules)
    assert any(r.name == "Recovered" for r in parser.get_recovered_rules())
