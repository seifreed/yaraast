# Copyright (c) 2026 Marc Rivero López
# Licensed under GPLv3. See LICENSE file for details.
# This test suite validates real code behavior without mocks or stubs.
"""Regression coverage for yaraast.parser.error_tolerant_recovery.

Targets the branches and lines that the existing test suite leaves uncovered
at 92.20%.  Every test exercises the production functions directly through
real YARA-like input strings and the real ErrorTolerantParser.  No mocks of
the module under test are used.

Reachable missing lines covered here
-------------------------------------
161-165  parse_string_line — hex fallback path where HexStringParser raises
         HexParseError (invalid hex bytes inside braces after the standard
         parser already returned None).

166-170  parse_string_line — hex fallback success path (standard parser
         rejected the line because of an unsupported modifier, plain_match
         did not fire because the line is not a quoted string, hex_match
         succeeded, HexStringParser parsed the byte content successfully).

224      parse_condition — the ``start < 0`` branch: raw_line is provided
         but the stripped condition_text is not a substring of raw_line, so
         raw_line.find() returns -1 and must be clamped to 0.

Structurally unreachable lines
--------------------------------
209      parse_string_line_with_standard_parser — returns None when
         ast.rules is empty or ast.rules[0].strings is empty after a
         successful parse.  The helper always wraps the input in a fixed
         ``rule recovered { strings: ... }`` template; if the Parser
         succeeds it always produces exactly one rule with at least one
         string (otherwise the Parser raises and line 206 fires instead).

214      parse_string_line_with_standard_parser — returns None when the
         string definition is not a PlainString, HexString, or RegexString.
         The Parser never places any other node type in rule.strings for
         YARA classic syntax.

242      _parse_recovered_condition_expression — returns Identifier when
         the parser succeeds but ast.rules is empty or the condition is
         None.  If the Parser().parse() call succeeds it always produces
         exactly one rule with a non-None condition; failures are handled
         by the except clause on line 239.

These three lines are documented here as genuine dead-code guards rather
than driven through artificial monkeypatching that would not represent real
code execution.
"""

from __future__ import annotations

from yaraast.ast.strings import HexString
from yaraast.parser.error_tolerant_parser import ErrorTolerantParser
from yaraast.parser.error_tolerant_recovery import parse_condition, parse_string_line

# ---------------------------------------------------------------------------
# Lines 163-165: HexParseError path inside parse_string_line hex fallback
# ---------------------------------------------------------------------------


def test_parse_string_line_hex_fallback_invalid_bytes_returns_none_and_records_error() -> None:
    """Arrange: a string definition whose standard parser fails and whose
    hex content is syntactically invalid (``ZZ`` is not a valid hex byte).

    parse_string_line_with_standard_parser wraps the line in a rule snippet
    and calls the strict Parser; that fails, so it returns None.  The
    plain-string regex does not match (no double-quoted value).  The hex
    fallback regex matches the ``$x = { ... }`` portion, but HexStringParser
    rejects ``ZZ ZZ`` and raises HexParseError — exercising lines 163-165.

    Act: call parse_string_line with a line containing ``$x = { ZZ ZZ }``.

    Assert: the return value is None and the parser records exactly one
    error whose message mentions the invalid character.
    """
    line = "$x = { ZZ ZZ }"
    parser = ErrorTolerantParser(f"rule r {{ strings:\n    {line}\n condition:\n    true\n}}")
    parser.lines = [line]

    result = parse_string_line(parser, line, 0)

    assert result is None
    assert len(parser.errors) == 1
    assert "invalid character" in parser.errors[0].message.lower()


def test_parse_string_line_hex_fallback_multiple_invalid_tokens_records_first_error() -> None:
    """Arrange: two sets of invalid hex tokens in the same hex body.

    HexParseError fires on the first invalid token; only one error is
    recorded and the function returns None.
    """
    line = "$data = { GG HH II }"
    parser = ErrorTolerantParser(f"rule r {{ strings:\n    {line}\n condition:\n    true\n}}")
    parser.lines = [line]

    result = parse_string_line(parser, line, 0)

    assert result is None
    assert len(parser.errors) == 1


# ---------------------------------------------------------------------------
# Lines 166-170: hex fallback success path inside parse_string_line
# ---------------------------------------------------------------------------


def test_parse_string_line_hex_fallback_success_with_modifier_suffix() -> None:
    """Arrange: a hex string followed by the ``nocase`` modifier.

    ``nocase`` after a hex-string braces block is not valid YARA syntax, so
    the strict Parser (called by parse_string_line_with_standard_parser)
    rejects the snippet and returns None.  The plain-string regex also does
    not match.  The hex regex matches up to the closing ``}`` and discards
    the trailing modifier text.  HexStringParser succeeds on ``DE AD BE EF``
    — exercising lines 166-170.

    Act: call parse_string_line with ``$a = { DE AD BE EF } nocase``.

    Assert: a HexString with identifier ``$a`` and four hex bytes is
    returned; no errors are recorded.
    """
    line = "$a = { DE AD BE EF } nocase"
    parser = ErrorTolerantParser(f"rule r {{ strings:\n    {line}\n condition:\n    true\n}}")
    parser.lines = [line]

    result = parse_string_line(parser, line, 0)

    assert isinstance(result, HexString)
    assert result.identifier == "$a"
    assert len(result.tokens) == 4
    assert len(parser.errors) == 0


def test_parse_string_line_hex_fallback_success_wide_modifier() -> None:
    """Arrange: a hex string followed by the ``wide`` modifier.

    The standard parser rejects the snippet, so the fallback fires.
    The hex content ``CA FE`` is valid for HexStringParser.

    Act: call parse_string_line with ``$b = { CA FE } wide``.

    Assert: a HexString with identifier ``$b`` and two bytes is returned.
    """
    line = "$b = { CA FE } wide"
    parser = ErrorTolerantParser(f"rule r {{ strings:\n    {line}\n condition:\n    true\n}}")
    parser.lines = [line]

    result = parse_string_line(parser, line, 0)

    assert isinstance(result, HexString)
    assert result.identifier == "$b"
    assert len(result.tokens) == 2
    assert len(parser.errors) == 0


def test_parse_string_line_hex_fallback_location_is_set() -> None:
    """Arrange: a hex string with a valid body and an extra modifier.

    When the hex fallback succeeds (lines 166-170), set_recovered_location
    is called with the matched start and end columns derived from the hex
    regex group positions.

    Act: call parse_string_line.

    Assert: the returned HexString has a non-None location with line_num+1
    as its line number.
    """
    line = "$sig = { FF D8 FF E0 } ascii"
    line_num = 3
    parser = ErrorTolerantParser("rule r { condition: true }")
    # Populate lines so set_recovered_location can resolve the line text.
    parser.lines = [""] * (line_num + 1)
    parser.lines[line_num] = line

    result = parse_string_line(parser, line, line_num)

    assert isinstance(result, HexString)
    assert result.location is not None
    assert result.location.line == line_num + 1


# ---------------------------------------------------------------------------
# Line 224: start < 0 branch in parse_condition
# ---------------------------------------------------------------------------


def test_parse_condition_start_clamped_when_text_not_in_raw_line() -> None:
    """Arrange: condition_text that is a valid expression and a raw_line
    that does not contain the stripped condition_text as a substring.

    The function computes ``start = raw_line.find(condition_text)``.  When
    the text is absent, find() returns -1 and line 224 clamps it to 0.
    set_recovered_location is then called with start=0.

    Act: call parse_condition with condition_text='true' and a raw_line
    that only contains 'false' so find() returns -1.

    Assert: the returned node has a non-None location whose column is 1
    (matching start=0 after the clamp, i.e. column = 0+1 = 1).
    """
    condition_text = "true"
    raw_line = "    condition: false"  # 'true' not present
    line_num = 0
    parser = ErrorTolerantParser("rule r { condition: true }")
    parser.lines = [raw_line]

    node = parse_condition(parser, condition_text, line_num, raw_line)

    # start was clamped to 0 so column must be 1 (1-based)
    assert node is not None
    assert node.location is not None
    assert node.location.column == 1


def test_parse_condition_start_clamped_with_complex_expression_not_in_raw_line() -> None:
    """Arrange: a complex condition expression whose text does not appear
    in the supplied raw_line at all.

    This confirms the ``start < 0`` guard handles non-trivial expressions
    and does not raise an exception; the location is pinned to column 1.

    Act: call parse_condition with condition_text='$a and $b' and a
    raw_line that only contains the word 'condition'.

    Assert: the returned node's location column is 1.
    """
    condition_text = "$a and $b"
    raw_line = "    condition:"
    line_num = 2
    parser = ErrorTolerantParser("rule r { condition: true }")
    parser.lines = ["", "", raw_line]

    node = parse_condition(parser, condition_text, line_num, raw_line)

    assert node is not None
    assert node.location is not None
    assert node.location.column == 1


def test_parse_condition_start_not_clamped_when_text_present_in_raw_line() -> None:
    """Regression guard: when condition_text IS present in raw_line, find()
    returns a non-negative value and the clamp at line 224 is NOT triggered.

    The start column must equal the index of condition_text in raw_line
    converted to 1-based column (index + 1).

    Act: call parse_condition with condition_text='true' and raw_line
    '    condition: true'.

    Assert: node.location.column equals the 1-based position of 'true'
    inside raw_line.
    """
    raw_line = "    condition: true"
    condition_text = "true"
    expected_col = raw_line.find(condition_text) + 1  # 1-based
    line_num = 0
    parser = ErrorTolerantParser("rule r { condition: true }")
    parser.lines = [raw_line]

    node = parse_condition(parser, condition_text, line_num, raw_line)

    assert node is not None
    assert node.location is not None
    assert node.location.column == expected_col
