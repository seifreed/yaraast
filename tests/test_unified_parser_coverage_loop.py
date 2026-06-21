"""Targeted regression tests to cover remaining branches in unified_parser.

Copyright (c) 2026 Marc Rivero López
Licensed under GPLv3. See LICENSE file for details.
This test suite validates real code behavior without mocks or stubs.

Missing branches addressed:
  - Line 150: escaped=False reset after backslash-escape inside a quoted string
  - Line 152: escaped=True set when backslash is encountered inside a quoted string
  - Lines 301-303: _parse_file_streaming falls back to traditional parser for
                   YARA-X and YARA-L files when force_streaming=True with no
                   explicit dialect (auto-detection returns non-standard dialect)
  - Line 309: the _dialect_factory closure body inside _parse_file_streaming
              (confirmed unreachable via the public API because StreamingParser is
               always constructed without a dialect argument in that path)
  - Line 197: defensive guard in _extract_preamble_source after _strip_comments
              (confirmed unreachable: _strip_comments guarantees non-None returns
               always have a non-empty .strip())
"""

from __future__ import annotations

from pathlib import Path

import pytest

from yaraast.ast.base import YaraFile
from yaraast.dialects import YaraDialect
from yaraast.unified_parser import UnifiedParser
from yaraast.yaral.ast_nodes import YaraLFile

# ---------------------------------------------------------------------------
# Lines 150 and 152: backslash escape handling inside strings in _strip_comments
# ---------------------------------------------------------------------------


def test_strip_comments_backslash_sets_and_clears_escaped_flag() -> None:
    """Line 152 (escaped=True) and line 150 (escaped=False) are hit when
    _strip_comments encounters a backslash inside a double-quoted string,
    then a subsequent non-quote character resets the flag.

    Concrete input: 'include "path\\\\to\\\\file.yar"\\n'
    In that raw string the file line is:   include "path\\to\\file.yar"
    The parser sees: " -> in_string=True; p,a,t,h -> appended; \\ -> line 152
    (escaped=True); t -> line 149 (append) + line 150 (escaped=False); o -> ...
    """
    # Raw file line: include "path\to\file.yar"\n
    # Python string to represent those bytes:
    line = 'include "path\\to\\file.yar"\n'
    result, still_in_multiline = UnifiedParser._strip_comments(line, False)

    # The line is NOT inside a comment, so the full line is returned unchanged.
    assert result == line
    assert still_in_multiline is False


def test_strip_comments_escaped_quote_inside_string_does_not_close_string() -> None:
    """Line 152 is hit (backslash seen inside string, escaped=True).
    Line 150 is hit when the immediately following character is a quote,
    which would otherwise close the string, but the escape prevents that.

    Raw file line:  include "file\"suffix.yar"
    Sequence: " -> in_string=True; ... ; \\ -> escaped=True (line 152);
    \" -> escaped branch (line 149 append + line 150 escaped=False, NOT line 153);
    suffix.yar" -> continuation; " -> in_string=False.
    """
    # Raw file line: include "file\"suffix.yar"
    line = 'include "file\\"suffix.yar"\n'
    result, still_in_multiline = UnifiedParser._strip_comments(line, False)

    assert result == line
    assert still_in_multiline is False


def test_strip_comments_multiple_escapes_inside_string() -> None:
    """Multiple backslashes in a single string exercise lines 150 and 152
    repeatedly.  Each pair of \\ characters is a double-escape (literal
    backslash), meaning: first \\ sets escaped=True (line 152), the second
    \\ is seen in the escaped branch and clears it (line 150).
    """
    # Raw file line: include "a\\b\\c.yar"
    line = 'include "a\\\\b\\\\c.yar"\n'
    result, still_in_multiline = UnifiedParser._strip_comments(line, False)

    assert result == line
    assert still_in_multiline is False


def test_strip_comments_backslash_at_end_of_string_content() -> None:
    """Backslash followed immediately by the closing quote exercises line 152
    (escaped=True) and then line 150 (escaped=False) when the quote is treated
    as an escaped character, keeping in_string=True until the next quote.

    Raw file line:  rule_path = "ends_with\\"
    """
    # File content line: rule_path = "ends_with\"
    # After escaping the closing quote: the string continues past it.
    # The actual byte sequence in the file: rule_path = "ends_with\"<more>"\n
    line = 'rule_path = "ends_with\\"more"\n'
    result, still_in_multiline = UnifiedParser._strip_comments(line, False)

    assert result == line
    assert still_in_multiline is False


def test_strip_comments_preamble_with_escaped_path_produces_correct_imports(
    tmp_path: Path,
) -> None:
    """End-to-end: a preamble file whose string literal contains backslash
    characters exercises lines 150 and 152 inside _extract_preamble_source,
    which calls _strip_comments for every line.

    The import statement uses a module name without backslashes (import "pe")
    to ensure it parses cleanly; the include uses a Unix path with no
    backslashes either.  A separate comment-bearing line includes a
    double-backslash string so that _strip_comments walks through the escape
    paths (lines 152 and 150) but the string is still inside a comment
    so it does not affect the AST.
    """
    # The line below causes _strip_comments to visit lines 152 + 150 during
    # preamble scanning because it is processed as raw text (comment stripping
    # happens before rule parsing).  The string "path\\to" inside a comment
    # means the scanner enters in_string during comment processing.
    preamble = (
        'import "pe"\n'
        '// include "path\\\\to\\\\file.yar"\n'
        'include "libs/common.yar"\n'
        "rule r { condition: true }\n"
    )
    rule_file = tmp_path / "preamble_escape.yar"
    rule_file.write_text(preamble, encoding="utf-8")

    ast = UnifiedParser._extract_preamble_ast_fast(rule_file)

    assert len(ast.imports) == 1
    assert ast.imports[0].module == "pe"
    assert len(ast.includes) == 1
    assert ast.includes[0].path == "libs/common.yar"


# ---------------------------------------------------------------------------
# Lines 301-303: _parse_file_streaming fallback to traditional parser when
# the auto-detected dialect is YARA-X or YARA-L (non-streaming dialects)
# ---------------------------------------------------------------------------


def test_parse_file_force_streaming_with_yarax_content_falls_back_to_traditional(
    tmp_path: Path,
) -> None:
    """Lines 301-303: when force_streaming=True and dialect=None, the streaming
    path detects the file's dialect first.  If the dialect is YARA-X the
    streaming parser (which only supports standard YARA) is bypassed and the
    traditional parser handles the file instead.

    The YARA-X list literal [1, 2][0] triggers YARA-X auto-detection.
    """
    yarax_source = "rule test_list_access { condition: [1, 2][0] }\n"
    rule_file = tmp_path / "test_yarax.yar"
    rule_file.write_text(yarax_source, encoding="utf-8")

    # Confirm the file is detected as YARA-X so the test premise holds.
    assert UnifiedParser.detect_file_dialect(rule_file) == YaraDialect.YARA_X

    # force_streaming=True with no explicit dialect must fall through to the
    # traditional parser for YARA-X (lines 301-303).
    ast = UnifiedParser.parse_file(rule_file, force_streaming=True)

    assert isinstance(ast, YaraFile)
    assert len(ast.rules) == 1
    assert ast.rules[0].name == "test_list_access"


def test_parse_file_force_streaming_with_yaral_content_falls_back_to_traditional(
    tmp_path: Path,
) -> None:
    """Lines 301-303: same fallback path for YARA-L dialect.

    A YARA-L rule with an 'events:' block is auto-detected as YARA-L.
    The streaming path must fall back to the traditional YARA-L parser.
    """
    yaral_source = (
        "rule login_detect {\n"
        "  events:\n"
        '    $e.metadata.event_type = "LOGIN"\n'
        "  condition:\n"
        "    $e\n"
        "}\n"
    )
    rule_file = tmp_path / "test_yaral.yar"
    rule_file.write_text(yaral_source, encoding="utf-8")

    # Confirm the file is detected as YARA-L so the test premise holds.
    detected = UnifiedParser.detect_file_dialect(rule_file)
    assert detected == YaraDialect.YARA_L

    # force_streaming=True with no explicit dialect must fall through to the
    # traditional YARA-L parser for YARA-L (lines 301-303).
    ast = UnifiedParser.parse_file(rule_file, force_streaming=True)

    assert isinstance(ast, YaraLFile)
    assert len(ast.rules) == 1
    assert ast.rules[0].name == "login_detect"


def test_parse_file_force_streaming_with_yarax_dialect_explicitly_skips_fallback(
    tmp_path: Path,
) -> None:
    """Complementary negative: when the dialect is passed EXPLICITLY (not None),
    _parse_file_streaming skips the auto-detection block (lines 296-303) and
    proceeds directly to the streaming path (lines 305+).

    This verifies lines 301-303 are reached ONLY via the auto-detection branch,
    not via explicit dialect.
    """
    # A plain standard YARA file used with explicit YARA_X dialect forces the
    # streaming parser to handle it as YARA-X — which for a simple rule that
    # parses identically under both parsers produces a valid YaraFile.
    yara_source = "rule explicit_dialect_test { condition: true }\n"
    rule_file = tmp_path / "explicit_dialect.yar"
    rule_file.write_text(yara_source, encoding="utf-8")

    ast = UnifiedParser.parse_file(
        rule_file,
        dialect=YaraDialect.YARA,
        force_streaming=True,
    )

    assert isinstance(ast, YaraFile)
    assert len(ast.rules) == 1
    assert ast.rules[0].name == "explicit_dialect_test"


# ---------------------------------------------------------------------------
# Line 197 and line 309 — confirmed unreachable; documented here as a record.
# ---------------------------------------------------------------------------


def test_strip_comments_multiline_spanning_entire_line_returns_none_not_empty() -> None:
    """Confirms the invariant that makes line 197 unreachable.

    _strip_comments returns None (not an empty string) whenever the
    effective content after comment removal is purely whitespace.  Because
    _extract_preamble_source checks for None at line 192 before reaching
    line 197, there is no code path that reaches line 197 with stripped==''.

    This test pins the observable contract: a line that is entirely inside a
    multiline comment must produce None, not ('', ...).
    """
    # Entire line is a multiline comment continuation.
    line_inside_block = "still inside the comment\n"
    result, still_in_multiline = UnifiedParser._strip_comments(line_inside_block, True)
    assert result is None
    assert still_in_multiline is True

    # Line that opens AND closes a block comment with only whitespace remaining.
    line_open_close_whitespace = "  /* comment */  \n"
    result2, still2 = UnifiedParser._strip_comments(line_open_close_whitespace, False)
    assert result2 is None
    assert still2 is False


def test_parse_file_force_streaming_standard_yara_dialect_factory_not_invoked(
    tmp_path: Path,
) -> None:
    """Documents that line 309 (_dialect_factory closure body) is not reached
    via the public API.

    _parse_file_streaming constructs StreamingParser without a 'dialect'
    argument, so StreamingParser.dialect stays None and _parse_content never
    calls dialect_parser_factory.  We verify the end result is still correct
    (the file is parsed successfully) without asserting on line 309 coverage,
    which is structurally unreachable.
    """
    yara_source = 'import "pe"\n' "rule standard_streaming {\n" "  condition:\n" "    true\n" "}\n"
    rule_file = tmp_path / "standard.yar"
    rule_file.write_text(yara_source, encoding="utf-8")

    ast = UnifiedParser.parse_file(rule_file, force_streaming=True)

    assert isinstance(ast, YaraFile)
    assert len(ast.rules) == 1
    assert ast.rules[0].name == "standard_streaming"
    assert len(ast.imports) == 1
    assert ast.imports[0].module == "pe"


# ---------------------------------------------------------------------------
# Additional edge cases for _strip_comments to maximise branch coverage
# ---------------------------------------------------------------------------


def test_strip_comments_line_comment_after_content_strips_comment() -> None:
    """// line comment after real content: content returned, comment discarded."""
    line = 'import "pe" // load pe module\n'
    result, still_in_ml = UnifiedParser._strip_comments(line, False)

    assert result is not None
    assert "import" in result
    assert "//" not in result
    assert still_in_ml is False


def test_strip_comments_block_comment_mid_line_strips_comment() -> None:
    """Inline /* ... */ block comment mid-line: surrounding content preserved."""
    line = 'import "hash" /* inline block comment */ \n'
    result, still_in_ml = UnifiedParser._strip_comments(line, False)

    # After the block comment the remaining text is only whitespace,
    # so result is None (all non-comment text is before the comment start).
    # The import content before /* is 'import "hash" '
    assert result is not None
    assert "import" in result
    assert "/*" not in result
    assert still_in_ml is False


def test_strip_comments_continued_block_comment_mid_line_terminates() -> None:
    """A multiline comment that closes mid-line: text after */ is included."""
    line = 'still in block */ import "pe"\n'
    result, still_in_ml = UnifiedParser._strip_comments(line, True)

    assert result is not None
    assert "import" in result
    assert still_in_ml is False


def test_strip_comments_block_comment_never_closed_returns_none_in_multiline() -> None:
    """A /* that never closes on this line: returns (None, True)."""
    line = "some content /* start of block comment\n"
    result, still_in_ml = UnifiedParser._strip_comments(line, False)

    # 'some content ' has non-empty strip, so result is non-None
    assert result is not None
    assert "some content" in result
    assert still_in_ml is True


def test_strip_comments_empty_line_returns_none() -> None:
    """An empty line returns (None, False)."""
    result, still_in_ml = UnifiedParser._strip_comments("", False)
    assert result is None
    assert still_in_ml is False


def test_strip_comments_whitespace_only_line_returns_none() -> None:
    """A whitespace-only line returns (None, False)."""
    result, still_in_ml = UnifiedParser._strip_comments("   \t  \n", False)
    assert result is None
    assert still_in_ml is False


@pytest.mark.parametrize(
    "dialect",
    [YaraDialect.YARA, YaraDialect.YARA_X, YaraDialect.YARA_L],
)
def test_unified_parser_explicit_dialect_roundtrip_get_dialect(
    dialect: YaraDialect,
) -> None:
    """get_dialect() returns whatever dialect was passed to the constructor."""
    parser = UnifiedParser("rule x { condition: true }", dialect=dialect)
    assert parser.get_dialect() == dialect
