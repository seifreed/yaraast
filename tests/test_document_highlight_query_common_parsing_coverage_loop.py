"""Coverage tests for document_highlight, document_query_common, and parsing LSP modules.

Targets three modules with real YARA document parsing - no mocks, no stubs:
  yaraast/lsp/document_highlight.py    (missing: branch 34->51, lines 41, 52-54, 66, 72, 83, 85)
  yaraast/lsp/document_query_common.py (missing: line 8, branch 20->22)
  yaraast/lsp/parsing.py               (missing: line 20, line 25; line 26 structurally unreachable)

Copyright (c) 2026 Marc Rivero Lopez
Licensed under GPLv3. See LICENSE file for details.
This test suite validates real code behavior without mocks or stubs.
"""

from __future__ import annotations

from lsprotocol.types import DocumentHighlightKind, Position
import pytest

from yaraast.errors import ParseError
from yaraast.lsp.document_highlight import DocumentHighlightProvider
from yaraast.lsp.document_query_common import whole_word_positions
from yaraast.lsp.parsing import parse_for_lsp
from yaraast.parser._shared import ParserError


def _pos(line: int, char: int) -> Position:
    return Position(line=line, character=char)


# ---------------------------------------------------------------------------
# yaraast/lsp/document_query_common.py — whole_word_positions
# ---------------------------------------------------------------------------


def test_whole_word_positions_empty_word_returns_empty_list() -> None:
    """Line 8: early-return guard when word is the empty string."""
    # Arrange: any non-empty line, empty search term
    line = "rule alpha { condition: true }"

    # Act
    result = whole_word_positions(line, "")

    # Assert: the empty-word guard at line 8 fires and returns []
    assert result == []


def test_whole_word_positions_word_not_present_returns_empty_list() -> None:
    """Baseline: line.find returns -1 immediately, outer loop exits."""
    result = whole_word_positions("condition: true", "alpha")
    assert result == []


def test_whole_word_positions_right_boundary_fails_when_followed_by_alnum() -> None:
    """Branch 20→22: right_ok is False when the next char is alphanumeric.

    'alphabeta alpha' — the first occurrence of 'alpha' is inside 'alphabeta'
    so its right neighbour is 'b' (alnum), making right_ok False.  That match
    is skipped; only the standalone 'alpha' at col 10 is returned.
    """
    # Arrange
    line = "alphabeta alpha"

    # Act
    result = whole_word_positions(line, "alpha")

    # Assert: embedded prefix is rejected; standalone match is returned
    assert result == [10]


def test_whole_word_positions_right_boundary_fails_when_followed_by_underscore() -> None:
    """Branch 20→22: right_ok is False when the next char is an underscore.

    'alpha_test alpha' — 'alpha_test' has '_' immediately after 'alpha';
    that fails the right-boundary check so only the second 'alpha' is found.
    """
    line = "alpha_test alpha"
    result = whole_word_positions(line, "alpha")
    assert result == [11]


def test_whole_word_positions_left_boundary_fails_when_preceded_by_alnum() -> None:
    """Left-boundary guard: match rejected when the preceding char is alnum."""
    line = "xalpha alpha"
    result = whole_word_positions(line, "alpha")
    assert result == [7]


def test_whole_word_positions_exact_word_at_start() -> None:
    """Word at column 0 — left-boundary check uses col==0 path."""
    result = whole_word_positions("alpha beta", "alpha")
    assert result == [0]


def test_whole_word_positions_multiple_occurrences_all_standalone() -> None:
    """Multiple standalone occurrences are all collected."""
    result = whole_word_positions("alpha alpha alpha", "alpha")
    assert result == [0, 6, 12]


def test_whole_word_positions_word_at_end_of_line() -> None:
    """Word exactly at end of line: right_idx >= len(line) so right_ok is True."""
    result = whole_word_positions("condition alpha", "alpha")
    assert result == [10]


# ---------------------------------------------------------------------------
# yaraast/lsp/parsing.py — parse_for_lsp
# ---------------------------------------------------------------------------


def test_parse_for_lsp_returns_ast_for_valid_document() -> None:
    """Line 20: ast is not None branch — valid document returns the AST object."""
    # Arrange: a syntactically correct YARA rule
    yara_src = "rule valid { condition: true }"

    # Act
    ast = parse_for_lsp(yara_src)

    # Assert: a real AST object is returned (not None, not an exception)
    assert ast is not None
    assert hasattr(ast, "rules")


def test_parse_for_lsp_returns_ast_for_rule_with_strings() -> None:
    """Line 20: ast returned for rule with strings section (not just condition)."""
    yara_src = 'rule strings_rule { strings: $a = "abc" condition: $a }'
    ast = parse_for_lsp(yara_src)
    assert ast is not None


def test_parse_for_lsp_raises_parse_error_wrapping_lexer_error() -> None:
    """Line 23-24: LexerError is wrapped in ParseError (existing test — parity check)."""
    with pytest.raises(ParseError):
        parse_for_lsp('rule bad { strings: $a = "\ud800" condition: $a }')


def test_parse_for_lsp_raises_parser_error_for_invalid_syntax() -> None:
    """Line 25: non-LexerError parse failure re-raises the original exception.

    A rule with no name ('rule { condition: true }') triggers a ParserError from
    the underlying grammar parser.  parse_for_lsp must re-raise that error as-is
    so callers can distinguish parser failures from lexer failures.
    """
    # Arrange: syntactically invalid — missing rule name
    malformed = "rule { condition: true }"

    # Act & Assert: ParserError is propagated directly (line 25)
    with pytest.raises(ParserError):
        parse_for_lsp(malformed)


def test_parse_for_lsp_raises_parser_error_for_missing_condition() -> None:
    """Line 25: another ParserError path — rule body with no condition keyword."""
    malformed = "rule incomplete {"

    with pytest.raises(ParserError):
        parse_for_lsp(malformed)


def test_parse_for_lsp_with_explicit_uri() -> None:
    """Line 20: ast returned when optional uri parameter is supplied."""
    yara_src = "rule with_uri { condition: true }"
    ast = parse_for_lsp(yara_src, uri="file:///test/rule.yar")
    assert ast is not None


# ---------------------------------------------------------------------------
# yaraast/lsp/document_highlight.py — get_highlights coverage gaps
# ---------------------------------------------------------------------------


def test_document_highlight_module_member_falls_through_to_identifier_highlight() -> None:
    """Branch 34→51: resolved kind is 'module_member' — falls through all resolved
    branches and reaches the plain identifier highlight path (line 57).

    A 'module_member' resolved symbol is neither 'string' nor 'rule', and
    _is_local_shadow returns False for it (kind != 'identifier'), so execution
    falls through the resolved block to the general identifier highlight path.
    """
    # Arrange: import pe and reference pe.is_pe
    yara_src = "import pe\nrule module_ref {\n    condition:\n        pe.is_pe\n}\n"
    provider = DocumentHighlightProvider()

    # Act: position on 'pe' part of 'pe.is_pe' (line 3, col 8)
    highlights = provider.get_highlights(yara_src, _pos(3, 8))

    # Assert: at least one highlight is returned for the identifier
    assert len(highlights) >= 1


def test_document_highlight_hash_prefix_remapped_to_dollar_prefix() -> None:
    """Lines 52-54: word starts with '#' (string count operator) — remapped to '$'.

    When the cursor is on '#a', resolve_symbol returns None (the count operator
    is not a declaration), so the code reaches the string-prefix check at line 51.
    Because '#' is in the prefix set and is not '$', it gets rewritten to '$a'
    before calling _highlight_string_identifier.  All occurrences of $a, #a, @a,
    and !a should appear in the result.
    """
    # Arrange: rule with $a used via all four prefixes
    yara_src = (
        "rule r {\n"
        "    strings:\n"
        '        $a = "abc"\n'
        "    condition:\n"
        "        #a == 1 and @a > 0 and !a[0] == 3 and $a\n"
        "}\n"
    )
    provider = DocumentHighlightProvider()
    line4 = yara_src.splitlines()[4]
    hash_col = line4.index("#a")

    # Act: cursor on '#a'
    highlights = provider.get_highlights(yara_src, _pos(4, hash_col))

    # Assert: all string-related occurrences highlighted
    assert len(highlights) >= 4


def test_document_highlight_at_prefix_remapped_to_dollar_prefix() -> None:
    """Lines 52-54: word starts with '@' (string offset operator) — remapped to '$'."""
    yara_src = (
        "rule r {\n"
        "    strings:\n"
        '        $b = "xyz"\n'
        "    condition:\n"
        "        $b and #b > 0 and @b == 0\n"
        "}\n"
    )
    provider = DocumentHighlightProvider()
    line4 = yara_src.splitlines()[4]
    at_col = line4.index("@b")

    highlights = provider.get_highlights(yara_src, _pos(4, at_col))
    assert len(highlights) >= 3


def test_document_highlight_bang_prefix_remapped_to_dollar_prefix() -> None:
    """Lines 52-54: word starts with '!' (string length operator) — remapped to '$'."""
    yara_src = (
        'rule r {\n    strings:\n        $c = "foo"\n    condition:\n        $c and !c[0] > 2\n}\n'
    )
    provider = DocumentHighlightProvider()
    line4 = yara_src.splitlines()[4]
    bang_col = line4.index("!c")

    highlights = provider.get_highlights(yara_src, _pos(4, bang_col))
    assert len(highlights) >= 2


def test_document_highlight_is_local_shadow_plain_identifier_not_a_rule() -> None:
    """Line 83: _is_local_shadow reaches find_rule_definition path.

    When resolve_symbol returns kind='identifier' for a for-loop variable that
    is NOT a string identifier (word does not start with $ # @ !), _is_local_shadow
    calls ctx.find_rule_definition(normalized_name).  If the name is not a rule,
    find_rule_definition returns None so _is_local_shadow returns False, and
    execution falls through to the general highlight path.
    """
    # Arrange: a for-loop variable 'i' that is not a rule name
    yara_src = "rule loop_var {\n    condition:\n        for all i in (1, 2) : (i > 0)\n}\n"
    provider = DocumentHighlightProvider()
    line2 = yara_src.splitlines()[2]
    usage_col = line2.rindex("i")

    # Act: position on 'i' in the usage site 'i > 0'
    highlights = provider.get_highlights(yara_src, _pos(2, usage_col))

    # Assert: both the declaration and usage of 'i' are highlighted
    cols = {(h.range.start.line, h.range.start.character) for h in highlights}
    decl_col = line2.index("i")
    assert (2, decl_col) in cols
    assert (2, usage_col) in cols


def test_document_highlight_is_local_shadow_plain_identifier_is_a_rule() -> None:
    """Line 83: _is_local_shadow calls find_rule_definition and gets a result.

    When a plain identifier happens to match a rule name and resolution returns
    kind='identifier' (e.g., a for-loop variable that shadows a rule name),
    _is_local_shadow finds the rule and returns True — the result is a single-
    location highlight covering only the local binding.
    """
    # Arrange: 'helper' is both a rule name and a for-loop variable
    yara_src = (
        "rule helper { condition: true }\n"
        "rule local_ref {\n"
        "    condition:\n"
        "        for all helper in (1, 2) : (helper > 0)\n"
        "}\n"
    )
    provider = DocumentHighlightProvider()
    line3 = yara_src.splitlines()[3]
    decl_col = line3.index("helper")

    # Act: cursor on the for-loop variable declaration
    highlights = provider.get_highlights(yara_src, _pos(3, decl_col))

    # Assert: the resolved kind is 'identifier' and _is_local_shadow returns True,
    # so only the single local declaration range is returned.
    assert len(highlights) == 1
    assert highlights[0].range.start.line == 3
    assert highlights[0].kind == DocumentHighlightKind.Text


def test_document_highlight_invalid_text_type_raises_type_error() -> None:
    """Guard clause: non-string text raises TypeError immediately."""
    provider = DocumentHighlightProvider()
    with pytest.raises(TypeError, match="must be a string"):
        provider.get_highlights(42, _pos(0, 0))  # type: ignore[arg-type]


def test_document_highlight_invalid_position_type_raises_type_error() -> None:
    """Guard clause: non-Position position raises TypeError immediately."""
    provider = DocumentHighlightProvider()
    with pytest.raises(TypeError, match="must be an LSP Position"):
        provider.get_highlights("rule a { condition: true }", (0, 0))  # type: ignore[arg-type]


def test_document_highlight_empty_text_returns_empty_list() -> None:
    """No word at position in empty document returns empty list."""
    provider = DocumentHighlightProvider()
    highlights = provider.get_highlights("", _pos(0, 0))
    assert highlights == []


def test_document_highlight_highlights_from_records_assigns_write_to_declaration() -> None:
    """_highlights_from_records: role='declaration' maps to DocumentHighlightKind.Write."""
    yara_src = 'rule target {\n    strings:\n        $x = "test"\n    condition:\n        $x\n}\n'
    provider = DocumentHighlightProvider()
    # Position on '$x' in strings section (the declaration)
    highlights = provider.get_highlights(yara_src, _pos(2, 8))

    kinds = {h.kind for h in highlights}
    assert DocumentHighlightKind.Write in kinds
    assert DocumentHighlightKind.Read in kinds


# ---------------------------------------------------------------------------
# document_highlight.py line 41: kind == "rule" path
# ---------------------------------------------------------------------------


def test_document_highlight_rule_kind_uses_highlight_identifier() -> None:
    """Line 41: resolved.kind == 'rule' returns via _highlight_identifier.

    When the cursor is on a rule reference in the condition section and
    resolve_symbol returns kind='rule', the provider uses the rule-name
    highlight path.  Both the rule declaration and the reference site
    must appear in the result.
    """
    # Arrange: two rules where the second refers to the first
    yara_src = "rule base_rule { condition: true }\nrule caller { condition: base_rule }\n"
    provider = DocumentHighlightProvider()
    # Position on 'base_rule' in the condition of the second rule
    line1 = yara_src.splitlines()[1]
    ref_col = line1.index("base_rule")

    # Act
    highlights = provider.get_highlights(yara_src, _pos(1, ref_col))

    # Assert: at least two highlights — one Write (declaration) and one Read (reference)
    assert len(highlights) >= 2
    kinds = {h.kind for h in highlights}
    assert DocumentHighlightKind.Write in kinds
    assert DocumentHighlightKind.Read in kinds


# ---------------------------------------------------------------------------
# document_highlight.py line 66: _highlight_string_identifier fallback
# (records empty, falls through to highlight_string_identifier helper)
# ---------------------------------------------------------------------------


def test_document_highlight_string_identifier_fallback_on_broken_doc() -> None:
    """Line 66: when AST parse fails, string reference records are empty.

    In a document that cannot be fully parsed, find_string_reference_records
    returns an empty list and _highlight_string_identifier falls back to the
    text-scan implementation (line 66).
    """
    # Arrange: broken YARA — missing closing brace, strings still visible
    yara_src = 'rule broken {\n    strings:\n        $a = "abc"\n    condition:\n        $a\n'
    provider = DocumentHighlightProvider()

    # Act: position on '$a' in the condition
    highlights = provider.get_highlights(yara_src, _pos(4, 8))

    # Assert: at least one highlight returned (text scan fallback works)
    assert len(highlights) >= 1


# ---------------------------------------------------------------------------
# document_highlight.py line 72: _highlight_identifier fallback
# (records empty, falls through to highlight_identifier helper)
# ---------------------------------------------------------------------------


def test_document_highlight_identifier_fallback_when_no_rule_records() -> None:
    """Line 72: when identifier is not a rule name, rule reference records are empty.

    _get_rule_reference_records returns [] for an identifier that is not a
    declared rule, so _highlight_identifier falls back to the text-scan
    helper (line 72).
    """
    # Arrange: a document with 'alpha' used but NOT as a rule name anywhere
    yara_src = "alpha beta alpha\n"
    provider = DocumentHighlightProvider()

    # Act: position on 'alpha' — no rule named 'alpha', so records are empty
    highlights = provider.get_highlights(yara_src, _pos(0, 0))

    # Assert: text-scan fallback returns both occurrences
    start_cols = {h.range.start.character for h in highlights}
    assert 0 in start_cols
    assert 11 in start_cols


# ---------------------------------------------------------------------------
# document_highlight.py branch 34->51 with word starting with # in a comment
# ---------------------------------------------------------------------------


def test_document_highlight_hash_in_comment_takes_resolved_none_path() -> None:
    """Branch 34->51 with lines 52-54: '#a' inside a comment resolves to None.

    When the cursor is on '#a' inside a comment, position_is_in_non_code_segment
    makes the text fallback return None, so ctx.resolve_symbol returns None.
    Execution falls through the 'if resolved is not None' block to line 51,
    where '#a' matches the string-prefix check and gets rewritten to '$a'.
    """
    yara_src = (
        "rule r {\n"
        "    strings:\n"
        '        $a = "abc"\n'
        "    condition:\n"
        "        $a // #a is the string count\n"
        "}\n"
    )
    provider = DocumentHighlightProvider()
    line4 = yara_src.splitlines()[4]
    hash_col = line4.index("#a")

    # Act: cursor on '#a' inside the comment — resolve_symbol returns None
    highlights = provider.get_highlights(yara_src, _pos(4, hash_col))

    # Assert: the '$a' declaration is found via text scan (line 66 fallback)
    lines_hit = {h.range.start.line for h in highlights}
    assert 2 in lines_hit  # the $a declaration on line 2


def test_document_highlight_at_in_comment_takes_resolved_none_path() -> None:
    """Branch 34->51 with lines 52-54: '@b' inside a comment remapped to '$b'."""
    yara_src = (
        "rule r {\n"
        "    strings:\n"
        '        $b = "xyz"\n'
        "    condition:\n"
        "        $b // @b is the offset\n"
        "}\n"
    )
    provider = DocumentHighlightProvider()
    line4 = yara_src.splitlines()[4]
    at_col = line4.index("@b")

    highlights = provider.get_highlights(yara_src, _pos(4, at_col))

    lines_hit = {h.range.start.line for h in highlights}
    assert 2 in lines_hit  # $b declaration


# ---------------------------------------------------------------------------
# document_highlight.py line 85: _is_local_shadow string definition check
# ---------------------------------------------------------------------------


def test_document_highlight_is_local_shadow_string_definition_found() -> None:
    """Line 85: _is_local_shadow calls find_string_definition and gets a result.

    When resolve_symbol returns kind='identifier' for a YARA-X 'with $a = ...'
    local binding, _is_local_shadow checks find_string_definition for '$a'
    (word starts with '$') and finds the outer string declaration, returning True.
    The result is a single highlight covering only the local binding range.
    """
    yara_src = (
        "rule shadowed {\n"
        "    strings:\n"
        '        $a = "abc"\n'
        "    condition:\n"
        "        with $a = 1:\n"
        "            $a > 0\n"
        "}\n"
    )
    provider = DocumentHighlightProvider()
    # Position on '$a' in the 'with $a = 1:' declaration (line 4, after 'with ')
    line4 = yara_src.splitlines()[4]
    with_col = line4.index("$a")

    # Act
    highlights = provider.get_highlights(yara_src, _pos(4, with_col))

    # Assert: only the local binding is returned (single highlight)
    assert len(highlights) == 1
    assert highlights[0].range.start.line == 4
    assert highlights[0].kind == DocumentHighlightKind.Text


def test_document_highlight_is_local_shadow_string_definition_not_found() -> None:
    """Line 85: _is_local_shadow calls find_string_definition and gets None.

    When the identifier starts with '$' but no string with that name is declared
    in the document, find_string_definition returns None and _is_local_shadow
    returns False.  Execution falls through to the string-identifier highlight path.
    """
    # Arrange: '$undeclared' used in condition but NOT in a strings section
    yara_src = "rule no_strings {\n    condition:\n        $undeclared\n}\n"
    provider = DocumentHighlightProvider()
    line2 = yara_src.splitlines()[2]
    col = line2.index("$undeclared")

    # Act: resolve returns kind='identifier' (it can't resolve to a declaration)
    highlights = provider.get_highlights(yara_src, _pos(2, col))

    # Assert: does not error; returns whatever the fallback provides
    assert isinstance(highlights, list)


# ---------------------------------------------------------------------------
# document_highlight.py branch 52->54: word already starts with '$'
# so the rewrite (line 53) is skipped entirely.
# ---------------------------------------------------------------------------


def test_document_highlight_dollar_in_comment_skips_rewrite() -> None:
    """Branch 52->54: word starts with '$' so line 53 rewrite is skipped.

    When the cursor is on '$a' inside a comment, resolve_symbol returns None
    (non-code segment).  Line 51 fires (startswith('$')).  Line 52: word already
    starts with '$' so the `if not word.startswith('$')` check is False and
    execution jumps directly to line 54 without the rewrite on line 53.
    """
    # Arrange: '$a' appears in a comment; the outer declaration is reachable
    yara_src = (
        "rule r {\n"
        "    strings:\n"
        '        $a = "abc"\n'
        "    condition:\n"
        "        $a // we also use $a here conceptually\n"
        "}\n"
    )
    provider = DocumentHighlightProvider()
    line4 = yara_src.splitlines()[4]
    # Position on '$a' inside the comment (second occurrence on line 4)
    # The first '$a' at col 8 is a real reference; find the one inside '//'
    comment_start = line4.index("//")
    dollar_col = line4.index("$a", comment_start)

    # Act: cursor is on '$a' inside the comment — resolve_symbol returns None,
    # word starts with '$' so branch 52->54 is taken (no rewrite)
    highlights = provider.get_highlights(yara_src, _pos(4, dollar_col))

    # Assert: the '$a' string declaration and references are found
    assert len(highlights) >= 1


# ---------------------------------------------------------------------------
# document_highlight.py line 66: _highlight_string_identifier text-scan fallback
# when _get_string_reference_records returns an empty list
# ---------------------------------------------------------------------------


def test_document_highlight_string_identifier_fallback_when_no_records() -> None:
    """Line 66: _highlight_string_identifier falls back to text scan when records empty.

    When the searched string identifier does not appear in the document at all,
    find_string_reference_records returns an empty list, and _highlight_string_identifier
    falls through to the text-scan helper on line 66.
    """
    # Arrange: document with $a declared and used, but we search for $z (absent)
    yara_src = 'rule r { strings: $a = "abc" condition: $a }\n'
    provider = DocumentHighlightProvider()

    # Act: search for '$z' which is not in the document at all
    # _get_string_reference_records returns [] -> triggers line 66 fallback
    highlights = provider._highlight_string_identifier(yara_src, "$z")

    # Assert: text-scan finds nothing (no '$z' in document), returns empty list
    assert highlights == []
