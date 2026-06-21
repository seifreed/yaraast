# Copyright (c) 2026 Marc Rivero López
# Licensed under GPLv3. See LICENSE file for details.
# This test suite validates real code behavior without mocks or stubs.

"""Regression tests targeting uncovered lines in yaraast.yaral._parsing_events.

Each test exercises a specific branch, path, or helper that was not reached by
existing test files.  All tests parse through the real YaraLParser or invoke
mixin methods directly on a parser instance with a hand-constructed token list;
no mocks or stubs are used anywhere.
"""

from __future__ import annotations

from yaraast.lexer.tokens import TokenType as T
from yaraast.yaral._parsing_events import (
    _event_statement_token_text,
    _join_event_statement_tokens,
    _join_prefixed_event_statement,
    _token_value_is,
)
from yaraast.yaral.ast_nodes import (
    EventAssignment,
    EventStatement,
    EventVariable,
    FunctionCall,
    UDMFieldAccess,
)
from yaraast.yaral.lexer import YaraLToken
from yaraast.yaral.parser import YaraLParser
from yaraast.yaral.tokens import YaraLTokenType

# ---------------------------------------------------------------------------
# Helpers mirrored from the existing test file so this file is self-contained.
# ---------------------------------------------------------------------------


def _tok(
    token_type: T,
    value: str | int | float | None,
    line: int = 1,
    yaral_type: YaraLTokenType | None = None,
) -> YaraLToken:
    return YaraLToken(
        type=token_type,
        value=value,
        line=line,
        column=1,
        length=1,
        yaral_type=yaral_type,
    )


def _set_tokens(parser: YaraLParser, tokens: list[YaraLToken]) -> None:
    parser.tokens = tokens
    parser.current = 0


# ---------------------------------------------------------------------------
# Lines 79-80: unknown token in _parse_event_statement causes skip + None return
# ---------------------------------------------------------------------------


def test_parse_event_statement_unknown_token_returns_none_and_advances() -> None:
    """Line 79-80: the else-branch that skips unrecognised tokens returns None."""
    # Arrange: a COLON token is not LPAREN, not IDENTIFIER, not INTEGER/DOUBLE,
    # not EVENT_VAR, not STRING_IDENTIFIER, and _is_complex_event_pattern_start
    # returns False for it.  That means all guards fail and lines 79-80 execute.
    parser = YaraLParser("")
    _set_tokens(
        parser,
        [
            _tok(T.COLON, ":"),
            _tok(T.EOF, None, yaral_type=YaraLTokenType.EOF),
        ],
    )

    # Act
    result = parser._parse_event_statement()

    # Assert: COLON triggers the skip path; None is returned and the parser
    # advances past the skipped token.
    assert result is None
    assert parser.current == 1


# ---------------------------------------------------------------------------
# Lines 50->43 (loop continues when stmt is None) - covered via _parse_events_section
# ---------------------------------------------------------------------------


def test_parse_events_section_skips_none_statements_and_continues() -> None:
    """Line 50->43 branch: None from _parse_event_statement is not appended.

    The while-loop body calls _parse_event_statement; when None is returned the
    'if stmt' guard drops it silently and the loop iterates again.
    """
    # Arrange: a COLON token causes _parse_event_statement to return None (skip
    # path at lines 79-80), then a real event assignment follows.
    parser = YaraLParser("")
    _set_tokens(
        parser,
        [
            _tok(T.IDENTIFIER, "events"),
            _tok(T.COLON, ":"),
            # COLON is not a valid statement start → None returned by _parse_event_statement.
            _tok(T.COLON, ":", line=1),
            # A valid event assignment follows.
            _tok(T.STRING_IDENTIFIER, "$e", line=1, yaral_type=YaraLTokenType.EVENT_VAR),
            _tok(T.DOT, ".", line=1),
            _tok(T.IDENTIFIER, "field", line=1),
            _tok(T.EQ, "=", line=1),
            _tok(T.STRING, "value", line=1),
            _tok(T.EOF, None, line=1, yaral_type=YaraLTokenType.EOF),
        ],
    )

    # Act
    section = parser._parse_events_section()

    # Assert: the skipped COLON is not in results; one real statement was collected.
    assert len(section.statements) == 1
    assert isinstance(section.statements[0], EventAssignment)


# ---------------------------------------------------------------------------
# Lines 59, 64->68: _parse_event_statement dispatches to _parse_boolean_expression
# when it sees LPAREN
# ---------------------------------------------------------------------------


def test_parse_event_statement_lparen_dispatches_to_boolean_expression() -> None:
    """Lines 59, 64->68: LPAREN at statement start routes to _parse_boolean_expression."""
    # Arrange
    parser = YaraLParser("")
    _set_tokens(
        parser,
        [
            _tok(T.LPAREN, "("),
            _tok(T.STRING_IDENTIFIER, "$e", yaral_type=YaraLTokenType.EVENT_VAR),
            _tok(T.IDENTIFIER, "or"),
            _tok(T.STRING_IDENTIFIER, "$f", yaral_type=YaraLTokenType.EVENT_VAR),
            _tok(T.RPAREN, ")"),
            _tok(T.EOF, None, yaral_type=YaraLTokenType.EOF),
        ],
    )

    # Act
    stmt = parser._parse_event_statement()

    # Assert: result is an EventStatement produced by _parse_boolean_expression.
    assert isinstance(stmt, EventStatement)
    assert stmt.text is not None
    assert "$e" in stmt.text


# ---------------------------------------------------------------------------
# Line 72: _is_complex_event_pattern_start True → _parse_complex_event_pattern_statement
# ---------------------------------------------------------------------------


def test_parse_event_statement_dispatches_to_complex_pattern_when_any_keyword() -> None:
    """Line 72: 'any' keyword triggers _parse_complex_event_pattern_statement."""
    # Arrange: 'any' starts a complex event pattern.
    parser = YaraLParser("")
    _set_tokens(
        parser,
        [
            _tok(T.IDENTIFIER, "any"),
            _tok(T.IDENTIFIER, "of"),
            _tok(T.LPAREN, "("),
            _tok(T.STRING_IDENTIFIER, "$e1", yaral_type=YaraLTokenType.EVENT_VAR),
            _tok(T.RPAREN, ")"),
            _tok(T.EOF, None, yaral_type=YaraLTokenType.EOF),
        ],
    )

    # Act
    stmt = parser._parse_event_statement()

    # Assert: EventStatement produced; text contains 'any'.
    assert isinstance(stmt, EventStatement)
    assert stmt.text is not None
    assert "any" in stmt.text


def test_parse_event_statement_dispatches_to_complex_pattern_when_all_keyword() -> None:
    """Line 72: 'all' keyword also triggers _parse_complex_event_pattern_statement."""
    parser = YaraLParser("")
    _set_tokens(
        parser,
        [
            _tok(T.IDENTIFIER, "all"),
            _tok(T.IDENTIFIER, "of"),
            _tok(T.IDENTIFIER, "them"),
            _tok(T.EOF, None, yaral_type=YaraLTokenType.EOF),
        ],
    )

    stmt = parser._parse_event_statement()

    assert isinstance(stmt, EventStatement)
    assert stmt.text is not None
    assert "all" in stmt.text


# ---------------------------------------------------------------------------
# Line 130: _try_parse_function_call_start returns None (non-module identifier)
# ---------------------------------------------------------------------------


def test_try_parse_function_call_start_returns_none_for_non_module_identifier() -> None:
    """Line 130: identifier not in _RAW_EVENT_MODULES returns None."""
    # Arrange: 'foo' is not in {"arrays","math","net","re","strings"}.
    parser = YaraLParser("")
    _set_tokens(
        parser,
        [
            _tok(T.IDENTIFIER, "foo"),
            _tok(T.LPAREN, "("),
            _tok(T.RPAREN, ")"),
            _tok(T.EOF, None, yaral_type=YaraLTokenType.EOF),
        ],
    )

    # Act
    result = parser._try_parse_function_call_start()

    # Assert: None is returned and no tokens were consumed.
    assert result is None
    assert parser.current == 0


# ---------------------------------------------------------------------------
# Line 112-113: nocase modifier appended after event assignment value
# ---------------------------------------------------------------------------


def test_parse_event_statement_appends_nocase_modifier() -> None:
    """Lines 112-113: 'nocase' keyword after value is added to modifiers."""
    parser = YaraLParser("")
    _set_tokens(
        parser,
        [
            _tok(T.STRING_IDENTIFIER, "$e", yaral_type=YaraLTokenType.EVENT_VAR),
            _tok(T.DOT, "."),
            _tok(T.IDENTIFIER, "principal"),
            _tok(T.DOT, "."),
            _tok(T.IDENTIFIER, "hostname"),
            _tok(T.EQ, "="),
            _tok(T.STRING, "example.com"),
            _tok(T.IDENTIFIER, "nocase"),
            _tok(T.EOF, None, yaral_type=YaraLTokenType.EOF),
        ],
    )

    stmt = parser._parse_event_statement()

    assert isinstance(stmt, EventAssignment)
    assert stmt.modifiers == ["nocase"]


# ---------------------------------------------------------------------------
# Line 152: _token_value_is(token, "in") True branch in _is_event_var_comparison_operator_at
# ---------------------------------------------------------------------------


def test_is_event_var_comparison_operator_at_detects_in_keyword_by_value() -> None:
    """Line 152: token with value 'in' (identifier type) is detected as comparison."""
    # Arrange: use an IDENTIFIER token whose value is "in" — this covers the
    # _token_value_is(token, "in") True path at line 151-152.
    parser = YaraLParser("")
    _set_tokens(
        parser,
        [
            _tok(T.IDENTIFIER, "in"),
            _tok(T.EOF, None, yaral_type=YaraLTokenType.EOF),
        ],
    )

    result = parser._is_event_var_comparison_operator_at(0)

    assert result is True


def test_is_event_var_comparison_operator_at_detects_matches_keyword_by_value() -> None:
    """Line 152: token with value 'matches' (identifier type) is detected as comparison."""
    parser = YaraLParser("")
    _set_tokens(
        parser,
        [
            _tok(T.IDENTIFIER, "matches"),
            _tok(T.EOF, None, yaral_type=YaraLTokenType.EOF),
        ],
    )

    result = parser._is_event_var_comparison_operator_at(0)

    assert result is True


# ---------------------------------------------------------------------------
# Line 139: _check_comparison_or_in delegates to _is_event_var_comparison_operator_at(0)
# ---------------------------------------------------------------------------


def test_check_comparison_or_in_returns_true_for_gt_token() -> None:
    """Line 139: _check_comparison_or_in passes through the GT token type."""
    parser = YaraLParser("")
    _set_tokens(
        parser,
        [
            _tok(T.GT, ">"),
            _tok(T.EOF, None, yaral_type=YaraLTokenType.EOF),
        ],
    )

    assert parser._check_comparison_or_in() is True


def test_check_comparison_or_in_returns_false_for_unrelated_token() -> None:
    """Line 139: _check_comparison_or_in returns False for STRING token."""
    parser = YaraLParser("")
    _set_tokens(
        parser,
        [
            _tok(T.STRING, "hello"),
            _tok(T.EOF, None, yaral_type=YaraLTokenType.EOF),
        ],
    )

    assert parser._check_comparison_or_in() is False


# ---------------------------------------------------------------------------
# Line 197: _looks_like_new_statement detects EQ at offset 1
# ---------------------------------------------------------------------------


def test_looks_like_new_statement_detects_eq_at_next_position() -> None:
    """Line 197: next token is EQ → _looks_like_new_statement returns True."""
    parser = YaraLParser("")
    # Tokens at positions 0 and 1: position 0 is current, position 1 is next.
    _set_tokens(
        parser,
        [
            _tok(T.STRING_IDENTIFIER, "$e", yaral_type=YaraLTokenType.EVENT_VAR),
            _tok(T.EQ, "="),
            _tok(T.EOF, None, yaral_type=YaraLTokenType.EOF),
        ],
    )

    assert parser._looks_like_new_statement() is True


def test_looks_like_new_statement_detects_dot_at_next_position() -> None:
    """Line 198: next token is DOT → _looks_like_new_statement returns True."""
    parser = YaraLParser("")
    _set_tokens(
        parser,
        [
            _tok(T.STRING_IDENTIFIER, "$e", yaral_type=YaraLTokenType.EVENT_VAR),
            _tok(T.DOT, "."),
            _tok(T.EOF, None, yaral_type=YaraLTokenType.EOF),
        ],
    )

    assert parser._looks_like_new_statement() is True


def test_looks_like_new_statement_returns_false_when_no_tokens_ahead() -> None:
    """Line 196-197: None from _event_value_token_ahead(1) → return False."""
    parser = YaraLParser("")
    _set_tokens(
        parser,
        [
            _tok(T.EOF, None, yaral_type=YaraLTokenType.EOF),
        ],
    )

    # current=0, offset 1 is beyond bounds.
    assert parser._looks_like_new_statement() is False


# ---------------------------------------------------------------------------
# Lines 210->216: _parse_event_assignment with module function on RHS
# ---------------------------------------------------------------------------


def test_parse_event_assignment_rhs_module_function_call_via_full_rule() -> None:
    """Lines 210->216: $var = re.regex(...) routes to _prefix_event_statement path."""
    ast = YaraLParser("""
        rule assignment_rhs_func {
          events:
            $var = re.regex($e.principal.hostname, `^admin`)
          condition:
            $e
        }
        """).parse()

    events = ast.rules[0].events
    assert events is not None
    assert len(events.statements) == 1
    stmt = events.statements[0]
    assert isinstance(stmt, EventStatement)
    assert stmt.text is not None
    assert "re.regex" in stmt.text
    assert "$var" in stmt.text


# ---------------------------------------------------------------------------
# Line 227: _parse_event_assignment RHS is not event-var and not module function
# ---------------------------------------------------------------------------


def test_parse_event_assignment_rhs_unsupported_falls_back_to_collect_tokens() -> None:
    """Line 227: RHS is not an event-var or module function; collect tokens fallback."""
    # Arrange: $var = "some_string" — RHS is a STRING, not EVENT_VAR or module.
    parser = YaraLParser("")
    _set_tokens(
        parser,
        [
            _tok(T.STRING_IDENTIFIER, "$var", yaral_type=YaraLTokenType.EVENT_VAR),
            _tok(T.EQ, "="),
            _tok(T.STRING, "some_string"),
            _tok(T.EOF, None, yaral_type=YaraLTokenType.EOF),
        ],
    )

    stmt = parser._parse_event_statement()

    assert isinstance(stmt, EventStatement)
    assert stmt.text is not None
    assert "$var" in stmt.text


# ---------------------------------------------------------------------------
# Line 248: _collect_rhs_expression_tokens stops on _is_complex_event_pattern_start
# ---------------------------------------------------------------------------


def test_collect_rhs_expression_tokens_stops_on_complex_pattern_start() -> None:
    """Line 248: 'any' on a new line stops RHS collection immediately."""
    parser = YaraLParser("")
    # current stays at 0; start_line is line 1.
    # Token at line 2 is 'any' which triggers _is_complex_event_pattern_start.
    _set_tokens(
        parser,
        [
            _tok(T.STRING_IDENTIFIER, "$e", line=1, yaral_type=YaraLTokenType.EVENT_VAR),
            _tok(T.DOT, ".", line=1),
            _tok(T.IDENTIFIER, "field", line=1),
            _tok(T.IDENTIFIER, "any", line=2),
            _tok(T.IDENTIFIER, "of", line=2),
            _tok(T.EOF, None, line=2, yaral_type=YaraLTokenType.EOF),
        ],
    )
    # Peek returns first token; start_line = 1.
    tokens = parser._collect_rhs_expression_tokens()

    # 'any' at line 2 terminates collection; only $e, '.', 'field' are consumed.
    assert len(tokens) == 3
    assert parser._peek().value == "any"


# ---------------------------------------------------------------------------
# Lines 265, 268-271: _is_complex_event_pattern_start branches
# ---------------------------------------------------------------------------


def test_is_complex_event_pattern_start_true_for_any_keyword() -> None:
    """Line 265: 'any' identifier value returns True immediately."""
    parser = YaraLParser("")
    _set_tokens(
        parser,
        [
            _tok(T.IDENTIFIER, "any"),
            _tok(T.EOF, None, yaral_type=YaraLTokenType.EOF),
        ],
    )
    assert parser._is_complex_event_pattern_start() is True


def test_is_complex_event_pattern_start_true_for_all_keyword() -> None:
    """Line 265: 'all' identifier value returns True."""
    parser = YaraLParser("")
    _set_tokens(
        parser,
        [
            _tok(T.IDENTIFIER, "all"),
            _tok(T.EOF, None, yaral_type=YaraLTokenType.EOF),
        ],
    )
    assert parser._is_complex_event_pattern_start() is True


def test_is_complex_event_pattern_start_false_when_non_identifier_token() -> None:
    """Line 267: non-IDENTIFIER token returns False at the early guard."""
    parser = YaraLParser("")
    _set_tokens(
        parser,
        [
            _tok(T.STRING, "hello"),
            _tok(T.EOF, None, yaral_type=YaraLTokenType.EOF),
        ],
    )
    assert parser._is_complex_event_pattern_start() is False


def test_is_complex_event_pattern_start_false_when_no_next_token() -> None:
    """Lines 268-270: next_pos >= len(tokens) causes False return."""
    parser = YaraLParser("")
    # Only one token; next_pos = current(0) + 1 = 1 >= len(tokens)(1).
    _set_tokens(
        parser,
        [
            _tok(T.IDENTIFIER, "followed"),
        ],
    )
    assert parser._is_complex_event_pattern_start() is False


def test_is_complex_event_pattern_start_true_for_identifier_followed_by_followed() -> None:
    """Line 271: identifier followed by 'followed' returns True."""
    parser = YaraLParser("")
    _set_tokens(
        parser,
        [
            _tok(T.IDENTIFIER, "evt"),
            _tok(T.IDENTIFIER, "followed"),
            _tok(T.EOF, None, yaral_type=YaraLTokenType.EOF),
        ],
    )
    assert parser._is_complex_event_pattern_start() is True


def test_is_complex_event_pattern_start_true_for_identifier_followed_by_before() -> None:
    """Line 271: 'before' as next-token value returns True."""
    parser = YaraLParser("")
    _set_tokens(
        parser,
        [
            _tok(T.IDENTIFIER, "evt"),
            _tok(T.IDENTIFIER, "before"),
            _tok(T.EOF, None, yaral_type=YaraLTokenType.EOF),
        ],
    )
    assert parser._is_complex_event_pattern_start() is True


def test_is_complex_event_pattern_start_true_for_identifier_followed_by_after() -> None:
    """Line 271: 'after' as next-token value returns True."""
    parser = YaraLParser("")
    _set_tokens(
        parser,
        [
            _tok(T.IDENTIFIER, "evt"),
            _tok(T.IDENTIFIER, "after"),
            _tok(T.EOF, None, yaral_type=YaraLTokenType.EOF),
        ],
    )
    assert parser._is_complex_event_pattern_start() is True


def test_is_complex_event_pattern_start_false_for_unrelated_next_token() -> None:
    """Line 271: next token value is 'foo' → False."""
    parser = YaraLParser("")
    _set_tokens(
        parser,
        [
            _tok(T.IDENTIFIER, "evt"),
            _tok(T.IDENTIFIER, "foo"),
            _tok(T.EOF, None, yaral_type=YaraLTokenType.EOF),
        ],
    )
    assert parser._is_complex_event_pattern_start() is False


# ---------------------------------------------------------------------------
# Lines 274-285: _parse_complex_event_pattern_statement full body
# ---------------------------------------------------------------------------


def test_parse_complex_event_pattern_statement_consumes_all_on_same_line() -> None:
    """Lines 274-285: all-of pattern consumed until EOF."""
    parser = YaraLParser("")
    _set_tokens(
        parser,
        [
            _tok(T.IDENTIFIER, "all"),
            _tok(T.IDENTIFIER, "of"),
            _tok(T.IDENTIFIER, "them"),
            _tok(T.EOF, None, yaral_type=YaraLTokenType.EOF),
        ],
    )

    stmt = parser._parse_complex_event_pattern_statement()

    assert isinstance(stmt, EventStatement)
    assert stmt.text is not None
    assert "all" in stmt.text
    assert "of" in stmt.text


def test_parse_complex_event_pattern_statement_stops_at_section_keyword() -> None:
    """Line 280: section keyword terminates consumption."""
    parser = YaraLParser("")
    _set_tokens(
        parser,
        [
            _tok(T.IDENTIFIER, "any"),
            _tok(T.IDENTIFIER, "of"),
            _tok(T.IDENTIFIER, "condition", line=2),
            _tok(T.COLON, ":", line=2),
            _tok(T.EOF, None, yaral_type=YaraLTokenType.EOF),
        ],
    )

    stmt = parser._parse_complex_event_pattern_statement()

    assert isinstance(stmt, EventStatement)
    assert parser._peek().value == "condition"


def test_parse_complex_event_pattern_statement_stops_on_new_event_statement_start() -> None:
    """Line 282: new event variable on a later line terminates consumption."""
    parser = YaraLParser("")
    _set_tokens(
        parser,
        [
            _tok(T.IDENTIFIER, "any", line=1),
            _tok(T.IDENTIFIER, "of", line=1),
            _tok(T.IDENTIFIER, "them", line=1),
            _tok(T.STRING_IDENTIFIER, "$e", line=2, yaral_type=YaraLTokenType.EVENT_VAR),
            _tok(T.DOT, ".", line=2),
            _tok(T.IDENTIFIER, "field", line=2),
            _tok(T.EOF, None, line=2, yaral_type=YaraLTokenType.EOF),
        ],
    )

    stmt = parser._parse_complex_event_pattern_statement()

    assert isinstance(stmt, EventStatement)
    # Parser should have stopped before the $e token.
    assert parser._peek().value == "$e"


# ---------------------------------------------------------------------------
# Lines 288-301: _is_event_statement_start full body
# ---------------------------------------------------------------------------


def test_is_event_statement_start_true_for_event_var() -> None:
    """Line 289: EVENT_VAR yaral_type → True."""
    parser = YaraLParser("")
    _set_tokens(
        parser,
        [
            _tok(T.STRING_IDENTIFIER, "$e", yaral_type=YaraLTokenType.EVENT_VAR),
            _tok(T.EOF, None, yaral_type=YaraLTokenType.EOF),
        ],
    )
    assert parser._is_event_statement_start() is True


def test_is_event_statement_start_true_for_string_identifier() -> None:
    """Line 290: STRING_IDENTIFIER → True."""
    parser = YaraLParser("")
    _set_tokens(
        parser,
        [
            _tok(T.STRING_IDENTIFIER, "$x"),
            _tok(T.EOF, None, yaral_type=YaraLTokenType.EOF),
        ],
    )
    assert parser._is_event_statement_start() is True


def test_is_event_statement_start_true_for_integer() -> None:
    """Line 291: INTEGER → True."""
    parser = YaraLParser("")
    _set_tokens(
        parser,
        [
            _tok(T.INTEGER, "42"),
            _tok(T.EOF, None, yaral_type=YaraLTokenType.EOF),
        ],
    )
    assert parser._is_event_statement_start() is True


def test_is_event_statement_start_true_for_double() -> None:
    """Line 292: DOUBLE → True."""
    parser = YaraLParser("")
    _set_tokens(
        parser,
        [
            _tok(T.DOUBLE, 1.5),
            _tok(T.EOF, None, yaral_type=YaraLTokenType.EOF),
        ],
    )
    assert parser._is_event_statement_start() is True


def test_is_event_statement_start_true_for_lparen() -> None:
    """Line 293: LPAREN → True."""
    parser = YaraLParser("")
    _set_tokens(
        parser,
        [
            _tok(T.LPAREN, "("),
            _tok(T.EOF, None, yaral_type=YaraLTokenType.EOF),
        ],
    )
    assert parser._is_event_statement_start() is True


def test_is_event_statement_start_true_for_complex_pattern_keyword() -> None:
    """Line 294: _is_complex_event_pattern_start() True → True."""
    parser = YaraLParser("")
    _set_tokens(
        parser,
        [
            _tok(T.IDENTIFIER, "all"),
            _tok(T.EOF, None, yaral_type=YaraLTokenType.EOF),
        ],
    )
    assert parser._is_event_statement_start() is True


def test_is_event_statement_start_false_for_non_identifier_non_event_token() -> None:
    """Line 298-299: non-IDENTIFIER non-special → False."""
    parser = YaraLParser("")
    _set_tokens(
        parser,
        [
            _tok(T.STRING, "hello"),
            _tok(T.EOF, None, yaral_type=YaraLTokenType.EOF),
        ],
    )
    assert parser._is_event_statement_start() is False


def test_is_event_statement_start_true_for_raw_event_module_identifier() -> None:
    """Lines 300-302: identifier is a module name → True."""
    parser = YaraLParser("")
    _set_tokens(
        parser,
        [
            _tok(T.IDENTIFIER, "re"),
            _tok(T.EOF, None, yaral_type=YaraLTokenType.EOF),
        ],
    )
    assert parser._is_event_statement_start() is True


def test_is_event_statement_start_true_for_compound_module_identifier() -> None:
    """Lines 301-302: compound identifier like 're.regex' → True."""
    parser = YaraLParser("")
    _set_tokens(
        parser,
        [
            _tok(T.IDENTIFIER, "re.regex"),
            _tok(T.EOF, None, yaral_type=YaraLTokenType.EOF),
        ],
    )
    assert parser._is_event_statement_start() is True


def test_is_event_statement_start_false_for_unrelated_identifier() -> None:
    """Line 301: non-module identifier → False."""
    parser = YaraLParser("")
    _set_tokens(
        parser,
        [
            _tok(T.IDENTIFIER, "foo"),
            _tok(T.EOF, None, yaral_type=YaraLTokenType.EOF),
        ],
    )
    assert parser._is_event_statement_start() is False


# ---------------------------------------------------------------------------
# Lines 319->314, 325->328, 329->314, 335->338: _parse_field_path bracket paths
# ---------------------------------------------------------------------------


def test_parse_field_path_dot_bracket_string_key() -> None:
    """Lines 319->314, 322-324: .fields["key"] form."""
    parser = YaraLParser("")
    _set_tokens(
        parser,
        [
            _tok(T.IDENTIFIER, "metadata"),
            _tok(T.DOT, "."),
            _tok(T.LBRACKET, "["),
            _tok(T.STRING, "event_type"),
            _tok(T.RBRACKET, "]"),
            _tok(T.EOF, None, yaral_type=YaraLTokenType.EOF),
        ],
    )

    path = parser._parse_field_path()

    assert path.parts == ["metadata", '["event_type"]']


def test_parse_field_path_dot_bracket_integer_index() -> None:
    """Lines 325-327: .fields[0] form (integer index after dot-bracket)."""
    parser = YaraLParser("")
    _set_tokens(
        parser,
        [
            _tok(T.IDENTIFIER, "fields"),
            _tok(T.DOT, "."),
            _tok(T.LBRACKET, "["),
            _tok(T.INTEGER, "0"),
            _tok(T.RBRACKET, "]"),
            _tok(T.EOF, None, yaral_type=YaraLTokenType.EOF),
        ],
    )

    path = parser._parse_field_path()

    assert path.parts == ["fields", "[0]"]


def test_parse_field_path_direct_bracket_string_key() -> None:
    """Lines 329->314, 332-334: fields["key"] form (bracket directly after identifier)."""
    parser = YaraLParser("")
    _set_tokens(
        parser,
        [
            _tok(T.IDENTIFIER, "labels"),
            _tok(T.LBRACKET, "["),
            _tok(T.STRING, "env"),
            _tok(T.RBRACKET, "]"),
            _tok(T.EOF, None, yaral_type=YaraLTokenType.EOF),
        ],
    )

    path = parser._parse_field_path()

    assert path.parts == ["labels", '["env"]']


def test_parse_field_path_direct_bracket_integer_index() -> None:
    """Lines 335-337: fields[0] form."""
    parser = YaraLParser("")
    _set_tokens(
        parser,
        [
            _tok(T.IDENTIFIER, "items"),
            _tok(T.LBRACKET, "["),
            _tok(T.INTEGER, "1"),
            _tok(T.RBRACKET, "]"),
            _tok(T.EOF, None, yaral_type=YaraLTokenType.EOF),
        ],
    )

    path = parser._parse_field_path()

    assert path.parts == ["items", "[1]"]


# ---------------------------------------------------------------------------
# Lines 362-363: _parse_event_operator MATCHES token type
# ---------------------------------------------------------------------------


def test_parse_event_operator_matches_token_type() -> None:
    """Lines 362-363: MATCHES token type returns its string value."""
    parser = YaraLParser("")
    _set_tokens(
        parser,
        [
            _tok(T.MATCHES, "matches"),
            _tok(T.EOF, None, yaral_type=YaraLTokenType.EOF),
        ],
    )

    op = parser._parse_event_operator()

    assert op == "matches"


# ---------------------------------------------------------------------------
# Lines 365-366: _parse_event_operator 'in' keyword (by identifier value)
# ---------------------------------------------------------------------------


def test_parse_event_operator_in_keyword_by_value() -> None:
    """Lines 365-366: IDENTIFIER with value 'in' returns 'in'."""
    parser = YaraLParser("")
    _set_tokens(
        parser,
        [
            _tok(T.IDENTIFIER, "in"),
            _tok(T.EOF, None, yaral_type=YaraLTokenType.EOF),
        ],
    )

    op = parser._parse_event_operator()

    assert op == "in"


# ---------------------------------------------------------------------------
# Lines 369-371: _parse_event_operator 'not matches' returns '!~'
# ---------------------------------------------------------------------------


def test_parse_event_operator_not_matches_keyword() -> None:
    """Lines 369-371: 'not' + 'matches' identifier returns '!~'."""
    parser = YaraLParser("")
    _set_tokens(
        parser,
        [
            _tok(T.IDENTIFIER, "not"),
            _tok(T.IDENTIFIER, "matches"),
            _tok(T.EOF, None, yaral_type=YaraLTokenType.EOF),
        ],
    )

    op = parser._parse_event_operator()

    assert op == "!~"


# ---------------------------------------------------------------------------
# Line 404: _parse_event_value returns bare EventVariable (no dot follows)
# ---------------------------------------------------------------------------


def test_parse_event_value_returns_bare_event_variable_without_dot() -> None:
    """Line 404: EVENT_VAR not followed by DOT returns EventVariable directly."""
    parser = YaraLParser("")
    _set_tokens(
        parser,
        [
            _tok(T.STRING_IDENTIFIER, "$e", yaral_type=YaraLTokenType.EVENT_VAR),
            _tok(T.EOF, None, yaral_type=YaraLTokenType.EOF),
        ],
    )

    value = parser._parse_event_value()

    assert isinstance(value, EventVariable)
    assert value.name == "$e"


def test_parse_event_value_returns_udm_field_access_when_dot_follows_event_var() -> None:
    """Lines 401-403: EVENT_VAR followed by DOT returns UDMFieldAccess."""
    parser = YaraLParser("")
    _set_tokens(
        parser,
        [
            _tok(T.STRING_IDENTIFIER, "$e", yaral_type=YaraLTokenType.EVENT_VAR),
            _tok(T.DOT, "."),
            _tok(T.IDENTIFIER, "principal"),
            _tok(T.DOT, "."),
            _tok(T.IDENTIFIER, "ip"),
            _tok(T.EOF, None, yaral_type=YaraLTokenType.EOF),
        ],
    )

    value = parser._parse_event_value()

    assert isinstance(value, UDMFieldAccess)
    assert value.event is not None
    assert value.event.name == "$e"
    assert value.field.parts == ["principal", "ip"]


# ---------------------------------------------------------------------------
# Line 426: _is_event_function_call_value_start returns False when next_token is None
# ---------------------------------------------------------------------------


def test_is_event_function_call_value_start_false_when_no_next_token() -> None:
    """Line 426: _event_value_token_ahead(1) is None → returns False."""
    parser = YaraLParser("")
    # Only one token at current position; offset 1 is beyond the list.
    _set_tokens(
        parser,
        [
            _tok(T.IDENTIFIER, "foo"),
        ],
    )
    assert parser._is_event_function_call_value_start() is False


# ---------------------------------------------------------------------------
# Lines 431-433: _is_event_function_call_value_start dot then function then LPAREN
# ---------------------------------------------------------------------------


def test_is_event_function_call_value_start_true_for_dotted_function() -> None:
    """Lines 431-433: module.func( pattern detected — returns True."""
    parser = YaraLParser("")
    # Tokens: identifier, dot, identifier, lparen
    _set_tokens(
        parser,
        [
            _tok(T.IDENTIFIER, "net"),
            _tok(T.DOT, "."),
            _tok(T.IDENTIFIER, "ip_in_range_cidr"),
            _tok(T.LPAREN, "("),
            _tok(T.EOF, None, yaral_type=YaraLTokenType.EOF),
        ],
    )

    assert parser._is_event_function_call_value_start() is True


def test_is_event_function_call_value_start_false_when_dot_but_no_lparen_after_func() -> None:
    """Lines 429-433: dot present but token after identifier is not LPAREN → False."""
    parser = YaraLParser("")
    _set_tokens(
        parser,
        [
            _tok(T.IDENTIFIER, "net"),
            _tok(T.DOT, "."),
            _tok(T.IDENTIFIER, "field"),
            _tok(T.DOT, "."),  # not LPAREN
            _tok(T.EOF, None, yaral_type=YaraLTokenType.EOF),
        ],
    )

    assert parser._is_event_function_call_value_start() is False


# ---------------------------------------------------------------------------
# Line 443: _event_value_token_ahead returns None when position is out of bounds
# ---------------------------------------------------------------------------


def test_event_value_token_ahead_returns_none_beyond_bounds() -> None:
    """Line 443: offset placing position past end of tokens list returns None."""
    parser = YaraLParser("")
    _set_tokens(
        parser,
        [
            _tok(T.IDENTIFIER, "only"),
            _tok(T.EOF, None, yaral_type=YaraLTokenType.EOF),
        ],
    )
    # current=0, offset=5 → position=5 >= len(tokens)=2 → None.
    result = parser._event_value_token_ahead(5)
    assert result is None


# ---------------------------------------------------------------------------
# Lines 449-451: _parse_event_function_call_value with dotted function name
# ---------------------------------------------------------------------------


def test_parse_event_function_call_value_dotted_name() -> None:
    """Lines 449-451: module.function(args) builds compound function name."""
    parser = YaraLParser("")
    _set_tokens(
        parser,
        [
            _tok(T.IDENTIFIER, "net"),
            _tok(T.DOT, "."),
            _tok(T.IDENTIFIER, "ip_in_range_cidr"),
            _tok(T.LPAREN, "("),
            _tok(T.STRING_IDENTIFIER, "$e", yaral_type=YaraLTokenType.EVENT_VAR),
            _tok(T.DOT, "."),
            _tok(T.IDENTIFIER, "principal"),
            _tok(T.DOT, "."),
            _tok(T.IDENTIFIER, "ip"),
            _tok(T.COMMA, ","),
            _tok(T.STRING, "10.0.0.0/8"),
            _tok(T.RPAREN, ")"),
            _tok(T.EOF, None, yaral_type=YaraLTokenType.EOF),
        ],
    )

    call = parser._parse_event_function_call_value()

    assert isinstance(call, FunctionCall)
    assert call.function == "net.ip_in_range_cidr"
    assert len(call.arguments) == 2


# ---------------------------------------------------------------------------
# Lines 455->461: _parse_event_function_call_value with zero arguments
# ---------------------------------------------------------------------------


def test_parse_event_function_call_value_no_arguments() -> None:
    """Lines 455->461: function() with empty argument list."""
    parser = YaraLParser("")
    _set_tokens(
        parser,
        [
            _tok(T.IDENTIFIER, "math"),
            _tok(T.DOT, "."),
            _tok(T.IDENTIFIER, "random"),
            _tok(T.LPAREN, "("),
            _tok(T.RPAREN, ")"),
            _tok(T.EOF, None, yaral_type=YaraLTokenType.EOF),
        ],
    )

    call = parser._parse_event_function_call_value()

    assert isinstance(call, FunctionCall)
    assert call.function == "math.random"
    assert call.arguments == []


# ---------------------------------------------------------------------------
# Lines 502->508: _parse_function_call_statement EQ with STRING_IDENTIFIER on RHS
# ---------------------------------------------------------------------------


def test_parse_function_call_statement_eq_with_string_identifier_rhs() -> None:
    """Lines 502-505: function(...) = $var (STRING_IDENTIFIER, not EVENT_VAR)."""
    parser = YaraLParser("")
    _set_tokens(
        parser,
        [
            _tok(T.IDENTIFIER, "re.regex"),
            _tok(T.LPAREN, "("),
            _tok(T.STRING_IDENTIFIER, "$e", yaral_type=YaraLTokenType.EVENT_VAR),
            _tok(T.RPAREN, ")"),
            _tok(T.EQ, "="),
            # STRING_IDENTIFIER without EVENT_VAR yaral_type — covers the second
            # branch of the OR at line 502-503.
            _tok(T.STRING_IDENTIFIER, "$cap"),
            _tok(T.EOF, None, yaral_type=YaraLTokenType.EOF),
        ],
    )

    stmt = parser._parse_function_call_statement()

    assert isinstance(stmt, EventStatement)
    assert "$cap" in (stmt.text or "")


# ---------------------------------------------------------------------------
# Line 541: _join_event_statement_tokens skips tokens whose text is empty
# ---------------------------------------------------------------------------


def test_join_event_statement_tokens_skips_empty_piece() -> None:
    """Line 541: token with None value produces empty piece; it is skipped."""
    # Arrange: one token with value=None (produces "") and one with real value.
    tok_none = _tok(T.STRING, None)
    tok_real = _tok(T.IDENTIFIER, "hello")

    result = _join_event_statement_tokens([tok_none, tok_real])

    assert result == "hello"


# ---------------------------------------------------------------------------
# Line 564: _join_prefixed_event_statement with empty RHS returns prefix alone
# ---------------------------------------------------------------------------


def test_join_prefixed_event_statement_returns_prefix_when_rhs_empty() -> None:
    """Line 564: empty token list produces empty rhs, so prefix is returned."""
    result = _join_prefixed_event_statement("$var =", [])

    assert result == "$var ="


def test_join_prefixed_event_statement_returns_combined_when_rhs_non_empty() -> None:
    """Line 562-563: non-empty RHS is combined with prefix."""
    tok = _tok(T.IDENTIFIER, "value")
    result = _join_prefixed_event_statement("$var =", [tok])

    assert result == "$var = value"


# ---------------------------------------------------------------------------
# Line 570: _event_statement_token_text returns "" for None value
# ---------------------------------------------------------------------------


def test_event_statement_token_text_returns_empty_for_none_value() -> None:
    """Line 570: token.value is None → returns ''."""
    tok = _tok(T.IDENTIFIER, None)
    result = _event_statement_token_text(tok)
    assert result == ""


def test_event_statement_token_text_returns_quoted_string_for_string_token() -> None:
    """Line 572: STRING token type wraps value in escaped quotes."""
    tok = _tok(T.STRING, "hello world")
    result = _event_statement_token_text(tok)
    assert result == '"hello world"'


def test_event_statement_token_text_returns_str_for_other_token() -> None:
    """Line 573: non-STRING, non-None token returns str(value)."""
    tok = _tok(T.IDENTIFIER, "re.regex")
    result = _event_statement_token_text(tok)
    assert result == "re.regex"


# ---------------------------------------------------------------------------
# _token_value_is edge cases
# ---------------------------------------------------------------------------


def test_token_value_is_case_insensitive() -> None:
    """_token_value_is lowercases the token value before comparing."""
    tok = _tok(T.IDENTIFIER, "IN")
    assert _token_value_is(tok, "in") is True


def test_token_value_is_returns_false_for_non_string_value() -> None:
    """_token_value_is returns False when value is not a string."""
    tok = _tok(T.INTEGER, 42)
    assert _token_value_is(tok, "42") is False


# ---------------------------------------------------------------------------
# Line 139: _is_event_var_comparison_operator_at returns False when token is None
# ---------------------------------------------------------------------------


def test_is_event_var_comparison_operator_at_returns_false_for_none_token() -> None:
    """Line 139: offset beyond token list yields None token → returns False."""
    parser = YaraLParser("")
    # One token only; offset 1 is out-of-bounds, _event_value_token_ahead returns None.
    _set_tokens(
        parser,
        [
            _tok(T.IDENTIFIER, "x"),
        ],
    )
    # current=0, offset=1 → position=1 >= len(tokens)=1 → None → line 139 executes.
    result = parser._is_event_var_comparison_operator_at(1)
    assert result is False


# ---------------------------------------------------------------------------
# Lines 210->216: _parse_event_assignment with IDENTIFIER RHS that is NOT a module
# ---------------------------------------------------------------------------


def test_parse_event_assignment_rhs_non_module_identifier_falls_through() -> None:
    """Lines 210->216 False branch: IDENTIFIER on RHS that is not a module name."""
    # When the RHS is an IDENTIFIER that is not in _RAW_EVENT_MODULES, the 'if'
    # at line 210 is False; execution falls through to line 216 (EVENT_VAR check).
    # Since the token is also not EVENT_VAR/STRING_IDENTIFIER, we reach line 227.
    parser = YaraLParser("")
    _set_tokens(
        parser,
        [
            _tok(T.STRING_IDENTIFIER, "$var", yaral_type=YaraLTokenType.EVENT_VAR),
            _tok(T.EQ, "="),
            # 'foo' is an IDENTIFIER but NOT in _RAW_EVENT_MODULES.
            _tok(T.IDENTIFIER, "foo"),
            _tok(T.EOF, None, yaral_type=YaraLTokenType.EOF),
        ],
    )

    stmt = parser._parse_event_statement()

    assert isinstance(stmt, EventStatement)
    assert stmt.text is not None
    assert "$var" in stmt.text
    assert "foo" in stmt.text


# ---------------------------------------------------------------------------
# Lines 319->314: dot-bracket path loops back to while header
# ---------------------------------------------------------------------------


def test_parse_field_path_dot_bracket_then_regular_dot_loops_back() -> None:
    """Lines 319->314: after taking dot+bracket path, while loop continues."""
    # metadata.[0].subfield: after consuming the bracket at line 319-328,
    # the while loop re-evaluates at line 314 (DOT present) and continues.
    parser = YaraLParser("")
    _set_tokens(
        parser,
        [
            _tok(T.IDENTIFIER, "metadata"),
            _tok(T.DOT, "."),
            _tok(T.LBRACKET, "["),
            _tok(T.INTEGER, "0"),
            _tok(T.RBRACKET, "]"),
            _tok(T.DOT, "."),
            _tok(T.IDENTIFIER, "subfield"),
            _tok(T.EOF, None, yaral_type=YaraLTokenType.EOF),
        ],
    )

    path = parser._parse_field_path()

    assert path.parts == ["metadata", "[0]", "subfield"]


# ---------------------------------------------------------------------------
# Lines 325->328: dot-bracket integer path continues into loop
# ---------------------------------------------------------------------------


def test_parse_field_path_dot_bracket_string_then_dot_bracket_integer_loops() -> None:
    """Lines 325->328: dot+STRING key followed by another bracket accesses."""
    # First: .["key"] (STRING path) then: .["second"] — ensures 325->328 is taken
    # and the loop continues back to line 314.
    parser = YaraLParser("")
    _set_tokens(
        parser,
        [
            _tok(T.IDENTIFIER, "root"),
            _tok(T.DOT, "."),
            _tok(T.LBRACKET, "["),
            _tok(T.INTEGER, "5"),
            _tok(T.RBRACKET, "]"),
            _tok(T.DOT, "."),
            _tok(T.LBRACKET, "["),
            _tok(T.STRING, "key"),
            _tok(T.RBRACKET, "]"),
            _tok(T.EOF, None, yaral_type=YaraLTokenType.EOF),
        ],
    )

    path = parser._parse_field_path()

    assert path.parts == ["root", "[5]", '["key"]']


# ---------------------------------------------------------------------------
# Lines 329->314: direct-bracket path loops back (after LBRACKET branch, while continues)
# ---------------------------------------------------------------------------


def test_parse_field_path_direct_bracket_then_dot_loops_back() -> None:
    """Lines 329->314: after direct bracket, while loop re-evaluates at 314."""
    # labels["env"].subfield: direct bracket, then DOT triggers another iteration.
    parser = YaraLParser("")
    _set_tokens(
        parser,
        [
            _tok(T.IDENTIFIER, "labels"),
            _tok(T.LBRACKET, "["),
            _tok(T.STRING, "env"),
            _tok(T.RBRACKET, "]"),
            _tok(T.DOT, "."),
            _tok(T.IDENTIFIER, "name"),
            _tok(T.EOF, None, yaral_type=YaraLTokenType.EOF),
        ],
    )

    path = parser._parse_field_path()

    assert path.parts == ["labels", '["env"]', "name"]


# ---------------------------------------------------------------------------
# Lines 335->338: direct-bracket integer path continues into loop
# ---------------------------------------------------------------------------


def test_parse_field_path_direct_bracket_integer_then_another_bracket_loops() -> None:
    """Lines 335->338: direct bracket integer followed by another bracket."""
    # items[0]["key"]: integer bracket, then string bracket — both paths taken, loop iterates.
    parser = YaraLParser("")
    _set_tokens(
        parser,
        [
            _tok(T.IDENTIFIER, "items"),
            _tok(T.LBRACKET, "["),
            _tok(T.INTEGER, "0"),
            _tok(T.RBRACKET, "]"),
            _tok(T.LBRACKET, "["),
            _tok(T.STRING, "name"),
            _tok(T.RBRACKET, "]"),
            _tok(T.EOF, None, yaral_type=YaraLTokenType.EOF),
        ],
    )

    path = parser._parse_field_path()

    assert path.parts == ["items", "[0]", '["name"]']


# ---------------------------------------------------------------------------
# Lines 319->314: dot followed by neither IDENTIFIER nor LBRACKET (bare dot at end)
# ---------------------------------------------------------------------------


def test_parse_field_path_dot_neither_identifier_nor_bracket_restarts_loop() -> None:
    """Lines 319->314: DOT consumed but next is neither IDENTIFIER nor LBRACKET.

    After advancing past the DOT at line 316, the parser checks IDENTIFIER (317)
    and LBRACKET (319) — both False.  Execution falls through all inner-if branches
    and the while re-evaluates at line 314.  Since there is no more DOT or LBRACKET,
    the while exits.
    """
    parser = YaraLParser("")
    _set_tokens(
        parser,
        [
            _tok(T.IDENTIFIER, "metadata"),
            _tok(T.DOT, "."),
            # STRING is neither IDENTIFIER nor LBRACKET — triggers the 319->314 gap.
            _tok(T.STRING, "orphan"),
            _tok(T.EOF, None, yaral_type=YaraLTokenType.EOF),
        ],
    )

    # Parser consumed 'metadata', saw '.', advanced past it, then saw STRING which
    # is neither IDENTIFIER nor LBRACKET — loop exits with only "metadata".
    path = parser._parse_field_path()

    assert path.parts == ["metadata"]
    # The STRING token was NOT consumed by _parse_field_path.
    assert parser._peek().value == "orphan"


# ---------------------------------------------------------------------------
# Lines 325->328: dot-bracket with neither STRING nor INTEGER inside
# ---------------------------------------------------------------------------


def test_parse_field_path_dot_bracket_empty_bracket_falls_through_325() -> None:
    """Lines 325->328: .[ followed by neither STRING nor INTEGER inside bracket.

    After consuming DOT and LBRACKET at line 321, the parser checks STRING (322)
    and INTEGER (325) — both False.  Line 328 (consume RBRACKET) is called with an
    empty bracket.  The branch 325->328 (integer check False → directly to 328) is taken.
    """
    parser = YaraLParser("")
    _set_tokens(
        parser,
        [
            _tok(T.IDENTIFIER, "fields"),
            _tok(T.DOT, "."),
            _tok(T.LBRACKET, "["),
            # No STRING or INTEGER — directly close the bracket.
            _tok(T.RBRACKET, "]"),
            _tok(T.EOF, None, yaral_type=YaraLTokenType.EOF),
        ],
    )

    path = parser._parse_field_path()

    # No key was appended since neither STRING nor INTEGER was present.
    assert path.parts == ["fields"]


# ---------------------------------------------------------------------------
# Lines 329->314: direct-bracket path — while loop continues after bracket body
# ---------------------------------------------------------------------------


def test_parse_field_path_direct_bracket_string_then_direct_bracket_loops() -> None:
    """Lines 329->314: direct bracket taken, then while iterates for a second bracket."""
    # labels["env"]["zone"]: two consecutive direct brackets — first enters the
    # elif body at 329, then the while re-evaluates at 314 (329->314 taken again).
    parser = YaraLParser("")
    _set_tokens(
        parser,
        [
            _tok(T.IDENTIFIER, "labels"),
            _tok(T.LBRACKET, "["),
            _tok(T.STRING, "env"),
            _tok(T.RBRACKET, "]"),
            _tok(T.LBRACKET, "["),
            _tok(T.STRING, "zone"),
            _tok(T.RBRACKET, "]"),
            _tok(T.EOF, None, yaral_type=YaraLTokenType.EOF),
        ],
    )

    path = parser._parse_field_path()

    assert path.parts == ["labels", '["env"]', '["zone"]']


# ---------------------------------------------------------------------------
# Lines 335->338: direct-bracket with neither STRING nor INTEGER inside
# ---------------------------------------------------------------------------


def test_parse_field_path_direct_bracket_empty_falls_through_335() -> None:
    """Lines 335->338: [ followed by neither STRING nor INTEGER (empty bracket).

    After advancing past LBRACKET at line 331, STRING check (332) and INTEGER
    check (335) are both False.  Line 338 (consume RBRACKET) is called directly.
    The branch 335->338 (integer False → directly to 338) is taken.
    """
    parser = YaraLParser("")
    _set_tokens(
        parser,
        [
            _tok(T.IDENTIFIER, "arr"),
            _tok(T.LBRACKET, "["),
            # No STRING or INTEGER — close immediately.
            _tok(T.RBRACKET, "]"),
            _tok(T.EOF, None, yaral_type=YaraLTokenType.EOF),
        ],
    )

    path = parser._parse_field_path()

    assert path.parts == ["arr"]


# ---------------------------------------------------------------------------
# Lines 365-366: _parse_event_operator keyword "matches" (identifier value)
# ---------------------------------------------------------------------------


def test_parse_event_operator_matches_keyword_by_value() -> None:
    """Lines 365-366: check_keyword('matches') True → returns '=~'."""
    # An IDENTIFIER token whose value is "matches" (not the MATCHES token type).
    parser = YaraLParser("")
    _set_tokens(
        parser,
        [
            _tok(T.IDENTIFIER, "matches"),
            _tok(T.EOF, None, yaral_type=YaraLTokenType.EOF),
        ],
    )

    op = parser._parse_event_operator()

    assert op == "=~"


# ---------------------------------------------------------------------------
# Lines 502->508: _parse_function_call_statement EQ with no EVENT_VAR/STRING_IDENTIFIER
# ---------------------------------------------------------------------------


def test_parse_function_call_statement_eq_rhs_not_consumed_when_not_var() -> None:
    """Lines 502->508 False branch: EQ present but RHS is neither EVENT_VAR nor STRING_IDENTIFIER."""
    # After function(...) = the RHS is a STRING token — not an EVENT_VAR or
    # STRING_IDENTIFIER — so the 'if' at line 502 is False and line 505 is skipped.
    parser = YaraLParser("")
    _set_tokens(
        parser,
        [
            _tok(T.IDENTIFIER, "re.regex"),
            _tok(T.LPAREN, "("),
            _tok(T.RPAREN, ")"),
            _tok(T.EQ, "="),
            # STRING (not STRING_IDENTIFIER) — the condition at 502 is False.
            _tok(T.STRING, "somevalue"),
            _tok(T.EOF, None, yaral_type=YaraLTokenType.EOF),
        ],
    )

    stmt = parser._parse_function_call_statement()

    # Statement is returned; the STRING token was NOT consumed (parser stopped
    # at the EQ because the RHS is not a variable).
    assert isinstance(stmt, EventStatement)
    # The EQ was consumed but "somevalue" was left behind — verify current position.
    assert parser._peek().value == "somevalue"


# ---------------------------------------------------------------------------
# Full-rule integration: nocase via real parse
# ---------------------------------------------------------------------------


def test_full_rule_parse_event_with_nocase_modifier_integration() -> None:
    """End-to-end: 'nocase' modifier appears in the parsed EventAssignment."""
    ast = YaraLParser("""
        rule nocase_rule {
          events:
            $e.principal.hostname = "ADMIN" nocase
          condition:
            $e
        }
        """).parse()

    events = ast.rules[0].events
    assert events is not None
    stmt = events.statements[0]
    assert isinstance(stmt, EventAssignment)
    assert stmt.modifiers == ["nocase"]


# ---------------------------------------------------------------------------
# Full-rule integration: parenthesized boolean expression
# ---------------------------------------------------------------------------


def test_full_rule_parse_parenthesized_boolean_expression_in_events() -> None:
    """End-to-end: parenthesized OR expression parsed without error."""
    ast = YaraLParser("""
        rule paren_bool {
          events:
            ($e.metadata.event_type = "NETWORK_CONNECTION" or
             $e.metadata.event_type = "DNS_QUERY")
          condition:
            $e
        }
        """).parse()

    events = ast.rules[0].events
    assert events is not None
    assert len(events.statements) == 1
    stmt = events.statements[0]
    assert isinstance(stmt, EventStatement)
    assert stmt.text is not None
    assert "NETWORK_CONNECTION" in stmt.text


# ---------------------------------------------------------------------------
# Full-rule integration: complex event pattern with any/all
# ---------------------------------------------------------------------------


def test_full_rule_parse_any_of_complex_pattern_integration() -> None:
    """Lines 274-285 via real parser: 'any of' pattern parses without error."""
    ast = YaraLParser("""
        rule complex_pattern {
          events:
            any of
              ($e.principal.ip = "1.2.3.4",
               $e.target.ip = "5.6.7.8")
          condition:
            $e
        }
        """).parse()

    events = ast.rules[0].events
    assert events is not None
    assert len(events.statements) >= 1


# ---------------------------------------------------------------------------
# Full-rule integration: net module function call as event value
# ---------------------------------------------------------------------------


def test_full_rule_parse_net_function_call_as_event_value() -> None:
    """Lines 449-451, 431-433: net.ip_in_range_cidr() as comparison value."""
    ast = YaraLParser("""
        rule net_func {
          events:
            net.ip_in_range_cidr($e.principal.ip, "192.168.0.0/16")
          condition:
            $e
        }
        """).parse()

    events = ast.rules[0].events
    assert events is not None
    assert len(events.statements) >= 1
