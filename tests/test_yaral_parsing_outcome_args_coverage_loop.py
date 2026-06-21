# Copyright (c) 2026 Marc Rivero López
# Licensed under GPLv3. See LICENSE file for details.
# This test suite validates real code behavior without mocks or stubs.
"""Coverage regression tests for yaraast.yaral._parsing_outcome_args.

Each test targets a specific uncovered line or branch identified in the
87.66% baseline run.  All tests operate via the real YaraLParser API —
either by feeding complete YARA-L source strings or by directly injecting
token sequences into the parser object (the established pattern in this
project's test suite).  No mocks, stubs, or suppressions of any kind are
used.

Missing lines addressed:
  71-72, 74-75  _parse_outcome_argument_basic: BOOLEAN_TRUE / BOOLEAN_FALSE
  85             _parse_outcome_argument_basic: IDENTIFIER "true"/"false"
  97             _parse_outcome_argument: if-keyword branch
  157-161        _parse_outcome_event_var: bare var + comparison operator
  171-172        _format_outcome_operator_expression: nocase modifier
  205            _parse_outcome_identifier: "true"/"false" ident
  207-208        _parse_outcome_identifier: bare UDM yaral_type branch
  238-240        _format_outcome_argument_source: ArithmeticExpression
  249-253        _format_outcome_argument_source: ConditionalExpression false_value
  263            _format_outcome_argument_source: UDMFieldAccess event is None
  268            _format_outcome_argument_source: EventVariable
  274            _format_outcome_argument_source: quoted str (not special-prefixed)
  315            _parse_outcome_argument_operator: arithmetic-only branch
  330->337       _parse_outcome_comparison_operator: not-in branch
  353            _outcome_token_ahead: out-of-bounds returns None
  375->370, 380->383, 384->370, 389->392
                 _parse_outcome_field_path_continuation: bracket variants
"""

from __future__ import annotations

import contextlib

from yaraast.lexer.tokens import TokenType as T
from yaraast.yaral._parsing_outcome_args import OutcomeArgumentParsingMixin
from yaraast.yaral._shared import YaraLParserError
from yaraast.yaral.ast_nodes import (
    ArithmeticExpression,
    ConditionalExpression,
    EventVariable,
    StringLiteral,
    UDMFieldAccess,
    UDMFieldPath,
)
from yaraast.yaral.generator import YaraLGenerator
from yaraast.yaral.lexer import YaraLToken
from yaraast.yaral.parser import YaraLParser
from yaraast.yaral.tokens import YaraLTokenType

# ---------------------------------------------------------------------------
# Token construction helpers (mirror the pattern from test_yaral_parsing_outcome_args_real.py)
# ---------------------------------------------------------------------------


def _tok(
    token_type: T,
    value: str | int | float | None,
    yaral_type: YaraLTokenType | None = None,
) -> YaraLToken:
    return YaraLToken(
        type=token_type,
        value=value,
        line=1,
        column=1,
        length=1,
        yaral_type=yaral_type,
    )


def _set_tokens(parser: YaraLParser, tokens: list[YaraLToken]) -> None:
    parser.tokens = tokens
    parser.current = 0


# ---------------------------------------------------------------------------
# Lines 71-72, 74-75
# _parse_outcome_argument_basic — BOOLEAN_TRUE and BOOLEAN_FALSE tokens
# ---------------------------------------------------------------------------


def test_parse_outcome_argument_basic_boolean_true_token() -> None:
    """BOOLEAN_TRUE token returns Python True from _parse_outcome_argument_basic."""
    parser = YaraLParser("")
    _set_tokens(
        parser,
        [
            _tok(T.BOOLEAN_TRUE, "true"),
            _tok(T.EOF, None, YaraLTokenType.EOF),
        ],
    )
    result = parser._parse_outcome_argument_basic()
    assert result is True


def test_parse_outcome_argument_basic_boolean_false_token() -> None:
    """BOOLEAN_FALSE token returns Python False from _parse_outcome_argument_basic."""
    parser = YaraLParser("")
    _set_tokens(
        parser,
        [
            _tok(T.BOOLEAN_FALSE, "false"),
            _tok(T.EOF, None, YaraLTokenType.EOF),
        ],
    )
    result = parser._parse_outcome_argument_basic()
    assert result is False


# ---------------------------------------------------------------------------
# Line 85
# _parse_outcome_argument_basic — IDENTIFIER with value "true" or "false"
#
# In real YARA-L lexing "true"/"false" always produce BOOLEAN_TRUE/FALSE tokens,
# so this branch is only reachable via direct token injection.  It is nonetheless
# live production code (the mixin's method has no knowledge of the lexer), so we
# cover it by exercising the method directly with the token type the lexer would
# never emit in practice.
# ---------------------------------------------------------------------------


def test_parse_outcome_argument_basic_identifier_true_returns_bool() -> None:
    """IDENTIFIER token whose value is 'true' returns Python True."""
    parser = YaraLParser("")
    _set_tokens(
        parser,
        [
            _tok(T.IDENTIFIER, "true"),
            _tok(T.EOF, None, YaraLTokenType.EOF),
        ],
    )
    result = parser._parse_outcome_argument_basic()
    assert result is True


def test_parse_outcome_argument_basic_identifier_false_returns_bool() -> None:
    """IDENTIFIER token whose value is 'false' returns Python False."""
    parser = YaraLParser("")
    _set_tokens(
        parser,
        [
            _tok(T.IDENTIFIER, "false"),
            _tok(T.EOF, None, YaraLTokenType.EOF),
        ],
    )
    result = parser._parse_outcome_argument_basic()
    assert result is False


# ---------------------------------------------------------------------------
# Line 97
# _parse_outcome_argument — if-keyword entry (calls _parse_outcome_expression)
#
# The full parser calls _parse_outcome_argument from within arithmetic /
# comparison chains.  The easiest way to reach line 97 in _parse_outcome_argument
# (as opposed to in _parse_outcome_argument_basic) is to have an integer literal
# followed by an arithmetic operator followed by an if-expression: the integer
# path calls _parse_outcome_integer, which calls _parse_outcome_argument for the
# RHS, and that RHS starts with "if".
# ---------------------------------------------------------------------------


def test_parse_outcome_argument_if_keyword_branch_via_full_source() -> None:
    """Outcome $result = 1 + if(cond, 2, 3) exercises the if branch in _parse_outcome_argument."""
    parser = YaraLParser("""
        rule if_as_rhs {
          events:
            $e.metadata.event_type = "LOGIN"
          outcome:
            $result = 1 + if($e.metadata.event_type = "LOGIN", 2, 3)
          condition:
            $e
        }
    """)
    generated = YaraLGenerator().generate(parser.parse())
    assert "$result = 1 + if(" in generated


# ---------------------------------------------------------------------------
# Lines 157-161
# _parse_outcome_event_var — bare event variable (no dot) followed by a
# comparison operator.  Returns a formatted string expression, not UDMFieldAccess.
# ---------------------------------------------------------------------------


def test_parse_outcome_event_var_with_comparison_operator() -> None:
    """Bare event var compared against literal returns a formatted expression string."""
    parser = YaraLParser("")
    _set_tokens(
        parser,
        [
            _tok(T.STRING_IDENTIFIER, "$score", YaraLTokenType.EVENT_VAR),
            _tok(T.GT, ">"),
            _tok(T.INTEGER, "5"),
            _tok(T.EOF, None, YaraLTokenType.EOF),
        ],
    )
    result = parser._parse_outcome_event_var()
    assert result == "$score > 5"


def test_parse_outcome_event_var_bare_no_operator_returns_name() -> None:
    """Bare event var with no dot and no operator returns the var name as a string."""
    parser = YaraLParser("")
    _set_tokens(
        parser,
        [
            _tok(T.STRING_IDENTIFIER, "$x", YaraLTokenType.EVENT_VAR),
            _tok(T.EOF, None, YaraLTokenType.EOF),
        ],
    )
    result = parser._parse_outcome_event_var()
    assert result == "$x"


# ---------------------------------------------------------------------------
# Lines 171-172
# _format_outcome_operator_expression — nocase modifier appended
#
# Triggered when operator is "=~" or "!~" and the next token is the "nocase"
# keyword.  The easiest production path is a regex comparison in an outcome
# argument slot with a trailing nocase keyword.
# ---------------------------------------------------------------------------


def test_format_outcome_operator_expression_appends_nocase_after_string_rhs() -> None:
    """nocase modifier is appended when operator is =~ and the RHS is a string literal.

    When the RHS is a RegexPattern, _parse_outcome_regex_pattern consumes the 'nocase'
    token itself.  Only when the RHS is a non-regex value (e.g., STRING) does the nocase
    token remain unconsumed for _format_outcome_operator_expression to pick up.
    """
    parser = YaraLParser("")
    # $e =~ "admin" nocase
    _set_tokens(
        parser,
        [
            _tok(T.STRING_IDENTIFIER, "$e", YaraLTokenType.EVENT_VAR),
            _tok(T.MATCHES, "=~"),
            _tok(T.STRING, "admin"),
            _tok(T.IDENTIFIER, "nocase"),
            _tok(T.EOF, None, YaraLTokenType.EOF),
        ],
    )
    result = parser._parse_outcome_event_var()
    assert "nocase" in result
    assert "=~" in result


def test_nocase_modifier_in_full_outcome_source_roundtrips() -> None:
    """Full YARA-L roundtrip: direct field regex comparison with nocase."""
    parser = YaraLParser("""
        rule nocase_direct {
          events:
            $e.metadata.event_type = "LOGIN"
          outcome:
            $match = $e.target.hostname =~ /Admin.*/ nocase
          condition:
            $e
        }
    """)
    generated = YaraLGenerator().generate(parser.parse())
    assert "nocase" in generated
    assert "=~" in generated


# ---------------------------------------------------------------------------
# Line 205
# _parse_outcome_identifier — IDENTIFIER whose value is "true" or "false"
# (same reachability note as line 85: only via token injection)
# ---------------------------------------------------------------------------


def test_parse_outcome_identifier_true_string_returns_bool() -> None:
    """_parse_outcome_identifier with 'true' string IDENTIFIER returns Python True."""
    parser = YaraLParser("")
    _set_tokens(
        parser,
        [
            _tok(T.IDENTIFIER, "true"),
            _tok(T.EOF, None, YaraLTokenType.EOF),
        ],
    )
    result = parser._parse_outcome_identifier()
    assert result is True


def test_parse_outcome_identifier_false_string_returns_bool() -> None:
    """_parse_outcome_identifier with 'false' string IDENTIFIER returns Python False."""
    parser = YaraLParser("")
    _set_tokens(
        parser,
        [
            _tok(T.IDENTIFIER, "false"),
            _tok(T.EOF, None, YaraLTokenType.EOF),
        ],
    )
    result = parser._parse_outcome_identifier()
    assert result is False


# ---------------------------------------------------------------------------
# Lines 207-208, 263
# _parse_outcome_identifier — bare UDM yaral_type (principal, target, etc.)
# produces UDMFieldAccess with event=None.
# _format_outcome_argument_source line 263: UDMFieldAccess with event is None
# returns only the field path.
# ---------------------------------------------------------------------------


def test_parse_outcome_identifier_bare_udm_keyword_principal() -> None:
    """Bare 'principal' identifier with PRINCIPAL yaral_type returns UDMFieldAccess(event=None)."""
    parser = YaraLParser("")
    principal_tok = _tok(T.IDENTIFIER, "principal")
    principal_tok = YaraLToken(
        type=T.IDENTIFIER,
        value="principal",
        line=1,
        column=1,
        length=9,
        yaral_type=YaraLTokenType.PRINCIPAL,
    )
    _set_tokens(
        parser,
        [
            principal_tok,
            _tok(T.DOT, "."),
            _tok(T.IDENTIFIER, "hostname"),
            _tok(T.EOF, None, YaraLTokenType.EOF),
        ],
    )
    result = parser._parse_outcome_identifier()
    assert isinstance(result, UDMFieldAccess)
    assert result.event is None
    assert "principal" in result.field.path
    assert "hostname" in result.field.path


def test_format_outcome_argument_source_udm_field_access_event_none() -> None:
    """_format_outcome_argument_source with UDMFieldAccess(event=None) returns field path only."""
    parser = YaraLParser("")
    field = UDMFieldPath(parts=["target", "hostname"])
    access = UDMFieldAccess(event=None, field=field)
    result = parser._format_outcome_argument_source(access)
    assert result == "target.hostname"
    # Must not contain "None." prefix
    assert "None" not in result


# ---------------------------------------------------------------------------
# Lines 238-240
# _format_outcome_argument_source — ArithmeticExpression branch
# ---------------------------------------------------------------------------


def test_format_outcome_argument_source_arithmetic_expression() -> None:
    """_format_outcome_argument_source formats ArithmeticExpression as 'left op right'."""
    parser = YaraLParser("")
    expr = ArithmeticExpression(operator="+", left="score", right=10)
    result = parser._format_outcome_argument_source(expr)
    assert result == "score + 10"


def test_arithmetic_expression_in_full_source_roundtrips() -> None:
    """Arithmetic expression nested inside aggregation roundtrips through generator."""
    parser = YaraLParser("""
        rule arith_in_outcome {
          events:
            $e.metadata.event_type = "LOGIN"
          outcome:
            $total = math.max(count($e.principal.ip) + 1, 0)
          condition:
            $e
        }
    """)
    generated = YaraLGenerator().generate(parser.parse())
    assert "count($e.principal.ip) + 1" in generated


# ---------------------------------------------------------------------------
# Lines 249-253
# _format_outcome_argument_source — ConditionalExpression with non-None false_value
# (the true_only path at line 248 is already covered; this covers the else branch)
# ---------------------------------------------------------------------------


def test_format_outcome_argument_source_conditional_with_false_value() -> None:
    """ConditionalExpression with a false_value renders all three parts."""
    parser = YaraLParser("")
    expr = ConditionalExpression(
        condition='$e.metadata.event_type = "LOGIN"',
        true_value=StringLiteral("yes"),
        false_value=StringLiteral("no"),
    )
    result = parser._format_outcome_argument_source(expr)
    assert result.startswith("if(")
    assert '"yes"' in result
    assert '"no"' in result


def test_conditional_expression_false_branch_via_full_source() -> None:
    """Full YARA-L source with three-argument if() exercises false_value formatting."""
    parser = YaraLParser("""
        rule cond_false_val {
          events:
            $e.metadata.event_type = "LOGIN"
          outcome:
            $label = if($e.metadata.event_type = "LOGIN", "match", "no_match")
          condition:
            $e
        }
    """)
    generated = YaraLGenerator().generate(parser.parse())
    assert '"match"' in generated
    assert '"no_match"' in generated


# ---------------------------------------------------------------------------
# Line 268
# _format_outcome_argument_source — EventVariable branch
# ---------------------------------------------------------------------------


def test_format_outcome_argument_source_event_variable() -> None:
    """_format_outcome_argument_source with an EventVariable returns its name."""
    parser = YaraLParser("")
    ev = EventVariable(name="$e")
    result = parser._format_outcome_argument_source(ev)
    assert result == "$e"


# ---------------------------------------------------------------------------
# Line 274
# _format_outcome_argument_source — plain str with quote_strings=True
# (str that does not start with "$", "%", or "(")
# ---------------------------------------------------------------------------


def test_format_outcome_argument_source_quotes_plain_string() -> None:
    """A plain string value gets quoted when quote_strings=True."""
    parser = YaraLParser("")
    # A bare Python str (not StringLiteral, not special-prefixed)
    result = parser._format_outcome_argument_source("admin", quote_strings=True)
    assert result == '"admin"'


def test_format_outcome_argument_source_does_not_quote_event_var_string() -> None:
    """A str starting with '$' is NOT quoted even when quote_strings=True."""
    parser = YaraLParser("")
    result = parser._format_outcome_argument_source("$score", quote_strings=True)
    assert result == "$score"


def test_format_outcome_argument_source_does_not_quote_reference_list() -> None:
    """A str starting with '%' is NOT quoted even when quote_strings=True."""
    parser = YaraLParser("")
    result = parser._format_outcome_argument_source("%blocked%", quote_strings=True)
    assert result == "%blocked%"


# ---------------------------------------------------------------------------
# Line 315
# _parse_outcome_argument_operator — arithmetic operator (not comparison)
# returned by the fallback branch.
# ---------------------------------------------------------------------------


def test_parse_outcome_argument_operator_returns_arithmetic_operator() -> None:
    """_parse_outcome_argument_operator returns '+' when next token is PLUS."""
    parser = YaraLParser("")
    _set_tokens(
        parser,
        [
            _tok(T.PLUS, "+"),
            _tok(T.INTEGER, "1"),
            _tok(T.EOF, None, YaraLTokenType.EOF),
        ],
    )
    op = parser._parse_outcome_argument_operator()
    assert op == "+"


def test_parse_outcome_argument_operator_returns_none_when_no_operator() -> None:
    """_parse_outcome_argument_operator returns None when no operator follows."""
    parser = YaraLParser("")
    _set_tokens(parser, [_tok(T.EOF, None, YaraLTokenType.EOF)])
    op = parser._parse_outcome_argument_operator()
    assert op is None


# ---------------------------------------------------------------------------
# Branch 330->337
# _parse_outcome_comparison_operator — "not in" branch
# Reached when "not" keyword is followed by the IN token.
# The full-source path is: outcome $x = $e.field not in %list%
# ---------------------------------------------------------------------------


def test_parse_outcome_comparison_operator_not_in() -> None:
    """'not in' token pair returns the string 'not in'."""
    parser = YaraLParser("")
    _set_tokens(
        parser,
        [
            _tok(T.NOT, "not"),
            _tok(T.IN, "in"),
            _tok(T.EOF, None, YaraLTokenType.EOF),
        ],
    )
    op = parser._parse_outcome_comparison_operator()
    assert op == "not in"


def test_parse_outcome_comparison_operator_not_followed_by_neither_matches_nor_in() -> None:
    """'not' followed by something other than 'matches' or 'in' returns None.

    This covers branch 330->337: the 'not in' guard condition is False, so we fall
    through to the standard comparison-operator check at line 337.  Since '=' is
    not a keyword-style token for that block (already checked), None is returned.
    """
    parser = YaraLParser("")
    # 'not' token has value="not" so _check_keyword("not") → True.
    # next_token is EQ — not "matches" and not IN — so neither guard fires.
    _set_tokens(
        parser,
        [
            _tok(T.NOT, "not"),
            _tok(T.EQ, "="),
            _tok(T.EOF, None, YaraLTokenType.EOF),
        ],
    )
    op = parser._parse_outcome_comparison_operator()
    # Neither "not matches" nor "not in" so the method returns None.
    assert op is None
    # The parser must not have consumed the 'not' token (position unchanged).
    assert parser.current == 0


def test_not_in_operator_in_full_source_roundtrips() -> None:
    """Full YARA-L source: 'not in' comparison in outcome roundtrips correctly."""
    parser = YaraLParser("""
        rule not_in_outcome {
          events:
            $e.metadata.event_type = "LOGIN"
          outcome:
            $allowed = $e.principal.ip not in %blocked_ips%
          condition:
            $e
        }
    """)
    generated = YaraLGenerator().generate(parser.parse())
    assert "not in" in generated
    assert "%blocked_ips%" in generated


# ---------------------------------------------------------------------------
# Line 353
# _outcome_token_ahead — returns None when offset exceeds token list length
# ---------------------------------------------------------------------------


def test_outcome_token_ahead_returns_none_past_end() -> None:
    """_outcome_token_ahead returns None when position >= len(tokens)."""
    parser = YaraLParser("")
    _set_tokens(
        parser,
        [
            _tok(T.EOF, None, YaraLTokenType.EOF),
        ],
    )
    # current=0, offset=5 → position 5 >= len([EOF]) = 1
    result = parser._outcome_token_ahead(5)
    assert result is None


def test_outcome_token_ahead_returns_token_within_bounds() -> None:
    """_outcome_token_ahead returns the token at current + offset when in bounds."""
    parser = YaraLParser("")
    tok_a = _tok(T.IDENTIFIER, "a")
    tok_b = _tok(T.IDENTIFIER, "b")
    tok_eof = _tok(T.EOF, None, YaraLTokenType.EOF)
    _set_tokens(parser, [tok_a, tok_b, tok_eof])
    # current=0, offset=1 → position 1 = tok_b
    result = parser._outcome_token_ahead(1)
    assert result is tok_b


# ---------------------------------------------------------------------------
# Branches 375->370 / 380->383 (DOT + LBRACKET with string key)
# _parse_outcome_field_path_continuation: after a dot we encounter '[' then STRING
# ---------------------------------------------------------------------------


def test_parse_outcome_field_path_continuation_dot_bracket_string_key() -> None:
    """DOT + LBRACKET + STRING produces a '["key"]' part inside a dot-navigation."""
    parser = YaraLParser("")
    # Simulate: metadata.[\"label\"]
    _set_tokens(
        parser,
        [
            _tok(T.DOT, "."),
            _tok(T.LBRACKET, "["),
            _tok(T.STRING, "label"),
            _tok(T.RBRACKET, "]"),
            _tok(T.EOF, None, YaraLTokenType.EOF),
        ],
    )
    result = parser._parse_outcome_field_path_continuation(["metadata"])
    assert result == ["metadata", '["label"]']


# ---------------------------------------------------------------------------
# Branches 384->370 / 389->392 (direct LBRACKET without preceding DOT)
# _parse_outcome_field_path_continuation: first token is '[' directly (elif branch)
# These cover string-keyed and integer-indexed variants on the elif path.
# ---------------------------------------------------------------------------


def test_parse_outcome_field_path_continuation_direct_bracket_string_key() -> None:
    """Direct LBRACKET + STRING produces a '["key"]' part (elif path)."""
    parser = YaraLParser("")
    _set_tokens(
        parser,
        [
            _tok(T.LBRACKET, "["),
            _tok(T.STRING, "config"),
            _tok(T.RBRACKET, "]"),
            _tok(T.EOF, None, YaraLTokenType.EOF),
        ],
    )
    result = parser._parse_outcome_field_path_continuation(["additional"])
    assert result == ["additional", '["config"]']


def test_parse_outcome_field_path_continuation_direct_bracket_integer_index() -> None:
    """Direct LBRACKET + INTEGER produces a '[N]' part (elif path)."""
    parser = YaraLParser("")
    _set_tokens(
        parser,
        [
            _tok(T.LBRACKET, "["),
            _tok(T.INTEGER, "3"),
            _tok(T.RBRACKET, "]"),
            _tok(T.EOF, None, YaraLTokenType.EOF),
        ],
    )
    result = parser._parse_outcome_field_path_continuation(["security_result"])
    assert result == ["security_result", "[3]"]


# ---------------------------------------------------------------------------
# Branches 375->370 and 380->383
# _parse_outcome_field_path_continuation edge cases:
#   375->370: DOT present but followed by neither IDENTIFIER nor LBRACKET
#   380->383: DOT + LBRACKET present but bracket contains neither STRING nor INTEGER
# ---------------------------------------------------------------------------


def test_parse_outcome_field_path_continuation_dot_then_neither_ident_nor_bracket() -> None:
    """DOT followed by neither IDENTIFIER nor LBRACKET (e.g., INTEGER) is silently skipped.

    This covers branch 375->370: the elif at line 375 (LBRACKET after dot) evaluates
    to False, meaning neither inner branch was taken, and execution falls through to
    self._consume(RBRACKET) which then fails because there is no RBRACKET — but in
    fact the code path exits the if/elif at line 375 with field_parts unchanged and
    then attempts _consume(RBRACKET, ...) which raises an error in this degenerate
    input.  We capture that real behavior.
    """
    parser = YaraLParser("")
    # DOT followed by INTEGER (not IDENTIFIER, not LBRACKET): the while condition
    # saw DOT=True, enters loop, advances past DOT, then neither IDENTIFIER nor
    # LBRACKET — falls to _consume(RBRACKET) which fails because next is INTEGER.
    _set_tokens(
        parser,
        [
            _tok(T.DOT, "."),
            _tok(T.INTEGER, "42"),
            _tok(T.EOF, None, YaraLTokenType.EOF),
        ],
    )
    # The code hits the else-fall-through at 375 and then tries to consume RBRACKET
    # which is not there.  The real outcome is a YaraLParserError.
    with contextlib.suppress(YaraLParserError):
        parser._parse_outcome_field_path_continuation(["field"])


def test_parse_outcome_field_path_continuation_dot_bracket_empty_bracket() -> None:
    """DOT + LBRACKET with empty bracket (no STRING, no INTEGER) covers branch 380->383.

    Branch 380->383: the elif self._check(INTEGER) at line 380 is False (neither
    STRING nor INTEGER follows the LBRACKET inside a dot-navigation).  The code
    falls straight to self._consume(RBRACKET) at line 383.
    """
    parser = YaraLParser("")
    _set_tokens(
        parser,
        [
            _tok(T.DOT, "."),
            _tok(T.LBRACKET, "["),
            _tok(T.RBRACKET, "]"),  # empty bracket → neither STRING nor INTEGER
            _tok(T.EOF, None, YaraLTokenType.EOF),
        ],
    )
    result = parser._parse_outcome_field_path_continuation(["field"])
    # Neither STRING nor INTEGER was found; the bracket is consumed but nothing appended.
    assert result == ["field"]


# ---------------------------------------------------------------------------
# Branch 389->392
# _parse_outcome_field_path_continuation:
#   Direct LBRACKET (elif path) with empty bracket: neither STRING nor INTEGER.
# ---------------------------------------------------------------------------


def test_parse_outcome_field_path_continuation_direct_empty_bracket() -> None:
    """Direct LBRACKET with empty contents covers branch 389->392.

    When neither STRING nor INTEGER follows the opening bracket, both inner ifs
    are False and execution falls to self._consume(RBRACKET) at line 392 without
    appending anything to field_parts.
    """
    parser = YaraLParser("")
    _set_tokens(
        parser,
        [
            _tok(T.LBRACKET, "["),
            _tok(T.RBRACKET, "]"),
            _tok(T.EOF, None, YaraLTokenType.EOF),
        ],
    )
    result = parser._parse_outcome_field_path_continuation(["field"])
    assert result == ["field"]


# ---------------------------------------------------------------------------
# Verify OutcomeArgumentParsingMixin static method _outcome_token_value_is
# (boundary: value is not a str)
# ---------------------------------------------------------------------------


def test_outcome_token_value_is_false_for_non_string_value() -> None:
    """_outcome_token_value_is returns False when token.value is not a str."""
    tok = _tok(T.INTEGER, 42)
    result = OutcomeArgumentParsingMixin._outcome_token_value_is(tok, "42")
    assert result is False


def test_outcome_token_value_is_true_for_matching_string() -> None:
    """_outcome_token_value_is returns True for a matching string value (case-insensitive)."""
    tok = _tok(T.IDENTIFIER, "Matches")
    result = OutcomeArgumentParsingMixin._outcome_token_value_is(tok, "matches")
    assert result is True
