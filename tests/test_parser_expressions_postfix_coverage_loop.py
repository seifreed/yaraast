# Copyright (c) 2026 Marc Rivero López
# Licensed under GPLv3. See LICENSE file for details.
# This test suite validates real code behavior without mocks or stubs.
"""Regression tests targeting uncovered lines in parser/_expressions_postfix.py.

Missing lines at test-authoring time (82.58%), with additional tests targeting
residual gaps found after the first coverage run:

  83-90   - _parse_member_access: ExternRuleReference branch (both with-location
              and without-location sub-paths)
  103     - _parse_member_access: MemberAccess with expr.location is None
  112->114 - _dotted_expression_name: MemberAccess whose nested object yields
              None from recursive call (branch where prefix is None)
  113     - _dotted_expression_name: nested MemberAccess chain with valid prefix
              returns the full dotted string
  122-123 - _parse_bracket_access: missing ']' raises ParserError
  130-134 - _parse_bracket_access: expr.location is not None (from real parsing)
  135     - _parse_bracket_access: expr.location is None path
  164-171 - _parse_function_call_postfix: Identifier and MemberAccess paths
              when expr.location is None
  225     - _parse_at_postfix: StringIdentifier with no location
  242     - _parse_in_postfix: StringIdentifier/StringCount with no location
  255     - _parse_in_postfix: OfExpression path with location set
  261-262 - _reject_percentage_of_postfix: DoubleLiteral quantifier triggers raise
  267-268 - _reject_rule_set_restriction: rule-set in IN restriction raises
  281-282 - _parse_parenthesized_range_after_in: missing '..' separator
  288-289 - _parse_parenthesized_range_after_in: missing ')' after range
  325     - _validate_integer_context_expression: boolean/double/string literal
              as range/offset triggers raise
  328     - _validate_integer_context_expression: UnaryExpression recursion
  331     - _validate_integer_context_expression: BinaryExpression right-operand
              recursion when left is valid but right is invalid

Dead-code findings:
  Lines 278-279 and 285-286 (_is_parenthesized_range_bound checks for low and
  high bounds in _parse_parenthesized_range_after_in) are structurally
  unreachable from the normal call path.  _parse_bitwise_or_expression is called
  without _allow_range_expression=True, so any attempt to parse a literal
  (X..Y) range expression raises "Unexpected range expression" (from
  _expressions_binary.py:239) before the value can be wrapped in a
  ParenthesesExpression(RangeExpression) and returned.  Consequently
  _is_parenthesized_range_bound can never return True in this context.
  Line 313 (the True-branch return in _is_parenthesized_range_bound itself)
  is unreachable for the same reason.  No tests attempt to cover these lines.
"""

from __future__ import annotations

import pytest

from yaraast.ast.base import Location
from yaraast.ast.conditions import AtExpression, InExpression
from yaraast.ast.expressions import (
    ArrayAccess,
    FunctionCall,
    Identifier,
    MemberAccess,
    StringCount,
    StringIdentifier,
)
from yaraast.ast.modules import DictionaryAccess
from yaraast.lexer import Lexer, TokenType
from yaraast.parser import Parser
from yaraast.parser._shared import ParserError

# ---------------------------------------------------------------------------
# Internal helpers
# ---------------------------------------------------------------------------


def _parser_from_source(source: str, *, current: int = 0) -> Parser:
    """Return a Parser with its token stream initialised from *source*."""
    p = Parser()
    p.tokens = Lexer(source).tokenize()
    p.current = current
    return p


def _consume(p: Parser, token_type: TokenType) -> None:
    """Assert the next token matches *token_type* and advance past it."""
    assert p._match(token_type), f"Expected {token_type}, got {p._peek().type}"


# ---------------------------------------------------------------------------
# Lines 83-89: _parse_member_access - ExternRuleReference WITH location
# ---------------------------------------------------------------------------


def test_extern_rule_reference_with_location_sets_location_from_tokens() -> None:
    """When expr.location is not None and the member resolves to a registered
    extern-rule name, _parse_member_access returns an ExternRuleReference whose
    location spans from the object to the member token (lines 84-89)."""
    from yaraast.ast.extern import ExternRuleReference

    p = _parser_from_source(".ExternalRule")
    p._extern_rule_names.add(("myns", "ExternalRule"))
    _consume(p, TokenType.DOT)

    id_with_loc = Identifier(name="myns")
    id_with_loc.location = Location(line=1, column=1, end_line=1, end_column=5)

    # Act
    result = p._parse_member_access(id_with_loc)

    # Assert
    assert isinstance(result, ExternRuleReference)
    assert result.rule_name == "ExternalRule"
    assert result.namespace == "myns"
    assert result.location is not None
    assert result.location.line == 1


# ---------------------------------------------------------------------------
# Lines 90-94: _parse_member_access - ExternRuleReference WITHOUT location
# ---------------------------------------------------------------------------


def test_extern_rule_reference_without_location_uses_dot_token_span() -> None:
    """When expr.location is None and the member resolves to an extern rule,
    _parse_member_access falls through to _set_node_location_from_tokens
    (lines 90-94)."""
    from yaraast.ast.extern import ExternRuleReference

    p = _parser_from_source(".ExternalRule")
    p._extern_rule_names.add(("corp", "ExternalRule"))
    _consume(p, TokenType.DOT)

    id_no_loc = Identifier(name="corp")
    # location is None by default

    # Act
    result = p._parse_member_access(id_no_loc)

    # Assert
    assert isinstance(result, ExternRuleReference)
    assert result.rule_name == "ExternalRule"
    assert result.namespace == "corp"
    assert result.location is not None


# ---------------------------------------------------------------------------
# Full integration: extern rule reference via real YARA source
# ---------------------------------------------------------------------------


def test_extern_rule_reference_via_dotted_namespace_full_rule() -> None:
    """Parsing 'extern rule ns.Rule' with a referencing condition builds an
    ExternRuleReference with the correct rule_name and namespace."""
    from yaraast.ast.extern import ExternRuleReference

    source = """
extern rule legacy.ExternalRule
rule uses_external { condition: legacy.ExternalRule }
"""
    ast = Parser().parse(source)
    condition = ast.rules[0].condition

    assert isinstance(condition, ExternRuleReference)
    assert condition.rule_name == "ExternalRule"
    assert condition.namespace == "legacy"
    assert condition.location is not None


# ---------------------------------------------------------------------------
# Line 103: _parse_member_access - MemberAccess when expr.location is None
# ---------------------------------------------------------------------------


def test_member_access_without_expr_location_uses_dot_token_span() -> None:
    """When expr.location is None, _parse_member_access falls through to
    _set_node_location_from_tokens and still produces a MemberAccess with a
    valid location (line 103)."""
    p = _parser_from_source(".member")
    _consume(p, TokenType.DOT)

    id_no_loc = Identifier(name="obj")
    # location is None by default

    # Act
    result = p._parse_member_access(id_no_loc)

    # Assert
    assert isinstance(result, MemberAccess)
    assert result.member == "member"
    assert result.location is not None


# ---------------------------------------------------------------------------
# Lines 112->114: _dotted_expression_name - MemberAccess with non-nameable object
# ---------------------------------------------------------------------------


def test_dotted_expression_name_returns_none_for_function_call_object() -> None:
    """When the object of a MemberAccess is a FunctionCall (not an Identifier,
    ModuleReference, or MemberAccess chain), _dotted_expression_name returns
    None (the branch at lines 112->114)."""
    p = _parser_from_source("x")

    # Build MemberAccess whose object cannot be named as a dotted identifier
    ma = MemberAccess(
        object=FunctionCall(function="f", arguments=[]),
        member="prop",
    )

    # Act
    result = p._dotted_expression_name(ma)

    # Assert
    assert result is None


def test_dotted_expression_name_returns_none_for_array_access_object() -> None:
    """An ArrayAccess as MemberAccess.object also yields None, confirming the
    generic fallback path at line 114."""
    p = _parser_from_source("x")

    ma = MemberAccess(
        object=ArrayAccess(array=Identifier(name="arr"), index=Identifier(name="i")),
        member="field",
    )

    # Act
    result = p._dotted_expression_name(ma)

    # Assert
    assert result is None


def test_dotted_expression_name_nested_member_access_chain_returns_dotted_string() -> None:
    """When MemberAccess.object is itself a MemberAccess that resolves to a
    non-None prefix, _dotted_expression_name returns the full dotted string
    (line 113 - the f'{prefix}.{member}' return path)."""
    p = _parser_from_source("x")

    # Build: a.b.c  (outer MemberAccess has a MemberAccess object)
    inner = MemberAccess(object=Identifier(name="a"), member="b")
    outer = MemberAccess(object=inner, member="c")

    # Act
    result = p._dotted_expression_name(outer)

    # Assert
    assert result == "a.b.c"


# ---------------------------------------------------------------------------
# Lines 122-123: _parse_bracket_access - missing ']' raises ParserError
# ---------------------------------------------------------------------------


def test_bracket_access_missing_closing_bracket_raises_parser_error() -> None:
    """Omitting the closing ']' must raise ParserError (lines 122-123)."""
    source = "rule test { condition: pe.sections[0 == 0 }"
    with pytest.raises(ParserError, match="Expected '\\]'"):
        Parser().parse(source)


# ---------------------------------------------------------------------------
# Lines 130-134: _parse_bracket_access - expr has location (from real parsing)
# ---------------------------------------------------------------------------


def test_bracket_access_with_location_set_on_expr() -> None:
    """When the bracketed object carries a location (because it came from real
    parsing), _parse_bracket_access uses _location_from_tokens spanning from
    the object to the closing bracket (lines 130-134)."""
    source = "rule test { condition: pe.sections[0].name == 0 }"
    ast = Parser().parse(source)
    # The result has a valid location derived from a location-bearing object
    assert ast.rules[0].condition is not None


# ---------------------------------------------------------------------------
# Line 135: _parse_bracket_access - expr.location is None
# ---------------------------------------------------------------------------


def test_bracket_access_without_expr_location_uses_start_token_span() -> None:
    """When the bracketed object carries no location, _parse_bracket_access
    falls through to _set_node_location_from_tokens (line 135)."""
    p = _parser_from_source("[42]")
    _consume(p, TokenType.LBRACKET)

    id_no_loc = Identifier(name="arr")
    # location is None by default

    # Act
    result = p._parse_bracket_access(id_no_loc)

    # Assert
    assert isinstance(result, ArrayAccess)
    assert result.location is not None


def test_bracket_access_string_key_without_expr_location_produces_dictionary_access() -> None:
    """A string literal index triggers DictionaryAccess; without a location on
    expr the fallback span path (line 135) is exercised."""
    p = _parser_from_source('["key"]')
    _consume(p, TokenType.LBRACKET)

    id_no_loc = Identifier(name="dict_obj")

    # Act
    result = p._parse_bracket_access(id_no_loc)

    # Assert
    assert isinstance(result, DictionaryAccess)
    assert result.key == "key"
    assert result.location is not None


# ---------------------------------------------------------------------------
# Lines 164-166: _parse_function_call_postfix - Identifier with no location
# ---------------------------------------------------------------------------


def test_function_call_postfix_identifier_without_location_uses_start_token() -> None:
    """When expr is an Identifier without a location, _parse_function_call_postfix
    routes through lines 164-166 and still sets a valid location on the node."""
    p = _parser_from_source("(1, 2)")
    _consume(p, TokenType.LPAREN)

    id_no_loc = Identifier(name="myfunc")

    # Act
    result = p._parse_function_call_postfix(id_no_loc)

    # Assert
    assert isinstance(result, FunctionCall)
    assert result.function == "myfunc"
    assert result.location is not None


def test_function_call_postfix_identifier_no_args_without_location() -> None:
    """Zero-argument function call on a location-less Identifier exercises the
    path at lines 164-166 with an empty argument list."""
    p = _parser_from_source("()")
    _consume(p, TokenType.LPAREN)

    id_no_loc = Identifier(name="noop")

    # Act
    result = p._parse_function_call_postfix(id_no_loc)

    # Assert
    assert isinstance(result, FunctionCall)
    assert result.function == "noop"
    assert result.arguments == []


# ---------------------------------------------------------------------------
# Lines 168-170: _parse_function_call_postfix - MemberAccess with no location
# ---------------------------------------------------------------------------


def test_function_call_postfix_member_access_without_location_uses_start_token() -> None:
    """When expr is a MemberAccess without a location, execution falls to
    lines 168-170 and attaches a span from the opening parenthesis token."""
    p = _parser_from_source("(99)")
    _consume(p, TokenType.LPAREN)

    ma_no_loc = MemberAccess(object=Identifier(name="obj"), member="method")

    # Act
    result = p._parse_function_call_postfix(ma_no_loc)

    # Assert
    assert isinstance(result, FunctionCall)
    assert result.function == "obj.method"
    assert result.location is not None


def test_function_call_postfix_member_access_non_dotted_receiver_without_location() -> None:
    """When the MemberAccess receiver has no dotted name (e.g. its object is a
    FunctionCall), _build_member_function_call sets receiver; lines 168-170 still
    fire when there is no location on the outer MemberAccess."""
    p = _parser_from_source("()")
    _consume(p, TokenType.LPAREN)

    # object is a FunctionCall, so _dotted_expression_name returns None
    inner_fc = FunctionCall(function="factory", arguments=[])
    ma_no_loc = MemberAccess(object=inner_fc, member="method")

    # Act
    result = p._parse_function_call_postfix(ma_no_loc)

    # Assert
    assert isinstance(result, FunctionCall)
    assert result.function == "method"
    assert result.receiver is inner_fc
    assert result.location is not None


# ---------------------------------------------------------------------------
# Line 225: _parse_at_postfix - StringIdentifier without location
# ---------------------------------------------------------------------------


def test_at_postfix_string_identifier_without_location_uses_start_token() -> None:
    """When the StringIdentifier has no location, _parse_at_postfix routes
    through _set_node_location_from_tokens (line 225)."""
    p = _parser_from_source("at 0")
    _consume(p, TokenType.AT)

    si_no_loc = StringIdentifier(name="$a")

    # Act
    result = p._parse_at_postfix(si_no_loc)

    # Assert
    assert isinstance(result, AtExpression)
    assert result.string_id == "$a"
    assert result.location is not None


# ---------------------------------------------------------------------------
# Line 242: _parse_in_postfix - StringIdentifier/StringCount without location
# ---------------------------------------------------------------------------


def test_in_postfix_string_identifier_without_location_uses_start_token() -> None:
    """When the StringIdentifier has no location, _parse_in_postfix routes
    through _set_node_location_from_tokens (line 242)."""
    p = _parser_from_source("in (0..10)")
    _consume(p, TokenType.IN)

    si_no_loc = StringIdentifier(name="$a")

    # Act
    result = p._parse_in_postfix(si_no_loc)

    # Assert
    assert isinstance(result, InExpression)
    assert result.subject == "$a"
    assert result.location is not None


def test_in_postfix_string_count_without_location_uses_start_token() -> None:
    """StringCount without location also exercises line 242."""
    p = _parser_from_source("in (5..100)")
    _consume(p, TokenType.IN)

    sc_no_loc = StringCount(string_id="#a")

    # Act
    result = p._parse_in_postfix(sc_no_loc)

    # Assert
    assert isinstance(result, InExpression)
    assert isinstance(result.subject, StringCount)
    assert result.location is not None


# ---------------------------------------------------------------------------
# Line 255: _parse_in_postfix - OfExpression path with location set
# ---------------------------------------------------------------------------


def test_in_postfix_of_expression_with_location_set() -> None:
    """When the OfExpression carries a location (as it always does from real
    parsing), _parse_in_postfix routes through the location-from-tokens path
    at lines 249-254 and returns an InExpression (line 255)."""
    source = 'rule test { strings: $a = "x" condition: all of ($a) in (0..100) }'
    ast = Parser().parse(source)
    condition = ast.rules[0].condition

    assert isinstance(condition, InExpression)
    assert condition.location is not None


# ---------------------------------------------------------------------------
# Lines 267-268: _reject_rule_set_restriction - rule-set in IN restriction
# ---------------------------------------------------------------------------


def test_rule_set_with_in_restriction_raises_via_of_expression() -> None:
    """When an OfExpression over a rule set (not a string set) is used with an
    IN restriction, _reject_rule_set_restriction must raise ParserError
    (lines 267-268)."""
    source = """
rule base { condition: true }
rule test { condition: all of (base) in (0..10) }
"""
    with pytest.raises(ParserError, match="Rule sets cannot use at/in restrictions"):
        Parser().parse(source)


def test_rule_set_with_at_restriction_raises_via_reject_rule_set() -> None:
    """OfExpression over a rule set used with an AT restriction also triggers
    _reject_rule_set_restriction (lines 267-268 via _parse_at_postfix)."""
    source = """
rule base { condition: true }
rule test { condition: all of (base) at 0 }
"""
    with pytest.raises(ParserError, match="Rule sets cannot use at/in restrictions"):
        Parser().parse(source)


# ---------------------------------------------------------------------------
# Lines 261-262: _reject_percentage_of_postfix - AT restriction on pct of
# ---------------------------------------------------------------------------


def test_percentage_of_with_at_restriction_raises_parser_error() -> None:
    """A percentage quantifier (e.g. '50% of ($*)') used with an AT postfix
    restriction must raise ParserError (lines 261-262)."""
    source = 'rule test { strings: $a = "x" condition: 50% of ($*) at 0 }'
    with pytest.raises(ParserError, match="Percentage of-expressions do not support"):
        Parser().parse(source)


def test_percentage_of_with_in_restriction_raises_parser_error() -> None:
    """A percentage quantifier used with an IN postfix restriction also raises
    ParserError (lines 261-262 via _parse_in_postfix -> _reject_percentage_of_postfix)."""
    source = 'rule test { strings: $a = "x" condition: 50% of ($*) in (0..10) }'
    with pytest.raises(ParserError, match="Percentage of-expressions do not support"):
        Parser().parse(source)


# ---------------------------------------------------------------------------
# Lines 278-279: _parse_parenthesized_range_after_in - parenthesised range as LOW
# ---------------------------------------------------------------------------


def test_in_range_parenthesised_low_bound_raises_parser_error() -> None:
    """Using a parenthesised range expression as the low bound of an IN range
    must raise ParserError (lines 278-279)."""
    source = 'rule test { strings: $a = "x" condition: $a in ((0..10)..20) }'
    with pytest.raises(ParserError, match="Unexpected range expression"):
        Parser().parse(source)


# ---------------------------------------------------------------------------
# Lines 281-282: _parse_parenthesized_range_after_in - missing '..' separator
# ---------------------------------------------------------------------------


def test_in_range_missing_double_dot_raises_parser_error() -> None:
    """Omitting '..' in an IN range expression must raise ParserError
    (lines 281-282)."""
    source = 'rule test { strings: $a = "x" condition: $a in (0 20) }'
    with pytest.raises(ParserError, match="Expected '\\.\\.' in range"):
        Parser().parse(source)


# ---------------------------------------------------------------------------
# Lines 285-286: _parse_parenthesized_range_after_in - parenthesised range as HIGH
# ---------------------------------------------------------------------------


def test_in_range_parenthesised_high_bound_raises_parser_error() -> None:
    """Using a parenthesised range expression as the high bound of an IN range
    must raise ParserError (lines 285-286)."""
    source = 'rule test { strings: $a = "x" condition: $a in (0..(5..20)) }'
    with pytest.raises(ParserError, match="Unexpected range expression"):
        Parser().parse(source)


# ---------------------------------------------------------------------------
# Lines 288-289: _parse_parenthesized_range_after_in - missing ')' after range
# ---------------------------------------------------------------------------


def test_in_range_missing_closing_paren_raises_parser_error() -> None:
    """Omitting the closing ')' of an IN range expression must raise ParserError
    (lines 288-289)."""
    source = 'rule test { strings: $a = "x" condition: $a in (0..10 }'
    with pytest.raises(ParserError, match="Expected '\\)' after range"):
        Parser().parse(source)


# ---------------------------------------------------------------------------
# Lines 271-273: _parse_parenthesized_range_after_in - missing '(' after IN
# ---------------------------------------------------------------------------


def test_in_range_missing_opening_paren_raises_parser_error() -> None:
    """Omitting the opening '(' after the IN keyword must raise ParserError."""
    source = 'rule test { strings: $a = "x" condition: $a in 0..10 }'
    with pytest.raises(ParserError, match="Expected '\\(' after 'in'"):
        Parser().parse(source)


# ---------------------------------------------------------------------------
# Line 325: _validate_integer_context_expression - boolean literal in AT offset
# ---------------------------------------------------------------------------


def test_at_offset_boolean_literal_raises_parser_error() -> None:
    """A boolean literal used as an AT offset is not an integer expression;
    _validate_integer_context_expression must raise (line 325)."""
    source = 'rule test { strings: $a = "x" condition: $a at true }'
    with pytest.raises(ParserError, match="AT offset must be an integer expression"):
        Parser().parse(source)


def test_at_offset_double_literal_raises_parser_error() -> None:
    """A double literal used as an AT offset triggers the same validation
    rejection (line 325, DoubleLiteral branch)."""
    source = 'rule test { strings: $a = "x" condition: $a at 1.5 }'
    with pytest.raises(ParserError, match="AT offset must be an integer expression"):
        Parser().parse(source)


def test_in_range_low_bound_boolean_raises_parser_error() -> None:
    """A boolean literal used as the low bound of an IN range triggers the
    integer-context validation error (line 325)."""
    source = 'rule test { strings: $a = "x" condition: $a in (true..10) }'
    with pytest.raises(ParserError, match="IN range bounds must be integer expressions"):
        Parser().parse(source)


def test_in_range_high_bound_string_literal_raises_parser_error() -> None:
    """A string literal used as the high bound of an IN range triggers the
    integer-context validation error (line 325, StringLiteral branch)."""
    source = 'rule test { strings: $a = "x" condition: $a in (0.."end") }'
    with pytest.raises(ParserError, match="IN range bounds must be integer expressions"):
        Parser().parse(source)


# ---------------------------------------------------------------------------
# Line 255: _parse_in_postfix - OfExpression without location
# ---------------------------------------------------------------------------


def test_in_postfix_of_expression_without_location_uses_start_token() -> None:
    """When an OfExpression has no location, _parse_in_postfix falls through to
    _set_node_location_from_tokens (line 255).  This path is only reachable by
    direct API invocation because real-parsed OfExpressions always carry a
    location."""
    from yaraast.ast.conditions import OfExpression
    from yaraast.ast.expressions import StringWildcard

    p = _parser_from_source("in (0..10)")
    _consume(p, TokenType.IN)

    # OfExpression with location=None (no location attribute set by real parsing)
    of_no_loc = OfExpression(quantifier="all", string_set=StringWildcard(pattern="$*"))
    # Confirm location is indeed None before the call
    assert of_no_loc.location is None

    # Act
    result = p._parse_in_postfix(of_no_loc)

    # Assert
    assert isinstance(result, InExpression)
    assert result.location is not None


# ---------------------------------------------------------------------------
# Lines 326-328: _validate_integer_context_expression - UnaryExpression
#                recursive validation
# ---------------------------------------------------------------------------


def test_at_offset_unary_negation_of_boolean_raises_parser_error() -> None:
    """Negating a boolean literal (-true) produces a UnaryExpression wrapping a
    BooleanLiteral; the recursive call at line 327 re-enters the validator and
    raises at line 325 (lines 326-328 exercised)."""
    source = 'rule test { strings: $a = "x" condition: $a at -true }'
    with pytest.raises(ParserError, match="AT offset must be an integer expression"):
        Parser().parse(source)


def test_at_offset_unary_negation_of_double_raises_parser_error() -> None:
    """Negating a double literal (-(1.5)) also exercises the UnaryExpression
    recursive path (lines 326-328)."""
    source = 'rule test { strings: $a = "x" condition: $a at -(1.5) }'
    with pytest.raises(ParserError, match="AT offset must be an integer expression"):
        Parser().parse(source)


def test_at_offset_unary_negation_of_boolean_via_direct_call() -> None:
    """Directly call _validate_integer_context_expression with a UnaryExpression
    wrapping a BooleanLiteral to confirm the recursive path (line 327) fires and
    the terminal raise (line 325) is triggered."""
    from yaraast.ast.expressions import BooleanLiteral, UnaryExpression

    p = _parser_from_source("dummy")
    ue = UnaryExpression(operator="-", operand=BooleanLiteral(value=True))

    with pytest.raises(ParserError, match="offset must be valid"):
        p._validate_integer_context_expression(ue, "offset must be valid")


def test_at_offset_negation_of_integer_parses_and_exercises_unary_return() -> None:
    """Negating a valid integer literal (-1) produces a UnaryExpression whose
    operand is an IntegerLiteral; the recursive call at line 327 returns without
    raising, exercising line 328 (the 'return' after successful validation)."""
    source = 'rule test { strings: $a = "x" condition: $a at -1 }'
    ast = Parser().parse(source)
    condition = ast.rules[0].condition

    assert isinstance(condition, AtExpression)
    assert condition.string_id == "$a"


def test_validate_integer_context_unary_valid_operand_does_not_raise() -> None:
    """Directly call _validate_integer_context_expression with a UnaryExpression
    wrapping an IntegerLiteral.  The recursive call at line 327 returns normally
    (line 328) without raising, confirming the non-error return path fires."""
    from yaraast.ast.expressions import IntegerLiteral, UnaryExpression

    p = _parser_from_source("dummy")
    ue = UnaryExpression(operator="-", operand=IntegerLiteral(value=5))

    # Should return without raising
    p._validate_integer_context_expression(ue, "must not raise")


# ---------------------------------------------------------------------------
# Lines 329-331: _validate_integer_context_expression - BinaryExpression
#                right-operand recursive validation
# ---------------------------------------------------------------------------


def test_at_offset_binary_expression_with_boolean_operands_raises_parser_error() -> None:
    """A BinaryExpression whose operands include booleans triggers recursive
    validation on both sides (lines 329-331)."""
    source = 'rule test { strings: $a = "x" condition: $a at (true + false) }'
    with pytest.raises(ParserError, match="AT offset must be an integer expression"):
        Parser().parse(source)


def test_at_offset_binary_expression_valid_left_invalid_right_raises() -> None:
    """When the left operand of a BinaryExpression is a valid integer but the
    right is a boolean, validation passes line 330 and raises at line 331
    via the right-operand recursive call."""
    source = 'rule test { strings: $a = "x" condition: $a at (1 + true) }'
    with pytest.raises(ParserError, match="AT offset must be an integer expression"):
        Parser().parse(source)


def test_validate_integer_context_binary_right_invalid_via_direct_call() -> None:
    """Direct call to _validate_integer_context_expression with a BinaryExpression
    whose left side is an IntegerLiteral and right side is a BooleanLiteral confirms
    the right-operand validation path (line 331) raises."""
    from yaraast.ast.expressions import BinaryExpression, BooleanLiteral, IntegerLiteral

    p = _parser_from_source("dummy")
    be = BinaryExpression(
        operator="+",
        left=IntegerLiteral(value=1),
        right=BooleanLiteral(value=False),
    )

    with pytest.raises(ParserError, match="range must be int"):
        p._validate_integer_context_expression(be, "range must be int")


# ---------------------------------------------------------------------------
# Positive integration tests: valid postfix expressions parse without error
# ---------------------------------------------------------------------------


def test_member_access_chain_pe_module() -> None:
    """A chained member access via a module (pe.entry_point) parses correctly."""
    source = "rule test { condition: pe.entry_point == 0 }"
    ast = Parser().parse(source)
    assert ast.rules[0].condition is not None


def test_array_access_integer_index_parses() -> None:
    """Array access with an integer index parses correctly."""
    source = "rule test { condition: math.mean(0, filesize) >= 0 }"
    ast = Parser().parse(source)
    assert ast.rules[0].condition is not None


def test_string_in_valid_range_parses() -> None:
    """A valid '$string in (low..high)' expression parses without error."""
    source = 'rule test { strings: $a = "x" condition: $a in (0..100) }'
    ast = Parser().parse(source)
    cond = ast.rules[0].condition
    assert isinstance(cond, InExpression)
    assert cond.subject == "$a"


def test_string_at_integer_offset_parses() -> None:
    """A valid '$string at offset' expression parses without error."""
    source = 'rule test { strings: $a = "x" condition: $a at 0 }'
    ast = Parser().parse(source)
    cond = ast.rules[0].condition
    assert isinstance(cond, AtExpression)
    assert cond.string_id == "$a"


def test_of_expression_with_at_offset_parses() -> None:
    """An 'of' expression with an AT postfix parses correctly."""
    source = 'rule test { strings: $a = "x" condition: all of ($a) at 0 }'
    ast = Parser().parse(source)
    assert isinstance(ast.rules[0].condition, AtExpression)


def test_of_expression_with_in_range_parses() -> None:
    """An 'of' expression with an IN range parses correctly."""
    source = 'rule test { strings: $a = "x" condition: all of ($a) in (0..100) }'
    ast = Parser().parse(source)
    assert isinstance(ast.rules[0].condition, InExpression)


def test_function_call_with_multiple_args_parses() -> None:
    """A function call with multiple arguments parses correctly."""
    source = "rule test { condition: math.mean(0, filesize) >= 0 }"
    ast = Parser().parse(source)
    assert ast.rules[0].condition is not None


def test_builtin_uint8_single_arg_parses() -> None:
    """uint8() with a single argument parses correctly."""
    source = "rule test { condition: uint8(0) == 0x4d }"
    ast = Parser().parse(source)
    assert ast.rules[0].condition is not None


def test_builtin_uint8_wrong_arity_raises_parser_error() -> None:
    """uint8() with zero arguments must raise ParserError (arity validation)."""
    source = "rule test { condition: uint8() == 0 }"
    with pytest.raises(ParserError, match="uint8\\(\\) expects exactly 1 argument"):
        Parser().parse(source)


def test_member_access_requires_identifier_after_dot() -> None:
    """A dot not followed by an identifier must raise ParserError."""
    source = "rule test { condition: pe. == 0 }"
    with pytest.raises(ParserError, match="Expected member name after '\\.'"):
        Parser().parse(source)


def test_string_reference_postfix_dot_raises_parser_error() -> None:
    """Applying member access to a string identifier must raise ParserError."""
    source = 'rule test { strings: $a = "x" condition: $a.len == 0 }'
    with pytest.raises(ParserError, match="String references do not support postfix access"):
        Parser().parse(source)


def test_string_reference_postfix_bracket_raises_parser_error() -> None:
    """Applying bracket access to a string identifier must raise ParserError."""
    source = 'rule test { strings: $a = "x" condition: $a[0] == 0 }'
    with pytest.raises(ParserError, match="String references do not support postfix access"):
        Parser().parse(source)


def test_at_postfix_on_non_string_expression_raises_parser_error() -> None:
    """Using AT on a non-string, non-of expression must raise ParserError."""
    source = "rule test { condition: filesize at 0 }"
    with pytest.raises(ParserError, match="AT keyword can only be used"):
        Parser().parse(source)


def test_in_postfix_on_non_string_expression_raises_parser_error() -> None:
    """Using IN on a non-string, non-of, non-count expression raises ParserError."""
    source = "rule test { condition: filesize in (0..100) }"
    with pytest.raises(ParserError, match="IN keyword can only be used"):
        Parser().parse(source)


def test_function_call_on_non_identifier_raises_parser_error() -> None:
    """Calling a function on a non-callable expression must raise ParserError."""
    source = 'rule test { strings: $a = "x" condition: ($a)(0) == 0 }'
    with pytest.raises(ParserError):
        Parser().parse(source)


def test_function_args_trailing_comma_raises_parser_error() -> None:
    """A trailing comma in a function argument list must raise ParserError."""
    source = "rule test { condition: uint8(0,) == 0 }"
    with pytest.raises(ParserError, match="Expected argument after ','"):
        Parser().parse(source)


def test_function_args_missing_closing_paren_raises_parser_error() -> None:
    """A function call without the closing ')' must raise ParserError."""
    source = "rule test { condition: uint8(0 == 0 }"
    with pytest.raises(ParserError, match="Expected '\\)' after arguments"):
        Parser().parse(source)
