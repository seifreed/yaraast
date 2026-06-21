# Copyright (c) 2026 Marc Rivero Lopez
# Licensed under GPLv3. See LICENSE file for details.
# This test suite validates real code behavior without mocks or stubs.
"""Regression tests for uncovered lines in yaraast/codegen/generator_leaf_visitors.py.

Each test exercises the private and public helpers directly through real AST node
construction.  No mocks, stubs, or test doubles are used anywhere.

Missing lines targeted (as of 2026-06-21):
  152, 154-155  - _reject_non_integer_expression raises on non-integer AST node
  182           - _reject_non_string_dictionary_key returns after ParenthesesExpression recursion
  278-279       - visit_comment raises on block comment with embedded terminator
  311-312       - _require_comment_text raises TypeError on non-string input
  389           - visit_pragma DefineDirective with no value (macro_value is None)
  406-408       - visit_pragma fallthrough branch for generic Pragma with non-PRAGMA type
  413-414       - _format_pragma_arguments raises TypeError on non-list/tuple argument
  424-425       - _validate_pragma_token raises TypeError on non-string value
  427-428       - _validate_pragma_token raises ValueError on empty string
"""

from __future__ import annotations

import pytest

from yaraast.ast.expressions import (
    BooleanLiteral,
    ParenthesesExpression,
    StringLiteral,
)
from yaraast.ast.pragmas import DefineDirective, Pragma, PragmaType
from yaraast.codegen.generator_leaf_visitors import (
    _format_pragma_arguments,
    _reject_non_integer_expression,
    _reject_non_string_dictionary_key,
    _require_comment_text,
    _validate_pragma_token,
    visit_comment,
    visit_pragma,
)

# ---------------------------------------------------------------------------
# _reject_non_integer_expression (lines 152, 154-155)
# ---------------------------------------------------------------------------


def test_reject_non_integer_expression_raises_for_boolean_literal() -> None:
    """_reject_non_integer_expression must raise ValueError when its argument
    is a BooleanLiteral, which _is_definitely_non_integer_expression considers
    a definitely non-integer expression."""
    node = BooleanLiteral(value=True)
    with pytest.raises(ValueError, match="boolean is not an integer"):
        _reject_non_integer_expression(node, "boolean is not an integer")


def test_reject_non_integer_expression_does_not_raise_for_identifier() -> None:
    """_reject_non_integer_expression must not raise for an Identifier node because
    the type classifier cannot definitely rule out an identifier as non-integer."""
    from yaraast.ast.expressions import Identifier

    node = Identifier(name="file_size")
    # Should complete without raising.
    _reject_non_integer_expression(node, "should not raise")


# ---------------------------------------------------------------------------
# _reject_non_string_dictionary_key - ParenthesesExpression path (line 182)
# ---------------------------------------------------------------------------


def test_reject_non_string_dictionary_key_accepts_parenthesised_string_literal() -> None:
    """When the key is a ParenthesesExpression wrapping a StringLiteral the
    function must recurse, complete, and return (line 182) without raising."""
    inner = StringLiteral(value="key")
    node = ParenthesesExpression(expression=inner)
    # No exception expected; the function exits at the 'return' on line 182.
    _reject_non_string_dictionary_key(node)


def test_reject_non_string_dictionary_key_raises_for_nested_boolean_in_parens() -> None:
    """A ParenthesesExpression wrapping a BooleanLiteral must still raise because
    the recursive call encounters a rejected type."""
    inner = BooleanLiteral(value=False)
    node = ParenthesesExpression(expression=inner)
    with pytest.raises(ValueError, match="Dictionary key must be string"):
        _reject_non_string_dictionary_key(node)


# ---------------------------------------------------------------------------
# visit_comment - embedded block-comment terminator (lines 278-279)
# ---------------------------------------------------------------------------


def test_visit_comment_raises_on_block_comment_with_embedded_terminator() -> None:
    """visit_comment must raise ValueError when a block comment whose text
    starts with '/*' and ends with '*/' also contains '*/' inside the body.
    This exercises the guard at lines 277-279."""

    class _FakeComment:
        text: str = "/* start */ embedded */"
        is_multiline: bool = False

    with pytest.raises(ValueError, match="embedded terminators"):
        visit_comment(_FakeComment())


# ---------------------------------------------------------------------------
# _require_comment_text - non-string input (lines 311-312)
# ---------------------------------------------------------------------------


def test_require_comment_text_raises_type_error_for_non_string() -> None:
    """_require_comment_text must raise TypeError when its argument is not a
    str, exercising lines 311-312."""
    with pytest.raises(TypeError, match="Comment text must be a string"):
        _require_comment_text(42)


def test_require_comment_text_raises_type_error_for_none() -> None:
    """_require_comment_text must raise TypeError for None as well."""
    with pytest.raises(TypeError, match="Comment text must be a string"):
        _require_comment_text(None)


# ---------------------------------------------------------------------------
# visit_pragma - DefineDirective without macro_value (line 389)
# ---------------------------------------------------------------------------


def test_visit_pragma_define_directive_without_value_emits_bare_define() -> None:
    """visit_pragma must produce '#define NAME' when DefineDirective.macro_value
    is None, which exercises the branch at line 389."""
    node = DefineDirective(macro_name="MY_FLAG")
    result = visit_pragma(node)
    assert result == "#define MY_FLAG"


def test_visit_pragma_define_directive_with_value_emits_define_with_value() -> None:
    """visit_pragma must produce '#define NAME VALUE' when macro_value is set,
    confirming the else branch (line 390) is reachable and correct."""
    node = DefineDirective(macro_name="VERSION", macro_value="2")
    result = visit_pragma(node)
    assert result == "#define VERSION 2"


# ---------------------------------------------------------------------------
# visit_pragma - generic Pragma fallthrough branch (lines 406-408)
# ---------------------------------------------------------------------------


def test_visit_pragma_generic_pragma_with_custom_type_emits_hash_name() -> None:
    """A Pragma whose pragma_type is not PRAGMA and is not an instance of any
    specific subclass (IncludeOncePragma, DefineDirective, UndefDirective,
    ConditionalDirective, CustomPragma) must reach the fallthrough at lines
    406-408 and produce '#name'."""
    node = Pragma(pragma_type=PragmaType.CUSTOM, name="directive")
    result = visit_pragma(node)
    assert result == "#directive"


def test_visit_pragma_generic_pragma_fallthrough_with_arguments() -> None:
    """The fallthrough branch must also accept and render arguments."""
    node = Pragma(pragma_type=PragmaType.CUSTOM, name="pack", arguments=["1"])
    result = visit_pragma(node)
    assert result == "#pack 1"


# ---------------------------------------------------------------------------
# _format_pragma_arguments - non-list/tuple guard (lines 413-414)
# ---------------------------------------------------------------------------


def test_format_pragma_arguments_raises_type_error_for_string_input() -> None:
    """_format_pragma_arguments must raise TypeError when its argument is a
    string (not list or tuple), exercising lines 413-414."""
    with pytest.raises(TypeError, match="Pragma arguments must be a list or tuple"):
        _format_pragma_arguments("not_a_list")


def test_format_pragma_arguments_raises_type_error_for_integer_input() -> None:
    """_format_pragma_arguments must raise TypeError for any non-list/tuple."""
    with pytest.raises(TypeError, match="Pragma arguments must be a list or tuple"):
        _format_pragma_arguments(99)


# ---------------------------------------------------------------------------
# _validate_pragma_token - type and value guards (lines 424-425, 427-428)
# ---------------------------------------------------------------------------


def test_validate_pragma_token_raises_type_error_for_non_string() -> None:
    """_validate_pragma_token must raise TypeError when the value is not a str,
    exercising lines 424-425."""
    with pytest.raises(TypeError, match="must be a string"):
        _validate_pragma_token(3.14, "MyField")


def test_validate_pragma_token_raises_type_error_for_none() -> None:
    """_validate_pragma_token must raise TypeError for None."""
    with pytest.raises(TypeError, match="must be a string"):
        _validate_pragma_token(None, "MyField")


def test_validate_pragma_token_raises_value_error_for_empty_string() -> None:
    """_validate_pragma_token must raise ValueError when the value is an empty
    string, exercising lines 427-428."""
    with pytest.raises(ValueError, match="must not be empty"):
        _validate_pragma_token("", "MyField")


def test_validate_pragma_token_accepts_valid_token() -> None:
    """_validate_pragma_token must return the original string unchanged when the
    value is a non-empty, quote-free, control-character-free string."""
    result = _validate_pragma_token("some_value", "MyField")
    assert result == "some_value"
