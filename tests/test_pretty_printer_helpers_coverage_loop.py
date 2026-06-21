# Copyright (c) 2026 Marc Rivero López
# Licensed under GPLv3. See LICENSE file for details.
# This test suite validates real code behavior without mocks or stubs.
"""
Regression tests that drive previously uncovered lines in
yaraast/codegen/pretty_printer_helpers.py to 100%.

Every test calls real production functions with real AST nodes and asserts
on actual return values or raised exceptions.  No mocking frameworks are used.
"""

from __future__ import annotations

from typing import cast

import pytest

from yaraast.ast.base import YaraFile
from yaraast.ast.expressions import BinaryExpression, BooleanLiteral, Identifier
from yaraast.ast.meta import Meta
from yaraast.ast.rules import Rule
from yaraast.ast.strings import (
    HexAlternative,
    HexByte,
    HexJump,
    HexNegatedByte,
    HexNibble,
    HexString,
    HexWildcard,
    PlainString,
    RegexString,
)
from yaraast.codegen.pretty_printer import PrettyPrintOptions
from yaraast.codegen.pretty_printer_helpers import (
    _coerce_hex_alternative_branch,
    _format_hex_token,
    build_hex_pattern,
    calculate_meta_alignment_column,
    calculate_string_alignment_column,
    expression_to_string,
    format_plain_string,
    format_regex_string,
)
from yaraast.yarax.ast_nodes import (
    ArrayComprehension,
    DictComprehension,
    LambdaExpression,
    TupleExpression,
)

# ---------------------------------------------------------------------------
# _format_hex_token — all token-type branches
# ---------------------------------------------------------------------------


def test_format_hex_token_int_str_inside_alternative_list() -> None:
    """
    Line 65: the int|str branch of _format_hex_token.

    The path is reached when _coerce_hex_alternative_branch returns a list
    that was already a list (not wrapped), and the list contains bare int or
    str values.  build_hex_pattern calls _format_hex_token on each nested
    token after the coercion, so a list-of-ints alternative hits line 65.
    """
    # alternatives is a list whose items are themselves lists of ints
    alt = HexAlternative(alternatives=[[0x41, 0x42], [0x43]])
    result = build_hex_pattern(
        HexString(identifier="$t", tokens=[HexByte(0x4D), alt]),
        hex_uppercase=True,
        hex_spacing=True,
    )
    assert result == "4D (41 42 | 43)"


def test_format_hex_token_hex_wildcard() -> None:
    """Line 68-69: HexWildcard branch always returns '??'."""
    result = build_hex_pattern(
        HexString(identifier="$t", tokens=[HexByte(0x4D), HexWildcard()]),
        hex_uppercase=True,
        hex_spacing=True,
    )
    assert result == "4D ??"


def test_format_hex_token_hex_jump() -> None:
    """
    Lines 70-71 + 105-106: HexJump branch delegates to _format_hex_jump.

    A jump must appear between two bytes (not at the start or end of a
    top-level token list) to pass validate_hex_string_tokens.
    """
    result = build_hex_pattern(
        HexString(
            identifier="$t",
            tokens=[HexByte(0x4D), HexJump(min_jump=1, max_jump=4), HexByte(0x5A)],
        ),
        hex_uppercase=True,
        hex_spacing=True,
    )
    assert result == "4D [1-4] 5A"


def test_format_hex_token_hex_negated_byte_uppercase() -> None:
    """Lines 72-77: HexNegatedByte branch with uppercase=True."""
    result = build_hex_pattern(
        HexString(identifier="$t", tokens=[HexNegatedByte(0x4D)]),
        hex_uppercase=True,
        hex_spacing=True,
    )
    assert result == "~4D"


def test_format_hex_token_hex_negated_byte_lowercase() -> None:
    """Lines 72-77: HexNegatedByte branch with uppercase=False exercises _format_hex_byte_value."""
    result = build_hex_pattern(
        HexString(identifier="$t", tokens=[HexNegatedByte(0x4D)]),
        hex_uppercase=False,
        hex_spacing=True,
    )
    assert result == "~4d"


def test_format_hex_token_hex_nibble_high() -> None:
    """
    Lines 78-80: HexNibble branch.

    high=True means the nibble is the upper half of the byte, rendered as 'N?'.
    """
    result = build_hex_pattern(
        HexString(identifier="$t", tokens=[HexNibble(high=True, value=4)]),
        hex_uppercase=True,
        hex_spacing=True,
    )
    assert result == "4?"


def test_format_hex_token_hex_nibble_low() -> None:
    """Lines 78-80 + 101-102: HexNibble with high=False renders as '?N'."""
    result = build_hex_pattern(
        HexString(identifier="$t", tokens=[HexNibble(high=False, value=4)]),
        hex_uppercase=True,
        hex_spacing=True,
    )
    assert result == "?4"


def test_format_hex_token_hex_alternative_no_spacing() -> None:
    """
    Lines 81-92: HexAlternative branch with hex_spacing=False.

    Both separator (between nested tokens within one alternative) and
    alt_separator (between alternatives) are empty/compact.
    """
    alt = HexAlternative(alternatives=[[HexByte(0x41), HexByte(0x42)], [HexByte(0x43)]])
    result = build_hex_pattern(
        HexString(identifier="$t", tokens=[HexByte(0x4D), alt]),
        hex_uppercase=True,
        hex_spacing=False,
    )
    assert result == "4D(4142|43)"


def test_format_hex_token_unsupported_type_raises_type_error() -> None:
    """
    Line 93-94: the fallthrough TypeError.

    validate_hex_string_tokens rejects unknown tokens at the top level, so
    the only way to reach line 94 is to call _format_hex_token directly with
    a type not matched by any isinstance guard.
    """

    class _Unknown:
        pass

    with pytest.raises(TypeError, match="Unsupported hex token '_Unknown' for libyara output"):
        _format_hex_token(cast(int, _Unknown()), True, True)


# ---------------------------------------------------------------------------
# _coerce_hex_alternative_branch — non-list (scalar) path
# ---------------------------------------------------------------------------


def test_coerce_hex_alternative_branch_scalar_wraps_in_hex_byte() -> None:
    """
    Lines 110-112: when the alternative is not a list, it is wrapped in
    [HexByte(value)].  The scalar int path through HexAlternative.alternatives
    exercises this branch.
    """
    # _coerce returns [HexByte(0x41)] for scalar 0x41
    coerced = _coerce_hex_alternative_branch(0x41)
    assert len(coerced) == 1
    assert isinstance(coerced[0], HexByte)
    assert coerced[0].value == 0x41


def test_build_hex_pattern_alternative_with_scalar_alternatives() -> None:
    """
    End-to-end: scalar int alternatives in HexAlternative go through
    _coerce_hex_alternative_branch non-list path and then the HexByte branch.
    """
    alt = HexAlternative(alternatives=[0x41, 0x43])
    result = build_hex_pattern(
        HexString(identifier="$t", tokens=[HexByte(0x4D), alt]),
        hex_uppercase=False,
        hex_spacing=True,
    )
    assert result == "4d (41 | 43)"


# ---------------------------------------------------------------------------
# format_plain_string — zero-padding branch
# ---------------------------------------------------------------------------


def test_format_plain_string_no_padding() -> None:
    """Line 122: the else branch when padding is zero."""
    result = format_plain_string(PlainString("$a", value="hello"), quote='"', padding=0)
    assert result == '$a = "hello"'


def test_format_plain_string_with_padding() -> None:
    """Line 121: the if branch when padding is positive (existing coverage; kept for contrast)."""
    result = format_plain_string(PlainString("$a", value="hello"), quote='"', padding=3)
    assert result == '$a    = "hello"'


# ---------------------------------------------------------------------------
# format_regex_string — zero-padding branch
# ---------------------------------------------------------------------------


def test_format_regex_string_no_padding() -> None:
    """Line 130: the else branch when padding is zero."""
    result = format_regex_string(RegexString("$r", regex="ab.*"), padding=0)
    assert result == "$r = /ab.*/"


# ---------------------------------------------------------------------------
# calculate_string_alignment_column — branch coverage
# ---------------------------------------------------------------------------


def test_calculate_string_alignment_column_with_strings() -> None:
    """
    Line 166 (inner loop body): max_length is updated when a rule has strings.
    The longest identifier name drives the column.
    """
    ast = YaraFile(
        rules=[
            Rule(
                name="r",
                strings=[
                    PlainString("$abc", value="x"),
                    PlainString("$de", value="y"),
                ],
                condition=BooleanLiteral(True),
            )
        ]
    )
    col = calculate_string_alignment_column(ast)
    # output_string_identifier('$abc') has length 4; max_length=4; result=5
    assert col == 5


def test_calculate_string_alignment_column_no_strings() -> None:
    """
    Branch 180->179 (skip inner loop when rule.strings is empty):
    rules without strings contribute nothing to max_length.
    """
    ast = YaraFile(rules=[Rule(name="r", condition=BooleanLiteral(True))])
    col = calculate_string_alignment_column(ast)
    # max_length stays 0; result is 0+1=1
    assert col == 1


# ---------------------------------------------------------------------------
# calculate_meta_alignment_column — rule.meta is None branch
# ---------------------------------------------------------------------------


def test_calculate_meta_alignment_column_rule_without_meta() -> None:
    """
    Line 178: the 'continue' branch when rule.meta is None.

    The Rule constructor defaults meta to [] (not None).  Assigning None
    after construction is the only way to reach line 178, which represents
    a rule object that has had its meta cleared externally.
    """
    rule = Rule(name="r", condition=BooleanLiteral(True))
    rule.meta = None  # force None so the `if rule.meta is None: continue` fires
    ast = YaraFile(rules=[rule])
    col = calculate_meta_alignment_column(ast, min_alignment_column=10)
    assert col == 10


def test_calculate_meta_alignment_column_with_meta() -> None:
    """
    Lines 179-182: the loop body when rule.meta is not None; max_length is
    driven by the longest key.
    """
    ast = YaraFile(
        rules=[
            Rule(
                name="r",
                meta=[Meta("author", "me")],
                condition=BooleanLiteral(True),
            )
        ]
    )
    col = calculate_meta_alignment_column(ast, min_alignment_column=5)
    # 'author =' = 8 chars; +2 = 10; max(10, 5) = 10
    assert col == 10


# ---------------------------------------------------------------------------
# expression_to_string — visit_binary_expression compact word-operator branch
# ---------------------------------------------------------------------------


def test_calculate_meta_alignment_column_entry_without_key_attribute() -> None:
    """
    Branch 180->179: hasattr(entry, 'key') is False for an entry that lacks
    the 'key' attribute.

    When rule.meta is a raw dict, validate_rule_meta processes it and returns
    early (dict path), so the subsequent 'for entry in rule.meta' loop in
    calculate_meta_alignment_column iterates over the dict's string keys.
    Plain strings have no 'key' attribute, so the if-body is skipped and
    max_length stays zero, returning min_alignment_column.
    """

    class _FakeRule:
        """Rule-like object carrying a plain dict as meta."""

        strings: list[object] = []
        meta: object

        def __init__(self) -> None:
            self.meta = {"author": "me"}

    class _FakeAST:
        rules: list[object]

    fake_ast = _FakeAST()
    fake_ast.rules = [_FakeRule()]
    col = calculate_meta_alignment_column(fake_ast, min_alignment_column=20)
    assert col == 20


# ---------------------------------------------------------------------------
# expression_to_string — visit_set_expression
# ---------------------------------------------------------------------------


def test_expression_to_string_set_expression() -> None:
    """
    Lines 220-222: visit_set_expression uses comma separator and wraps in
    parentheses.
    """
    from yaraast.ast.expressions import SetExpression

    expr = SetExpression([Identifier("a"), Identifier("b")])
    result = expression_to_string(expr, PrettyPrintOptions())
    assert result == "(a, b)"


def test_expression_to_string_set_expression_compact_commas() -> None:
    """Lines 220-222: set expression with space_after_comma=False."""
    from yaraast.ast.expressions import SetExpression

    expr = SetExpression([Identifier("a"), Identifier("b")])
    result = expression_to_string(expr, PrettyPrintOptions(space_after_comma=False))
    assert result == "(a,b)"


def test_expression_to_string_compact_word_operator_keeps_spaces() -> None:
    """
    Lines 220-222: when space_around_operators=False and the operator is a
    word operator (e.g. 'and'), a space separator is still used.
    """
    opts = PrettyPrintOptions(space_around_operators=False)
    expr = BinaryExpression(Identifier("a"), "and", Identifier("b"))
    result = expression_to_string(expr, opts)
    assert result == "a and b"


def test_expression_to_string_compact_symbolic_operator_no_spaces() -> None:
    """
    Lines 215-216: when space_around_operators=False and the operator is
    symbolic (e.g. '=='), no spaces are inserted.
    """
    opts = PrettyPrintOptions(space_around_operators=False)
    expr = BinaryExpression(Identifier("a"), "==", Identifier("b"))
    result = expression_to_string(expr, opts)
    assert result == "a==b"


# ---------------------------------------------------------------------------
# expression_to_string — visit_array_comprehension
# ---------------------------------------------------------------------------


def test_expression_to_string_array_comprehension_without_condition() -> None:
    """Lines 256-267 (no-condition branch): array comprehension without an if clause."""
    ac = ArrayComprehension(
        expression=Identifier("x"),
        variable="x",
        iterable=Identifier("items"),
        condition=None,
    )
    result = expression_to_string(ac, PrettyPrintOptions())
    assert result == "[x for x in items]"


def test_expression_to_string_array_comprehension_with_condition() -> None:
    """Lines 265-266: array comprehension with an if clause appends the condition."""
    ac = ArrayComprehension(
        expression=Identifier("x"),
        variable="x",
        iterable=Identifier("items"),
        condition=Identifier("pred"),
    )
    result = expression_to_string(ac, PrettyPrintOptions())
    assert result == "[x for x in items if pred]"


# ---------------------------------------------------------------------------
# expression_to_string — visit_dict_comprehension branches
# ---------------------------------------------------------------------------


def test_expression_to_string_dict_comprehension_single_variable() -> None:
    """
    Lines 256-267 (dict variant) + branch 273->276: when value_variable is None,
    only the key variable appears in the for clause.
    """
    dc = DictComprehension(
        key_expression=Identifier("k"),
        value_expression=Identifier("v"),
        key_variable="k",
        value_variable=None,
        iterable=Identifier("items"),
        condition=None,
    )
    result = expression_to_string(dc, PrettyPrintOptions())
    assert result == "{k: v for k in items}"


def test_expression_to_string_dict_comprehension_with_condition() -> None:
    """
    Line 291: dict comprehension with an if clause; the condition text is appended.
    Also covers value_variable path (lines 274-275).
    """
    dc = DictComprehension(
        key_expression=Identifier("k"),
        value_expression=Identifier("v"),
        key_variable="k",
        value_variable="v",
        iterable=Identifier("items"),
        condition=Identifier("pred"),
    )
    result = expression_to_string(dc, PrettyPrintOptions())
    assert result == "{k: v for k, v in items if pred}"


# ---------------------------------------------------------------------------
# expression_to_string — visit_tuple_expression branches
# ---------------------------------------------------------------------------


def test_expression_to_string_tuple_empty() -> None:
    """Line 297: empty TupleExpression returns '()'."""
    result = expression_to_string(TupleExpression([]), PrettyPrintOptions())
    assert result == "()"


def test_expression_to_string_tuple_single_element() -> None:
    """Line 300: single-element tuple appends a trailing comma."""
    result = expression_to_string(TupleExpression([Identifier("x")]), PrettyPrintOptions())
    assert result == "(x,)"


def test_expression_to_string_tuple_multiple_elements() -> None:
    """
    Lines 301-302: multi-element tuple uses the comma separator.
    This path was already partially covered; verified here for completeness.
    """
    result = expression_to_string(
        TupleExpression([Identifier("a"), Identifier("b")]), PrettyPrintOptions()
    )
    assert result == "(a, b)"


# ---------------------------------------------------------------------------
# expression_to_string — visit_lambda_expression no-parameter branch
# ---------------------------------------------------------------------------


def test_expression_to_string_lambda_no_parameters() -> None:
    """Line 335: lambda with no parameters renders as 'lambda: <body>'."""
    le = LambdaExpression([], Identifier("x"))
    result = expression_to_string(le, PrettyPrintOptions())
    assert result == "lambda: x"


def test_expression_to_string_lambda_with_parameters() -> None:
    """
    Lines 326-334 (parameters present): lambda with parameters uses the
    with-parameters branch for contrast with the no-parameter case.
    """
    le = LambdaExpression(["a", "b"], Identifier("a"))
    result = expression_to_string(le, PrettyPrintOptions())
    assert result == "lambda a, b: a"
