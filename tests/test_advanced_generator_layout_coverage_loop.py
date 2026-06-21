# Copyright (c) 2026 Marc Rivero López
# Licensed under GPLv3. See LICENSE file for details.
# This test suite validates real code behavior without mocks or stubs.
"""
Coverage-push tests for yaraast/codegen/advanced_generator_layout.py.

Every test executes real production code with real AST nodes and real
FormattingConfig objects.  No mocks, no stubs, no suppressions.

Targeted uncovered lines (baseline 88.22 %):
  211->exit, 228, 243-245, 254-262, 265-266, 269-278, 281-301,
  304-310, 313-323, 326-328, 331-340, 343, 351->356, 361, 365-374,
  381->384, 395-396
"""

from __future__ import annotations

import io

import pytest

from yaraast.ast.base import YaraFile
from yaraast.ast.expressions import (
    BinaryExpression,
    FunctionCall,
    Identifier,
    IntegerLiteral,
    ParenthesesExpression,
    SetExpression,
    StringLiteral,
)
from yaraast.ast.rules import Import, Rule
from yaraast.codegen.advanced_generator_layout import (
    _AdvancedConditionGenerator,
    generate_condition_string,
    write_wrapped_condition,
)
from yaraast.codegen.advanced_layout import AdvancedLayout
from yaraast.codegen.formatting import FormattingConfig, IndentStyle
from yaraast.codegen.generator import CodeGenerator
from yaraast.codegen.options import GeneratorOptions
from yaraast.yarax.ast_nodes import (
    ArrayComprehension,
    DictComprehension,
    DictExpression,
    DictItem,
    LambdaExpression,
    ListExpression,
    MatchCase,
    PatternMatch,
    SliceExpression,
    SpreadOperator,
    TupleExpression,
    TupleIndexing,
    WithDeclaration,
    WithStatement,
)

# ---------------------------------------------------------------------------
# Minimal helper that satisfies the interface expected by write_wrapped_condition
# without any mocking - it uses the real AdvancedLayout for _layout.config.
# ---------------------------------------------------------------------------


class _RealWriteCapture:
    """A write-capture that uses the real AdvancedLayout so config is authentic."""

    def __init__(self, config: FormattingConfig) -> None:
        self._layout = AdvancedLayout(config)
        self._indent_level = 0
        self.buffer = io.StringIO()

    def _get_indent(self) -> str:
        if self._layout.config.indent_style == IndentStyle.TABS:
            return "\t" * self._indent_level
        return " " * (self._layout.config.indent_size * self._indent_level)

    def _write(self, text: str) -> None:
        self.buffer.write(text)

    def _writeline(self, text: str = "") -> None:
        self.buffer.write(text + "\n")


# ===========================================================================
# write_wrapped_condition
# ===========================================================================


def test_write_wrapped_condition_multiline_input_writes_each_line() -> None:
    """
    Lines 187-190: when the condition string already contains newlines the
    function writes each split line individually.
    """
    gen = _RealWriteCapture(FormattingConfig())
    write_wrapped_condition(gen, "part_a\npart_b\npart_c")
    result = gen.buffer.getvalue()
    assert result == "part_a\npart_b\npart_c\n"


def test_write_wrapped_condition_short_condition_written_as_single_line() -> None:
    """
    Lines 193-195: a condition that fits within max_line_length is written as
    a single call to _writeline with no wrapping.
    """
    gen = _RealWriteCapture(FormattingConfig(max_line_length=120))
    write_wrapped_condition(gen, "filesize < 100KB")
    result = gen.buffer.getvalue()
    assert result == "filesize < 100KB\n"


def test_write_wrapped_condition_long_input_wraps_at_word_boundary_with_spaces() -> None:
    """
    Lines 197-212: a condition longer than max_line_length is wrapped at word
    boundaries.  The continuation indent uses spaces when indent_style is SPACES.
    Line 211 (if current_line) takes the True branch and writes the trailing word.
    """
    config = FormattingConfig(indent_style=IndentStyle.SPACES, indent_size=4, max_line_length=20)
    gen = _RealWriteCapture(config)
    write_wrapped_condition(gen, "word1 word2 word3 word4 word5")
    result = gen.buffer.getvalue()
    lines = result.rstrip("\n").split("\n")
    assert len(lines) >= 2
    assert lines[0].startswith("word")
    # The continuation indent must use spaces (4 spaces here).
    assert lines[1].startswith("    ")


def test_write_wrapped_condition_long_input_wraps_with_tab_indent() -> None:
    """
    Line 198: when indent_style is TABS the continuation indent is a single tab.
    """
    config = FormattingConfig(indent_style=IndentStyle.TABS, max_line_length=20)
    gen = _RealWriteCapture(config)
    write_wrapped_condition(gen, "word1 word2 word3 word4 word5")
    result = gen.buffer.getvalue()
    lines = result.rstrip("\n").split("\n")
    assert len(lines) >= 2
    assert lines[1].startswith("\t")


def test_write_wrapped_condition_empty_after_split_skips_final_writeline() -> None:
    """
    Line 211->exit (False branch): when the condition string consists only of
    whitespace and is longer than base_limit, split() returns an empty list so
    the loop body never runs, leaving current_line as ''.  The `if current_line`
    guard is False and no trailing _writeline is called.
    """
    # max_line_length=1 makes base_limit=max(1,1)=1; '   '.split() returns []
    config = FormattingConfig(max_line_length=1)
    gen = _RealWriteCapture(config)
    write_wrapped_condition(gen, "   ")
    # Nothing written because: no newlines, len > base_limit, split returns [],
    # current_line stays '' so line 211 takes the False branch.
    assert gen.buffer.getvalue() == ""


# ===========================================================================
# _AdvancedConditionGenerator._nested_indent
# ===========================================================================


def test_nested_indent_uses_tab_when_indent_style_is_tabs() -> None:
    """
    Line 228: the TABS branch of _nested_indent returns '\t'.
    """
    config = FormattingConfig(indent_style=IndentStyle.TABS)
    gen = _AdvancedConditionGenerator(config)
    assert gen._nested_indent() == "\t"


def test_nested_indent_uses_spaces_when_indent_style_is_spaces() -> None:
    """
    Line 229: the SPACES branch returns a string of spaces matching indent_size.
    """
    config = FormattingConfig(indent_style=IndentStyle.SPACES, indent_size=2)
    gen = _AdvancedConditionGenerator(config)
    assert gen._nested_indent() == "  "


# ===========================================================================
# _AdvancedConditionGenerator.visit_set_expression  (lines 243-245)
# ===========================================================================


def test_visit_set_expression_with_space_after_comma() -> None:
    """
    Lines 243-245: set expression elements joined by comma-space separator.
    """
    config = FormattingConfig(space_after_comma=True)
    gen = _AdvancedConditionGenerator(config)
    node = SetExpression(elements=[IntegerLiteral(1), IntegerLiteral(2), IntegerLiteral(3)])
    result = gen.visit_set_expression(node)
    assert result == "(1, 2, 3)"


def test_visit_set_expression_without_space_after_comma() -> None:
    """
    Lines 243-245: set expression elements joined by comma only when
    space_after_comma is False.
    """
    config = FormattingConfig(space_after_comma=False)
    gen = _AdvancedConditionGenerator(config)
    node = SetExpression(elements=[IntegerLiteral(1), IntegerLiteral(2)])
    result = gen.visit_set_expression(node)
    assert result == "(1,2)"


# ===========================================================================
# _AdvancedConditionGenerator.visit_function_call  (lines 247-251)
# ===========================================================================


def test_visit_function_call_with_space_after_comma() -> None:
    """
    Lines 247-251: function call arguments joined with comma-space.
    """
    config = FormattingConfig(space_after_comma=True)
    gen = _AdvancedConditionGenerator(config)
    node = FunctionCall(function="uint8", arguments=[IntegerLiteral(0)])
    result = gen.visit_function_call(node)
    assert result == "uint8(0)"


def test_visit_function_call_multiple_args_without_space_after_comma() -> None:
    """
    Lines 247-251: unqualified function call with space_after_comma=False uses
    comma-only separator between arguments.
    """
    config = FormattingConfig(space_after_comma=False)
    gen = _AdvancedConditionGenerator(config)
    node = FunctionCall(function="my_func", arguments=[IntegerLiteral(1), IntegerLiteral(2)])
    result = gen.visit_function_call(node)
    assert result == "my_func(1,2)"


# ===========================================================================
# _AdvancedConditionGenerator.visit_with_statement / visit_with_declaration
# (lines 253-266)
# ===========================================================================


def test_visit_with_declaration_renders_identifier_equals_value() -> None:
    """
    Lines 265-266: WithDeclaration renders as 'identifier = value'.
    """
    config = FormattingConfig()
    gen = _AdvancedConditionGenerator(config)
    node = WithDeclaration(identifier="x", value=IntegerLiteral(42))
    result = gen.visit_with_declaration(node)
    assert result == "x = 42"


def test_visit_with_statement_single_declaration() -> None:
    """
    Lines 254-262: WithStatement with a single declaration renders as
    'with <decl>: <body>'.
    """
    config = FormattingConfig()
    gen = _AdvancedConditionGenerator(config)
    decl = WithDeclaration(identifier="v", value=IntegerLiteral(10))
    node = WithStatement(declarations=[decl], body=Identifier("v"))
    result = gen.visit_with_statement(node)
    assert result == "with v = 10: v"


def test_visit_with_statement_multiple_declarations_with_space() -> None:
    """
    Lines 254-262: multiple declarations separated by comma-space when
    space_after_comma=True.
    """
    config = FormattingConfig(space_after_comma=True)
    gen = _AdvancedConditionGenerator(config)
    decl_a = WithDeclaration(identifier="a", value=IntegerLiteral(1))
    decl_b = WithDeclaration(identifier="b", value=IntegerLiteral(2))
    node = WithStatement(
        declarations=[decl_a, decl_b],
        body=BinaryExpression(left=Identifier("a"), operator="+", right=Identifier("b")),
    )
    result = gen.visit_with_statement(node)
    assert result == "with a = 1, b = 2: a + b"


def test_visit_with_statement_multiple_declarations_without_space() -> None:
    """
    Lines 254-262: multiple declarations joined by comma-only when
    space_after_comma=False.
    """
    config = FormattingConfig(space_after_comma=False)
    gen = _AdvancedConditionGenerator(config)
    decl_a = WithDeclaration(identifier="a", value=IntegerLiteral(1))
    decl_b = WithDeclaration(identifier="b", value=IntegerLiteral(2))
    node = WithStatement(
        declarations=[decl_a, decl_b],
        body=Identifier("a"),
    )
    result = gen.visit_with_statement(node)
    assert result == "with a = 1,b = 2: a"


# ===========================================================================
# _AdvancedConditionGenerator.visit_array_comprehension  (lines 269-278)
# ===========================================================================


def test_visit_array_comprehension_without_filter_condition() -> None:
    """
    Lines 269-278: ArrayComprehension without an optional condition renders
    '[<expr> for <var> in <iterable>]'.
    """
    config = FormattingConfig()
    gen = _AdvancedConditionGenerator(config)
    node = ArrayComprehension(
        expression=Identifier("x"),
        variable="x",
        iterable=Identifier("items"),
    )
    result = gen.visit_array_comprehension(node)
    assert result == "[x for x in items]"


def test_visit_array_comprehension_with_filter_condition() -> None:
    """
    Lines 269-278 (line 277): ArrayComprehension with a condition appends
    ' if <cond>' to the output.
    """
    config = FormattingConfig()
    gen = _AdvancedConditionGenerator(config)
    node = ArrayComprehension(
        expression=Identifier("x"),
        variable="x",
        iterable=Identifier("items"),
        condition=IntegerLiteral(1),
    )
    result = gen.visit_array_comprehension(node)
    assert result == "[x for x in items if 1]"


# ===========================================================================
# _AdvancedConditionGenerator.visit_dict_comprehension  (lines 281-301)
# ===========================================================================


def test_visit_dict_comprehension_key_only_no_condition() -> None:
    """
    Lines 281-301: DictComprehension with a single key variable and no filter
    renders '{k: v for k in items}'.
    """
    config = FormattingConfig()
    gen = _AdvancedConditionGenerator(config)
    node = DictComprehension(
        key_expression=Identifier("k"),
        value_expression=Identifier("v"),
        key_variable="k",
        value_variable=None,
        iterable=Identifier("items"),
    )
    result = gen.visit_dict_comprehension(node)
    assert result == "{k: v for k in items}"


def test_visit_dict_comprehension_key_value_with_condition() -> None:
    """
    Lines 281-301 (lines 289-291, 299-300): DictComprehension with both
    key_variable and value_variable and a filter condition.
    """
    config = FormattingConfig()
    gen = _AdvancedConditionGenerator(config)
    node = DictComprehension(
        key_expression=Identifier("k"),
        value_expression=Identifier("v"),
        key_variable="k",
        value_variable="v",
        iterable=Identifier("items"),
        condition=IntegerLiteral(1),
    )
    result = gen.visit_dict_comprehension(node)
    assert result == "{k: v for k, v in items if 1}"


def test_visit_dict_comprehension_key_value_without_condition() -> None:
    """
    Lines 281-301: DictComprehension with both key/value variables but no
    filter condition renders '{k: v for k, v in items}'.
    """
    config = FormattingConfig()
    gen = _AdvancedConditionGenerator(config)
    node = DictComprehension(
        key_expression=Identifier("k"),
        value_expression=Identifier("v"),
        key_variable="k",
        value_variable="v",
        iterable=Identifier("items"),
    )
    result = gen.visit_dict_comprehension(node)
    assert result == "{k: v for k, v in items}"


# ===========================================================================
# _AdvancedConditionGenerator.visit_tuple_expression  (lines 304-310)
# ===========================================================================


def test_visit_tuple_expression_empty_returns_unit_tuple() -> None:
    """
    Lines 304-306: empty TupleExpression renders as '()'.
    """
    config = FormattingConfig()
    gen = _AdvancedConditionGenerator(config)
    node = TupleExpression(elements=[])
    result = gen.visit_tuple_expression(node)
    assert result == "()"


def test_visit_tuple_expression_single_element_has_trailing_comma() -> None:
    """
    Lines 304-309: single-element TupleExpression renders as '(<elem>,)'.
    """
    config = FormattingConfig()
    gen = _AdvancedConditionGenerator(config)
    node = TupleExpression(elements=[IntegerLiteral(7)])
    result = gen.visit_tuple_expression(node)
    assert result == "(7,)"


def test_visit_tuple_expression_multiple_elements_separated_by_comma_space() -> None:
    """
    Lines 304-310: multi-element TupleExpression renders as '(e1, e2)' with
    space_after_comma=True.
    """
    config = FormattingConfig(space_after_comma=True)
    gen = _AdvancedConditionGenerator(config)
    node = TupleExpression(elements=[IntegerLiteral(1), IntegerLiteral(2)])
    result = gen.visit_tuple_expression(node)
    assert result == "(1, 2)"


def test_visit_tuple_expression_multiple_elements_no_space() -> None:
    """
    Lines 304-310: multi-element TupleExpression with space_after_comma=False.
    """
    config = FormattingConfig(space_after_comma=False)
    gen = _AdvancedConditionGenerator(config)
    node = TupleExpression(elements=[IntegerLiteral(1), IntegerLiteral(2)])
    result = gen.visit_tuple_expression(node)
    assert result == "(1,2)"


# ===========================================================================
# _AdvancedConditionGenerator.visit_tuple_indexing  (lines 313-323)
# ===========================================================================


def test_visit_tuple_indexing_function_call_target_no_extra_parens() -> None:
    """
    Lines 313-322: when the target is a FunctionCall the indexed expression
    renders without extra wrapping parentheses.
    """
    config = FormattingConfig()
    gen = _AdvancedConditionGenerator(config)
    fc = FunctionCall(function="uint8", arguments=[IntegerLiteral(0)])
    node = TupleIndexing(tuple_expr=fc, index=IntegerLiteral(1))
    result = gen.visit_tuple_indexing(node)
    assert result == "uint8(0)[1]"


def test_visit_tuple_indexing_tuple_expression_target_no_extra_parens() -> None:
    """
    Lines 313-322: when the target is a TupleExpression the expression renders
    as '<tuple>[<index>]' without extra parentheses.
    """
    config = FormattingConfig()
    gen = _AdvancedConditionGenerator(config)
    te = TupleExpression(elements=[IntegerLiteral(10), IntegerLiteral(20)])
    node = TupleIndexing(tuple_expr=te, index=IntegerLiteral(0))
    result = gen.visit_tuple_indexing(node)
    assert result == "(10, 20)[0]"


def test_visit_tuple_indexing_parentheses_expression_target_no_extra_parens() -> None:
    """
    Lines 313-322: ParenthesesExpression wrapping a TupleExpression is allowed
    as a target and renders without additional wrapping.
    """
    config = FormattingConfig()
    gen = _AdvancedConditionGenerator(config)
    te = TupleExpression(elements=[IntegerLiteral(1), IntegerLiteral(2)])
    pe = ParenthesesExpression(expression=te)
    node = TupleIndexing(tuple_expr=pe, index=IntegerLiteral(0))
    result = gen.visit_tuple_indexing(node)
    assert result == "(1, 2)[0]"


def test_visit_tuple_indexing_invalid_target_raises_value_error() -> None:
    """
    Lines 313-323: validate_tuple_indexing_target raises ValueError for targets
    that are neither FunctionCall nor TupleExpression at normalisation time.
    Line 323 (the else-branch that would add wrapping parens) is genuinely
    unreachable because the validator always raises first.
    """
    config = FormattingConfig()
    gen = _AdvancedConditionGenerator(config)
    # Identifier is not a valid tuple-indexing target per YARA-X semantics.
    with pytest.raises(ValueError, match="Tuple indexing target"):
        gen.visit_tuple_indexing(TupleIndexing(tuple_expr=Identifier("t"), index=IntegerLiteral(0)))


# ===========================================================================
# _AdvancedConditionGenerator.visit_list_expression  (lines 325-328)
# ===========================================================================


def test_visit_list_expression_with_space_after_comma() -> None:
    """
    Lines 325-328: ListExpression renders as '[e1, e2]' with space_after_comma.
    """
    config = FormattingConfig(space_after_comma=True)
    gen = _AdvancedConditionGenerator(config)
    node = ListExpression(elements=[IntegerLiteral(1), IntegerLiteral(2), IntegerLiteral(3)])
    result = gen.visit_list_expression(node)
    assert result == "[1, 2, 3]"


def test_visit_list_expression_without_space_after_comma() -> None:
    """
    Lines 325-328: ListExpression with space_after_comma=False uses comma only.
    """
    config = FormattingConfig(space_after_comma=False)
    gen = _AdvancedConditionGenerator(config)
    node = ListExpression(elements=[IntegerLiteral(1), IntegerLiteral(2)])
    result = gen.visit_list_expression(node)
    assert result == "[1,2]"


# ===========================================================================
# _AdvancedConditionGenerator.visit_dict_expression / visit_dict_item
# (lines 330-343)
# ===========================================================================


def test_visit_dict_expression_all_plain_items() -> None:
    """
    Lines 330-340: DictExpression with regular DictItems renders as
    '{k1: v1, k2: v2}'.
    """
    config = FormattingConfig(space_after_comma=True)
    gen = _AdvancedConditionGenerator(config)
    di1 = DictItem(key=StringLiteral("a"), value=IntegerLiteral(1))
    di2 = DictItem(key=StringLiteral("b"), value=IntegerLiteral(2))
    node = DictExpression(items=[di1, di2])
    result = gen.visit_dict_expression(node)
    assert result == '{"a": 1, "b": 2}'


def test_visit_dict_expression_with_spread_operator_item() -> None:
    """
    Lines 330-340 (lines 336-337): when a DictItem's value is a SpreadOperator
    the operator itself is rendered directly (not as 'key: **value').
    """
    config = FormattingConfig(space_after_comma=True)
    gen = _AdvancedConditionGenerator(config)
    normal = DictItem(key=StringLiteral("x"), value=IntegerLiteral(99))
    spread = DictItem(
        key=StringLiteral("_"), value=SpreadOperator(expression=Identifier("extra"), is_dict=True)
    )
    node = DictExpression(items=[normal, spread])
    result = gen.visit_dict_expression(node)
    assert result == '{"x": 99, **extra}'


def test_visit_dict_item_renders_key_colon_value() -> None:
    """
    Line 343: DictItem renders as '"key": value'.
    """
    config = FormattingConfig()
    gen = _AdvancedConditionGenerator(config)
    node = DictItem(key=StringLiteral("k"), value=IntegerLiteral(7))
    result = gen.visit_dict_item(node)
    assert result == '"k": 7'


# ===========================================================================
# _AdvancedConditionGenerator.visit_slice_expression  (lines 345-362)
# ===========================================================================


def test_visit_slice_expression_identifier_target_no_extra_parens() -> None:
    """
    Lines 345-362 (line 351->skip 355): Identifier target renders without
    extra parentheses around target.
    """
    config = FormattingConfig()
    gen = _AdvancedConditionGenerator(config)
    node = SliceExpression(
        target=Identifier("arr"), start=IntegerLiteral(0), stop=IntegerLiteral(10)
    )
    result = gen.visit_slice_expression(node)
    assert result == "arr[0:10]"


def test_visit_slice_expression_list_expression_target_no_extra_parens() -> None:
    """
    Lines 345-362: ListExpression target is in the allowed set so no extra
    parentheses are added.
    """
    config = FormattingConfig()
    gen = _AdvancedConditionGenerator(config)
    le = ListExpression(elements=[IntegerLiteral(1), IntegerLiteral(2)])
    node = SliceExpression(target=le, start=IntegerLiteral(0))
    result = gen.visit_slice_expression(node)
    assert result == "[1, 2][0:]"


def test_visit_slice_expression_non_standard_target_gets_wrapping_parens() -> None:
    """
    Lines 351->356 (line 355): when the target is NOT in the allowed set
    (Identifier, FunctionCall, ListExpression, ParenthesesExpression,
    TupleExpression) the target is wrapped in parentheses.
    """
    config = FormattingConfig()
    gen = _AdvancedConditionGenerator(config)
    # BinaryExpression is not in the allowed set; it must be wrapped.
    be = BinaryExpression(left=IntegerLiteral(1), operator="+", right=IntegerLiteral(2))
    node = SliceExpression(target=be, start=IntegerLiteral(0), stop=IntegerLiteral(5))
    result = gen.visit_slice_expression(node)
    assert result == "(1 + 2)[0:5]"


def test_visit_slice_expression_with_step_appends_third_part() -> None:
    """
    Line 361: when step is not None it is appended as a third colon-separated
    part in the index brackets.
    """
    config = FormattingConfig()
    gen = _AdvancedConditionGenerator(config)
    node = SliceExpression(
        target=Identifier("arr"),
        start=IntegerLiteral(0),
        stop=IntegerLiteral(10),
        step=IntegerLiteral(2),
    )
    result = gen.visit_slice_expression(node)
    assert result == "arr[0:10:2]"


def test_visit_slice_expression_omitted_start_and_stop() -> None:
    """
    Lines 356-362: start and stop may each be None; they render as empty
    strings in the colon-separated parts.
    """
    config = FormattingConfig()
    gen = _AdvancedConditionGenerator(config)
    node = SliceExpression(target=Identifier("arr"))
    result = gen.visit_slice_expression(node)
    assert result == "arr[:]"


# ===========================================================================
# _AdvancedConditionGenerator.visit_lambda_expression  (lines 364-374)
# ===========================================================================


def test_visit_lambda_expression_with_parameters() -> None:
    """
    Lines 364-373: LambdaExpression with parameters renders as
    'lambda p1, p2: <body>'.
    """
    config = FormattingConfig()
    gen = _AdvancedConditionGenerator(config)
    body = BinaryExpression(left=Identifier("x"), operator="+", right=Identifier("y"))
    node = LambdaExpression(parameters=["x", "y"], body=body)
    result = gen.visit_lambda_expression(node)
    assert result == "lambda x, y: x + y"


def test_visit_lambda_expression_without_parameters() -> None:
    """
    Lines 364-374 (line 374): LambdaExpression with an empty parameter list
    renders as 'lambda: <body>'.
    """
    config = FormattingConfig()
    gen = _AdvancedConditionGenerator(config)
    node = LambdaExpression(parameters=[], body=IntegerLiteral(42))
    result = gen.visit_lambda_expression(node)
    assert result == "lambda: 42"


# ===========================================================================
# _AdvancedConditionGenerator.visit_pattern_match / visit_match_case
# (lines 376-392)
# ===========================================================================


def test_visit_pattern_match_without_default() -> None:
    """
    Lines 376-385 (line 381->384 False branch): PatternMatch with cases but no
    default renders cases only.
    """
    config = FormattingConfig()
    gen = _AdvancedConditionGenerator(config)
    mc1 = MatchCase(pattern=IntegerLiteral(1), result=StringLiteral("one"))
    mc2 = MatchCase(pattern=IntegerLiteral(2), result=StringLiteral("two"))
    node = PatternMatch(value=Identifier("x"), cases=[mc1, mc2])
    result = gen.visit_pattern_match(node)
    assert result.startswith("match x {")
    assert "1 => " in result
    assert "2 => " in result
    assert "_ =>" not in result
    assert result.rstrip().endswith("}")


def test_visit_pattern_match_with_default() -> None:
    """
    Lines 381-383: PatternMatch with a default renders a catch-all '_ => ...'
    arm.
    """
    config = FormattingConfig()
    gen = _AdvancedConditionGenerator(config)
    mc = MatchCase(pattern=IntegerLiteral(1), result=StringLiteral("one"))
    node = PatternMatch(value=Identifier("x"), cases=[mc], default=StringLiteral("other"))
    result = gen.visit_pattern_match(node)
    assert "_ => " in result
    assert '"other"' in result


def test_visit_pattern_match_uses_tab_nested_indent_when_tabs_configured() -> None:
    """
    Lines 379-385: PatternMatch uses _nested_indent() which returns '\t' when
    indent_style is TABS.
    """
    config = FormattingConfig(indent_style=IndentStyle.TABS)
    gen = _AdvancedConditionGenerator(config)
    mc = MatchCase(pattern=IntegerLiteral(0), result=IntegerLiteral(99))
    node = PatternMatch(value=Identifier("v"), cases=[mc])
    result = gen.visit_pattern_match(node)
    # The case line must be indented with a tab.
    assert "\t0 =>" in result


def test_visit_match_case_renders_pattern_arrow_result() -> None:
    """
    Lines 387-389: MatchCase renders as '<pattern> => <result>'.
    """
    config = FormattingConfig()
    gen = _AdvancedConditionGenerator(config)
    mc = MatchCase(pattern=IntegerLiteral(5), result=StringLiteral("five"))
    result = gen.visit_match_case(mc)
    assert result == '5 => "five"'


def test_indent_continuation_lines_replaces_newlines() -> None:
    """
    Lines 391-392: _indent_continuation_lines replaces '\n' with '\n<indent>'.
    """
    config = FormattingConfig(indent_style=IndentStyle.SPACES, indent_size=4)
    gen = _AdvancedConditionGenerator(config)
    result = gen._indent_continuation_lines("first\nsecond\nthird")
    assert result == "first\n    second\n    third"


def test_indent_continuation_lines_with_tab_indent() -> None:
    """
    Lines 391-392: _indent_continuation_lines uses tab when indent_style is TABS.
    """
    config = FormattingConfig(indent_style=IndentStyle.TABS)
    gen = _AdvancedConditionGenerator(config)
    result = gen._indent_continuation_lines("a\nb")
    assert result == "a\n\tb"


# ===========================================================================
# _AdvancedConditionGenerator.visit_spread_operator  (lines 394-396)
# ===========================================================================


def test_visit_spread_operator_dict_uses_double_star_prefix() -> None:
    """
    Line 395 (is_dict=True): the dict spread operator renders as '**<expr>'.
    """
    config = FormattingConfig()
    gen = _AdvancedConditionGenerator(config)
    node = SpreadOperator(expression=Identifier("d"), is_dict=True)
    result = gen.visit_spread_operator(node)
    assert result == "**d"


def test_visit_spread_operator_array_uses_ellipsis_prefix() -> None:
    """
    Line 396 (is_dict=False): the array spread operator renders as '...<expr>'.
    """
    config = FormattingConfig()
    gen = _AdvancedConditionGenerator(config)
    node = SpreadOperator(expression=Identifier("arr"), is_dict=False)
    result = gen.visit_spread_operator(node)
    assert result == "...arr"


# ===========================================================================
# generate_condition_string  (line 399-401)
# ===========================================================================


def test_generate_condition_string_without_config_uses_plain_generator() -> None:
    """
    Line 400 (else branch): when config is None a plain CodeGenerator is used.
    """
    result = generate_condition_string(IntegerLiteral(42))
    assert result == "42"


def test_generate_condition_string_with_config_uses_advanced_generator() -> None:
    """
    Line 400 (if branch): when a FormattingConfig is provided the
    _AdvancedConditionGenerator is used, which respects the config.
    """
    config = FormattingConfig(space_around_operators=False)
    be = BinaryExpression(left=IntegerLiteral(1), operator="+", right=IntegerLiteral(2))
    result = generate_condition_string(be, config)
    assert result == "1+2"


# ===========================================================================
# Integration: full CodeGenerator pipeline with AdvancedLayout
# ===========================================================================


def test_full_pipeline_advanced_layout_yarax_nodes_in_condition() -> None:
    """
    End-to-end regression: a YARA rule whose condition contains a
    WithStatement and ArrayComprehension is fully generated using the
    AdvancedLayout / FormattingConfig path through visit_rule and
    write_condition_section.
    """
    from yaraast.ast.rules import Rule

    decl = WithDeclaration(identifier="n", value=IntegerLiteral(5))
    ac = ArrayComprehension(
        expression=Identifier("n"),
        variable="n",
        iterable=Identifier("items"),
    )
    ws = WithStatement(declarations=[decl], body=ac)

    yara_file = YaraFile(rules=[Rule(name="integration_rule", condition=ws)])
    config = FormattingConfig(space_after_comma=True)
    opts = GeneratorOptions(advanced=config)
    gen = CodeGenerator(options=opts)
    output = gen.generate(yara_file)

    assert "rule integration_rule" in output
    assert "condition:" in output
    assert "with n = 5:" in output
    assert "[n for n in items]" in output


def test_full_pipeline_sort_imports_enabled() -> None:
    """
    Lines 59-64 (visit_yara_file sort_imports branch): when sort_imports=True
    the imports appear in alphabetical order regardless of insertion order.
    """
    from yaraast.ast.rules import Rule

    yara_file = YaraFile(
        imports=[Import(module="time"), Import(module="pe"), Import(module="elf")],
        rules=[Rule(name="r", condition=IntegerLiteral(1))],
    )
    config = FormattingConfig(sort_imports=True)
    opts = GeneratorOptions(advanced=config)
    gen = CodeGenerator(options=opts)
    output = gen.generate(yara_file)

    elf_pos = output.index("elf")
    pe_pos = output.index("pe")
    time_pos = output.index("time")
    assert elf_pos < pe_pos < time_pos


def test_full_pipeline_sort_rules_enabled() -> None:
    """
    Lines 71-72 (visit_yara_file sort_rules branch): when sort_rules=True
    rules appear in alphabetical order.
    """
    yara_file = YaraFile(
        rules=[
            Rule(name="zebra_rule", condition=IntegerLiteral(1)),
            Rule(name="alpha_rule", condition=IntegerLiteral(2)),
        ]
    )
    config = FormattingConfig(sort_rules=True)
    opts = GeneratorOptions(advanced=config)
    gen = CodeGenerator(options=opts)
    output = gen.generate(yara_file)

    alpha_pos = output.index("alpha_rule")
    zebra_pos = output.index("zebra_rule")
    assert alpha_pos < zebra_pos


def test_full_pipeline_dict_expression_in_condition() -> None:
    """
    End-to-end: DictExpression with a SpreadOperator item in a rule condition
    exercises visit_dict_expression through the full AdvancedLayout pipeline.
    """
    from yaraast.ast.rules import Rule

    normal = DictItem(key=StringLiteral("key"), value=IntegerLiteral(1))
    spread = DictItem(
        key=StringLiteral("_"), value=SpreadOperator(expression=Identifier("base"), is_dict=True)
    )
    de = DictExpression(items=[normal, spread])
    yara_file = YaraFile(rules=[Rule(name="dict_rule", condition=de)])
    config = FormattingConfig(space_after_comma=True)
    opts = GeneratorOptions(advanced=config)
    gen = CodeGenerator(options=opts)
    output = gen.generate(yara_file)

    assert '"key": 1' in output
    assert "**base" in output


def test_full_pipeline_lambda_in_condition() -> None:
    """
    End-to-end: LambdaExpression in a rule condition exercises
    visit_lambda_expression through the full AdvancedLayout pipeline.
    """
    from yaraast.ast.rules import Rule

    le = LambdaExpression(
        parameters=["x"],
        body=BinaryExpression(left=Identifier("x"), operator="+", right=IntegerLiteral(1)),
    )
    yara_file = YaraFile(rules=[Rule(name="lambda_rule", condition=le)])
    config = FormattingConfig()
    opts = GeneratorOptions(advanced=config)
    gen = CodeGenerator(options=opts)
    output = gen.generate(yara_file)

    assert "lambda x: x + 1" in output


def test_full_pipeline_pattern_match_with_default_in_condition() -> None:
    """
    End-to-end: PatternMatch with a default arm exercises the full default
    path of visit_pattern_match through the AdvancedLayout pipeline.
    """
    from yaraast.ast.rules import Rule

    mc = MatchCase(pattern=IntegerLiteral(0), result=StringLiteral("zero"))
    pm = PatternMatch(value=Identifier("n"), cases=[mc], default=StringLiteral("nonzero"))
    yara_file = YaraFile(rules=[Rule(name="match_rule", condition=pm)])
    config = FormattingConfig()
    opts = GeneratorOptions(advanced=config)
    gen = CodeGenerator(options=opts)
    output = gen.generate(yara_file)

    assert "match n {" in output
    assert "0 =>" in output
    assert "_ =>" in output
    assert '"nonzero"' in output
