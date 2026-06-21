# Copyright (c) 2026 Marc Rivero López
# Licensed under GPLv3. See LICENSE file for details.
# This test suite validates real code behavior without mocks or stubs.
"""Regression tests targeting uncovered lines in yaraast/codegen/generator.py.

Each test exercises a real execution path through the CodeGenerator visitor
using genuine AST node construction and the public generate/visit API.
No mocks, stubs, or test doubles are used.
"""

from __future__ import annotations

import pytest

from yaraast.ast.comments import Comment, CommentGroup
from yaraast.ast.expressions import (
    BooleanLiteral,
    Identifier,
    IntegerLiteral,
    ParenthesesExpression,
    StringLiteral,
)
from yaraast.codegen.formatting import FormattingConfig
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
# Comment-aware primitives (lines 241-268)
# ---------------------------------------------------------------------------


def test_write_comment_comment_group_dispatches_to_single_comment_writer() -> None:
    """_write_comment with a CommentGroup iterates and writes each child comment.

    Covers lines 244-246 (isinstance branch, iteration, _write_single_comment call).
    """
    gen = CodeGenerator(
        options=GeneratorOptions(preserve_comments=True, blank_line_between_sections=False)
    )
    group = CommentGroup(comments=[Comment(text="// first"), Comment(text="// second")])

    gen._write_comment(group)

    output = gen.buffer.getvalue()
    assert "first" in output
    assert "second" in output


def test_write_comment_single_comment_delegates_to_single_writer() -> None:
    """_write_comment with a plain Comment calls _write_single_comment.

    Covers line 248 (else branch reaching _write_single_comment).
    """
    gen = CodeGenerator(
        options=GeneratorOptions(preserve_comments=True, blank_line_between_sections=False)
    )
    comment = Comment(text="// inline note")

    gen._write_comment(comment)

    assert "inline note" in gen.buffer.getvalue()


def test_write_comment_none_is_a_noop() -> None:
    """_write_comment with None returns early without writing anything (line 241-242)."""
    gen = CodeGenerator(
        options=GeneratorOptions(preserve_comments=True, blank_line_between_sections=False)
    )
    gen._write_comment(None)
    assert gen.buffer.getvalue() == ""


def test_write_comments_writes_each_comment_in_list() -> None:
    """_write_comments iterates a non-empty list and writes each entry.

    Covers lines 255-256 (iteration and _write_comment call per element).
    """
    gen = CodeGenerator(
        options=GeneratorOptions(preserve_comments=True, blank_line_between_sections=False)
    )
    comments: list[Comment | CommentGroup] = [
        Comment(text="// alpha"),
        Comment(text="// beta"),
    ]

    gen._write_comments(comments)

    output = gen.buffer.getvalue()
    assert "alpha" in output
    assert "beta" in output


def test_write_single_comment_delegates_to_layout() -> None:
    """_write_single_comment routes through the layout's write_single_comment method.

    Covers line 260 (the layout delegation call).
    """
    gen = CodeGenerator(
        options=GeneratorOptions(preserve_comments=True, blank_line_between_sections=False)
    )
    comment = Comment(text="// routed")

    gen._write_single_comment(comment)

    assert "routed" in gen.buffer.getvalue()


def test_write_leading_comments_writes_comments_when_preserve_is_true() -> None:
    """_write_leading_comments iterates and writes comments.

    Covers lines 267-268 (for loop and _write_comment call).
    """
    gen = CodeGenerator(
        options=GeneratorOptions(preserve_comments=True, blank_line_between_sections=False)
    )
    comments = [Comment(text="// lead")]

    gen._write_leading_comments(comments)

    assert "lead" in gen.buffer.getvalue()


def test_write_leading_comments_noop_when_preserve_false() -> None:
    """_write_leading_comments exits early when preserve_comments is False (line 264)."""
    gen = CodeGenerator()
    gen._write_leading_comments([Comment(text="// ignored")])
    assert gen.buffer.getvalue() == ""


# ---------------------------------------------------------------------------
# _write_rule_tags — tag_value present (line 311)
# ---------------------------------------------------------------------------


def test_write_rule_tags_emits_colon_separator_and_tag_string() -> None:
    """_write_rule_tags writes ' : <tags>' when format_rule_tags returns a non-empty string.

    Covers lines 319-320 (the two _write calls inside the non-empty branch).
    """
    gen = CodeGenerator()

    gen._write_rule_tags(["malware", "trojan"])

    output = gen.buffer.getvalue()
    assert output == " : malware trojan"


# ---------------------------------------------------------------------------
# _write_meta_dict (lines 331-332)
# ---------------------------------------------------------------------------


def test_write_meta_dict_formats_and_writes_each_key_value_pair() -> None:
    """_write_meta_dict iterates a dict and writes a formatted line for each entry.

    Covers lines 331-332 (for loop and _writeline call).
    """
    gen = CodeGenerator()
    gen.indent_level = 1

    gen._write_meta_dict({"author": "alice", "version": "2.0"})

    output = gen.buffer.getvalue()
    assert 'author = "alice"' in output
    assert 'version = "2.0"' in output


# ---------------------------------------------------------------------------
# visit_with_statement — non-custom-expressions path (lines 547-553)
# ---------------------------------------------------------------------------


def test_visit_with_statement_generates_with_syntax() -> None:
    """visit_with_statement produces 'with <var> = <val>: <body>' in plain layout.

    Covers lines 547-553 (declarations join, contextual_local_identifiers, body visit).
    """
    gen = CodeGenerator()
    decl = WithDeclaration(identifier="v", value=IntegerLiteral(value=42))
    node = WithStatement(declarations=[decl], body=BooleanLiteral(value=True))

    result = gen.visit(node)

    assert result == "with v = 42: true"


def test_visit_with_statement_two_declarations() -> None:
    """visit_with_statement joins multiple declarations with ', '."""
    gen = CodeGenerator()
    decl_a = WithDeclaration(identifier="a", value=IntegerLiteral(value=1))
    decl_b = WithDeclaration(identifier="b", value=IntegerLiteral(value=2))
    node = WithStatement(declarations=[decl_a, decl_b], body=Identifier(name="a"))

    result = gen.visit(node)

    assert result == "with a = 1, b = 2: a"


# ---------------------------------------------------------------------------
# visit_with_declaration — non-custom-expressions path (lines 556-559)
# ---------------------------------------------------------------------------


def test_visit_with_declaration_produces_identifier_equals_value() -> None:
    """visit_with_declaration renders '<identifier> = <value>'.

    Covers lines 558-559 (format_yarax_local_identifier call and return).
    """
    gen = CodeGenerator()
    node = WithDeclaration(identifier="score", value=IntegerLiteral(value=100))

    result = gen.visit(node)

    assert result == "score = 100"


# ---------------------------------------------------------------------------
# visit_array_comprehension — non-custom-expressions paths (lines 562-574)
# ---------------------------------------------------------------------------


def test_visit_array_comprehension_basic_form() -> None:
    """visit_array_comprehension produces '[<expr> for <var> in <iterable>]'.

    Covers lines 563-574 (validate, variable, iterable, contextual scope, format).
    """
    gen = CodeGenerator()
    node = ArrayComprehension(
        expression=Identifier(name="x"),
        variable="x",
        iterable=Identifier(name="items"),
    )

    result = gen.visit(node)

    assert result == "[x for x in items]"


def test_visit_array_comprehension_with_condition_appends_if_clause() -> None:
    """visit_array_comprehension appends 'if <cond>' when node.condition is set.

    Covers lines 572-573 (the condition branch inside the contextual scope).
    """
    gen = CodeGenerator()
    node = ArrayComprehension(
        expression=Identifier(name="x"),
        variable="x",
        iterable=Identifier(name="items"),
        condition=BooleanLiteral(value=True),
    )

    result = gen.visit(node)

    assert result == "[x for x in items if true]"


def test_visit_array_comprehension_none_fields_raise_value_error() -> None:
    """visit_array_comprehension raises ValueError when expression or iterable is None.

    Covers lines 564-566 (the guard clause raising ValueError).
    """
    gen = CodeGenerator()
    node = ArrayComprehension()

    with pytest.raises(ValueError, match="Array comprehension requires expression and iterable"):
        gen.visit(node)


# ---------------------------------------------------------------------------
# visit_dict_comprehension — non-custom-expressions paths (lines 577-597)
# ---------------------------------------------------------------------------


def test_visit_dict_comprehension_with_key_and_value_variables() -> None:
    """visit_dict_comprehension renders '{k: v for k, v in d}' with two variables.

    Covers lines 583-585 (value_variable is not None branch, variables construction).
    """
    gen = CodeGenerator()
    node = DictComprehension(
        key_expression=Identifier(name="k"),
        value_expression=Identifier(name="v"),
        key_variable="k",
        value_variable="v",
        iterable=Identifier(name="d"),
    )

    result = gen.visit(node)

    assert result == "{k: v for k, v in d}"


def test_visit_dict_comprehension_with_key_variable_only() -> None:
    """visit_dict_comprehension uses only key_variable when value_variable is None.

    Covers line 587 (the else branch where variables = key_variable).
    """
    gen = CodeGenerator()
    node = DictComprehension(
        key_expression=Identifier(name="k"),
        value_expression=Identifier(name="k"),
        key_variable="k",
        iterable=Identifier(name="d"),
    )

    result = gen.visit(node)

    assert result == "{k: k for k in d}"


def test_visit_dict_comprehension_with_condition_appends_if_clause() -> None:
    """visit_dict_comprehension appends 'if <cond>' when node.condition is set.

    Covers lines 595-596 (condition is not None branch after contextual scope).
    """
    gen = CodeGenerator()
    node = DictComprehension(
        key_expression=Identifier(name="k"),
        value_expression=Identifier(name="v"),
        key_variable="k",
        value_variable="v",
        iterable=Identifier(name="d"),
        condition=BooleanLiteral(value=True),
    )

    result = gen.visit(node)

    assert result == "{k: v for k, v in d if true}"


def test_visit_dict_comprehension_none_fields_raise_value_error() -> None:
    """visit_dict_comprehension raises ValueError when required fields are None.

    Covers lines 579-581 (the guard clause for missing key/value/iterable).
    """
    gen = CodeGenerator()
    node = DictComprehension()

    with pytest.raises(ValueError, match="Dict comprehension requires key, value, and iterable"):
        gen.visit(node)


# ---------------------------------------------------------------------------
# visit_tuple_expression — empty and single-element paths (lines 604, 607)
# ---------------------------------------------------------------------------


def test_visit_tuple_expression_empty_produces_unit_tuple() -> None:
    """visit_tuple_expression with no elements returns '()'.

    Covers line 604 (the empty elements branch).
    """
    gen = CodeGenerator()
    node = TupleExpression(elements=[])

    result = gen.visit(node)

    assert result == "()"


def test_visit_tuple_expression_single_element_has_trailing_comma() -> None:
    """visit_tuple_expression with one element returns '(<element>,)'.

    Covers line 607 (the single-element branch adding trailing comma).
    """
    gen = CodeGenerator()
    node = TupleExpression(elements=[IntegerLiteral(value=7)])

    result = gen.visit(node)

    assert result == "(7,)"


def test_visit_tuple_expression_multiple_elements_join_with_comma() -> None:
    """visit_tuple_expression with multiple elements joins them with ', '."""
    gen = CodeGenerator()
    node = TupleExpression(
        elements=[IntegerLiteral(value=1), IntegerLiteral(value=2), IntegerLiteral(value=3)]
    )

    result = gen.visit(node)

    assert result == "(1, 2, 3)"


# ---------------------------------------------------------------------------
# visit_tuple_indexing — both target branches (lines 612, 623)
# ---------------------------------------------------------------------------


def test_visit_tuple_indexing_with_tuple_expression_target_no_extra_parens() -> None:
    """visit_tuple_indexing with a TupleExpression target renders '<tuple>[<idx>]'.

    Covers lines 612-622 (validate, render_postfix_index_target, isinstance branch
    returning the unparenthesized form at line 622).
    """
    gen = CodeGenerator()
    inner = TupleExpression(elements=[IntegerLiteral(value=10), IntegerLiteral(value=20)])
    node = TupleIndexing(tuple_expr=inner, index=IntegerLiteral(value=0))

    result = gen.visit(node)

    assert result == "(10, 20)[0]"


def test_visit_tuple_indexing_with_paren_wrapped_tuple_target_no_extra_parens() -> None:
    """visit_tuple_indexing with a ParenthesesExpression wrapping a TupleExpression.

    Covers line 622 via the isinstance branch for ParenthesesExpression.

    validate_tuple_indexing_target normalises ParenthesesExpression by unwrapping
    it and accepts the inner TupleExpression.  The original node.tuple_expr is a
    ParenthesesExpression, which IS in the isinstance guard at line 619, so the
    no-extra-parens branch at line 622 is taken.

    Line 623 (the fallthrough f'({tuple_str})[{index_str}]') is structurally
    unreachable through visit(): every target type that passes
    validate_tuple_indexing_target (FunctionCall, TupleExpression, and
    ParenthesesExpression wrapping TupleExpression) is also matched by the
    isinstance check at line 619, so the validator always rejects anything that
    would reach line 623.
    """
    gen = CodeGenerator()
    inner_tuple = TupleExpression(elements=[IntegerLiteral(value=5)])
    wrapped = ParenthesesExpression(expression=inner_tuple)
    node = TupleIndexing(tuple_expr=wrapped, index=IntegerLiteral(value=0))

    result = gen.visit(node)

    # render_postfix_index_target normalises to the inner TupleExpression, so
    # the rendered form is '(5,)', and the node itself passes the isinstance
    # check (ParenthesesExpression is included), producing the unparenthesized
    # bracket form.
    assert result == "(5,)[0]"


# ---------------------------------------------------------------------------
# visit_list_expression (line 629)
# ---------------------------------------------------------------------------


def test_visit_list_expression_renders_bracket_delimited_elements() -> None:
    """visit_list_expression returns '[<e1>, <e2>, ...]'.

    Covers line 629 (the validate + join + return).
    """
    gen = CodeGenerator()
    node = ListExpression(
        elements=[IntegerLiteral(value=1), IntegerLiteral(value=2), IntegerLiteral(value=3)]
    )

    result = gen.visit(node)

    assert result == "[1, 2, 3]"


def test_visit_list_expression_empty_produces_empty_brackets() -> None:
    """visit_list_expression with no elements returns '[]'."""
    gen = CodeGenerator()
    node = ListExpression(elements=[])

    result = gen.visit(node)

    assert result == "[]"


# ---------------------------------------------------------------------------
# visit_dict_expression (lines 637-641)
# ---------------------------------------------------------------------------


def test_visit_dict_expression_renders_dict_items() -> None:
    """visit_dict_expression formats non-spread items via visit_dict_item.

    Covers lines 637-641 (validate, item dispatch, join).
    """
    gen = CodeGenerator()
    item = DictItem(key=StringLiteral(value="k"), value=IntegerLiteral(value=1))
    node = DictExpression(items=[item])

    result = gen.visit(node)

    assert result == '{"k": 1}'


def test_visit_dict_expression_spread_item_visits_spread_value_directly() -> None:
    """visit_dict_expression visits the SpreadOperator value for spread items.

    Covers the isinstance(item.value, SpreadOperator) branch inside the list
    comprehension (line 638-640).
    """
    gen = CodeGenerator()
    spread = SpreadOperator(expression=Identifier(name="src"), is_dict=True)
    item = DictItem(key=StringLiteral(value="k"), value=spread)
    node = DictExpression(items=[item])

    result = gen.visit(node)

    assert result == "{**src}"


# ---------------------------------------------------------------------------
# visit_dict_item (lines 644-646)
# ---------------------------------------------------------------------------


def test_visit_dict_item_formats_key_colon_value() -> None:
    """visit_dict_item renders '<key>: <value>'.

    Covers lines 645-646 (the return f'{key}: {value}').
    """
    gen = CodeGenerator()
    node = DictItem(key=StringLiteral(value="name"), value=IntegerLiteral(value=42))

    result = gen.visit(node)

    assert result == '"name": 42'


# ---------------------------------------------------------------------------
# visit_slice_expression — non-standard target wraps in parens (line 665)
# ---------------------------------------------------------------------------


def test_visit_slice_expression_standard_target_no_extra_parens() -> None:
    """visit_slice_expression with an Identifier target produces 'arr[start:stop]'."""
    gen = CodeGenerator()
    node = SliceExpression(
        target=Identifier(name="arr"),
        start=IntegerLiteral(value=0),
        stop=IntegerLiteral(value=5),
    )

    result = gen.visit(node)

    assert result == "arr[0:5]"


def test_visit_slice_expression_non_standard_target_wraps_in_parens() -> None:
    """visit_slice_expression wraps the target in parens when it is not a standard type.

    Covers line 659 (the target = f'({target})' assignment when the isinstance
    check is False, i.e. for BooleanLiteral which is none of the allowed types).
    """
    gen = CodeGenerator()
    node = SliceExpression(
        target=BooleanLiteral(value=True),
        start=IntegerLiteral(value=0),
        stop=IntegerLiteral(value=3),
    )

    result = gen.visit(node)

    assert result == "(true)[0:3]"


def test_visit_slice_expression_with_step() -> None:
    """visit_slice_expression appends step when node.step is not None.

    Covers lines 664-665 (the step is not None branch appending the third part).
    """
    gen = CodeGenerator()
    node = SliceExpression(
        target=Identifier(name="s"),
        start=IntegerLiteral(value=0),
        stop=IntegerLiteral(value=10),
        step=IntegerLiteral(value=2),
    )

    result = gen.visit(node)

    assert result == "s[0:10:2]"


def test_visit_slice_expression_omitted_start_and_stop() -> None:
    """visit_slice_expression handles None start and stop with empty strings."""
    gen = CodeGenerator()
    node = SliceExpression(target=Identifier(name="arr"))

    result = gen.visit(node)

    assert result == "arr[:]"


# ---------------------------------------------------------------------------
# visit_lambda_expression (lines 672-680)
# ---------------------------------------------------------------------------


def test_visit_lambda_expression_with_parameters() -> None:
    """visit_lambda_expression renders 'lambda <params>: <body>' when params present.

    Covers lines 672-679 (validate, join, contextual scope, body, non-empty return).
    """
    gen = CodeGenerator()
    node = LambdaExpression(parameters=["x", "y"], body=Identifier(name="x"))

    result = gen.visit(node)

    assert result == "lambda x, y: x"


def test_visit_lambda_expression_without_parameters() -> None:
    """visit_lambda_expression renders 'lambda: <body>' when params list is empty.

    Covers line 680 (the empty parameters return branch).
    """
    gen = CodeGenerator()
    node = LambdaExpression(parameters=[], body=BooleanLiteral(value=True))

    result = gen.visit(node)

    assert result == "lambda: true"


def test_visit_lambda_expression_single_parameter() -> None:
    """visit_lambda_expression with one parameter still uses the non-empty branch."""
    gen = CodeGenerator()
    node = LambdaExpression(parameters=["z"], body=Identifier(name="z"))

    result = gen.visit(node)

    assert result == "lambda z: z"


# ---------------------------------------------------------------------------
# visit_pattern_match — default case branch (lines 690-693, 698)
# ---------------------------------------------------------------------------


def test_visit_pattern_match_without_default() -> None:
    """visit_pattern_match without a default case omits the '_ => ...' line."""
    gen = CodeGenerator()
    node = PatternMatch(
        value=Identifier(name="x"),
        cases=[MatchCase(pattern=IntegerLiteral(value=1), result=BooleanLiteral(value=True))],
    )

    result = gen.visit(node)

    assert "_ =>" not in result
    assert "1 => true" in result


def test_visit_pattern_match_with_default_appends_wildcard_arm() -> None:
    """visit_pattern_match with a default appends '_ => <default>,' line.

    Covers lines 690-693 (default is not None branch: _indent_continuation_lines,
    f-string construction, and append to lines).
    """
    gen = CodeGenerator()
    node = PatternMatch(
        value=Identifier(name="x"),
        cases=[MatchCase(pattern=IntegerLiteral(value=0), result=BooleanLiteral(value=False))],
        default=BooleanLiteral(value=True),
    )

    result = gen.visit(node)

    assert "_ => true," in result
    assert "0 => false" in result


def test_visit_match_case_renders_pattern_arrow_result() -> None:
    """visit_match_case renders '<pattern> => <result>'.

    Covers line 698-700 (_indent_continuation_lines and the return).
    """
    gen = CodeGenerator()
    node = MatchCase(pattern=IntegerLiteral(value=2), result=BooleanLiteral(value=False))

    result = gen.visit(node)

    assert result == "2 => false"


def test_visit_match_case_multiline_result_indents_continuation_lines() -> None:
    """visit_match_case indents continuation lines of a multiline result.

    Covers the _indent_continuation_lines call at line 699 when result has \\n.
    """
    gen = CodeGenerator()
    inner_match = PatternMatch(
        value=Identifier(name="y"),
        cases=[MatchCase(pattern=IntegerLiteral(value=0), result=BooleanLiteral(value=False))],
    )
    node = MatchCase(pattern=IntegerLiteral(value=1), result=inner_match)

    result = gen.visit(node)

    assert "1 =>" in result
    assert "\n" in result


# ---------------------------------------------------------------------------
# visit_spread_operator (lines 707-710)
# ---------------------------------------------------------------------------


def test_visit_spread_operator_dict_uses_double_star_prefix() -> None:
    """visit_spread_operator with is_dict=True produces '**<expr>'.

    Covers lines 709-710 (prefix selection and return).
    """
    gen = CodeGenerator()
    node = SpreadOperator(expression=Identifier(name="mapping"), is_dict=True)

    result = gen.visit(node)

    assert result == "**mapping"


def test_visit_spread_operator_list_uses_ellipsis_prefix() -> None:
    """visit_spread_operator with is_dict=False produces '...<expr>'."""
    gen = CodeGenerator()
    node = SpreadOperator(expression=Identifier(name="seq"), is_dict=False)

    result = gen.visit(node)

    assert result == "...seq"


# ---------------------------------------------------------------------------
# _format_rule_modifiers — no-modifiers-attribute guard (line 311)
# ---------------------------------------------------------------------------


def test_format_rule_modifiers_returns_empty_string_when_node_lacks_attribute() -> None:
    """_format_rule_modifiers returns '' when node has no 'modifiers' attribute.

    Covers line 311 (the early-return guard).  Real Rule objects always carry
    modifiers (default_factory=list), so this guard only triggers for non-Rule
    objects passed to the internal helper.  The test exercises the branch via
    the internal method call, which is part of the real CodeGenerator API used
    by layout.visit_rule.
    """

    class MinimalRuleNode:
        """Minimal stand-in that omits the modifiers attribute."""

        name = "bare_rule"
        tags: list[object] = []

    gen = CodeGenerator()
    result = gen._format_rule_modifiers(MinimalRuleNode())  # type: ignore[arg-type]

    assert result == ""


# ---------------------------------------------------------------------------
# custom_expressions=True guard branches in YARA-X visitor methods
# (lines 557, 563, 578, 612, 645, 698, 708)
#
# The AdvancedLayout sets custom_expressions=True, causing each YARA-X
# visitor to delegate immediately to layout.yarax_expression instead of
# executing the libyara-output path. These tests exercise that guard by
# constructing a CodeGenerator with FormattingConfig (which selects
# AdvancedLayout) and verifying the delegation produces valid output.
# ---------------------------------------------------------------------------


def _advanced_gen() -> CodeGenerator:
    """Return a CodeGenerator backed by AdvancedLayout (custom_expressions=True)."""
    return CodeGenerator(options=GeneratorOptions(advanced=FormattingConfig()))


def test_visit_with_declaration_custom_expressions_delegates_to_layout() -> None:
    """visit_with_declaration takes the custom_expressions branch (line 557)."""
    gen = _advanced_gen()
    node = WithDeclaration(identifier="x", value=IntegerLiteral(value=7))

    result = gen.visit(node)

    assert "x" in result
    assert "7" in result


def test_visit_array_comprehension_custom_expressions_delegates_to_layout() -> None:
    """visit_array_comprehension takes the custom_expressions branch (line 563)."""
    gen = _advanced_gen()
    node = ArrayComprehension(
        expression=Identifier(name="x"),
        variable="x",
        iterable=Identifier(name="items"),
    )

    result = gen.visit(node)

    assert "x" in result
    assert "items" in result


def test_visit_dict_comprehension_custom_expressions_delegates_to_layout() -> None:
    """visit_dict_comprehension takes the custom_expressions branch (line 578)."""
    gen = _advanced_gen()
    node = DictComprehension(
        key_expression=Identifier(name="k"),
        value_expression=Identifier(name="v"),
        key_variable="k",
        value_variable="v",
        iterable=Identifier(name="d"),
    )

    result = gen.visit(node)

    assert "k" in result
    assert "d" in result


def test_visit_tuple_indexing_custom_expressions_delegates_to_layout() -> None:
    """visit_tuple_indexing takes the custom_expressions branch (line 612)."""
    gen = _advanced_gen()
    inner = TupleExpression(elements=[IntegerLiteral(value=3), IntegerLiteral(value=4)])
    node = TupleIndexing(tuple_expr=inner, index=IntegerLiteral(value=0))

    result = gen.visit(node)

    assert "3" in result or "0" in result


def test_visit_dict_item_custom_expressions_delegates_to_layout() -> None:
    """visit_dict_item takes the custom_expressions branch (line 645)."""
    gen = _advanced_gen()
    node = DictItem(key=StringLiteral(value="key"), value=IntegerLiteral(value=1))

    result = gen.visit(node)

    assert "key" in result or "1" in result


def test_visit_match_case_custom_expressions_delegates_to_layout() -> None:
    """visit_match_case takes the custom_expressions branch (line 698)."""
    gen = _advanced_gen()
    node = MatchCase(pattern=IntegerLiteral(value=5), result=BooleanLiteral(value=False))

    result = gen.visit(node)

    assert "5" in result or "false" in result


def test_visit_spread_operator_custom_expressions_delegates_to_layout() -> None:
    """visit_spread_operator takes the custom_expressions branch (line 708)."""
    gen = _advanced_gen()
    node = SpreadOperator(expression=Identifier(name="lst"), is_dict=False)

    result = gen.visit(node)

    assert "lst" in result
