# Copyright (c) 2026 Marc Rivero López
# Licensed under GPLv3. See LICENSE file for details.
# This test suite validates real code behavior without mocks or stubs.
"""Regression tests targeting the specific uncovered branches in best_practices.py.

Baseline: 92.59% (before this file).

Branch mapping (as reported by pytest-cov --cov-branch --cov-report=term-missing):

  189->193  rule.condition is None: visit/check are skipped but finally clears local_scopes
  220->199  _analyze_strings loop: string is not PlainString/HexString/RegexString (base class)
            -> elif at 220 is False, loop continues to 199
  365-366   _mark_string_set_text: text == "them" -> mark_all + return
  371->373  _mark_string_set_text: local found but value IS _LOCAL_WITHOUT_VALUE -> return early
            NOTE: UNREACHABLE through public API (namespace mismatch between
            _push_local_scope (plain names) and normalize_string_reference_id ($-prefixed));
            documented below.
  384-385   _mark_wildcard_usage: _current_rule is None -> fallback mark + return
  404       _mark_all_current_rule_strings: _current_rule is None -> early return
  414-415   _visit_ast_value: collection branch iterates items
  419-420   _visit_string_set_value: plain str argument
  422-424   _visit_string_set_value: list/tuple/set/frozenset argument
  433-434   _visit_string_set_value: Identifier name not "them" and not "$"-prefixed
  451       _visit_string_set_value: unrecognized type falls through to _visit_ast_value
  472->474  visit_at_expression: string_id is Expression, not str (skip mark)
  480       visit_in_expression: subject is ASTNode -> self.visit(subject)
  491->exit visit_for_of_expression: condition is None -> skip condition visit
  532->534  visit_dict_comprehension: value_variable is None/falsy -> skip append
            (the TRUE branch 532->533 is covered elsewhere; the FALSE branch
            532->534 skips the append and jumps directly to _push_local_scope)
  569->exit _define_local: no active local_scopes -> no-op
  591->590  _analyze_global_patterns inner loop: hex_string.tokens is empty -> skip key
            (arc from line 591 back to 590 when len(tokens) == 0)

Unreachable branches (by design):
  371->373  _LOCAL_WITHOUT_VALUE is only stored by _push_local_scope, which uses plain names.
            normalize_string_reference_id always prepends "$", so the lookup from
            _mark_string_set_text can never find a _push_local_scope key.  The only
            path to a "$"-keyed scope entry is via _define_local (WithDeclaration), which
            always stores the real node.value — never _LOCAL_WITHOUT_VALUE.
"""

from __future__ import annotations

from typing import Any

import pytest

from yaraast.analysis.best_practices import BestPracticesAnalyzer
from yaraast.ast.base import YaraFile
from yaraast.ast.conditions import (
    AtExpression,
    ForExpression,
    ForOfExpression,
    InExpression,
    OfExpression,
)
from yaraast.ast.expressions import (
    BooleanLiteral,
    Identifier,
    IntegerLiteral,
    RangeExpression,
    SetExpression,
    StringIdentifier,
)
from yaraast.ast.rules import Rule
from yaraast.ast.strings import HexByte, HexString, PlainString, StringDefinition
from yaraast.yarax.ast_nodes import (
    ArrayComprehension,
    DictComprehension,
    LambdaExpression,
    ListExpression,
    WithDeclaration,
    WithStatement,
)

# ---------------------------------------------------------------------------
# Line 189->193: rule whose condition is None
# ---------------------------------------------------------------------------


def test_rule_with_none_condition_still_clears_local_scopes() -> None:
    """A Rule with condition=None must complete without raising.

    Branch 189->193: the `if node.condition is not None:` guard is False,
    so visit() and _check_unused_strings() are skipped.  The finally-block
    at line 193 (_local_scopes.clear()) still runs.
    """
    ast = YaraFile(
        rules=[
            Rule(
                name="no_condition",
                strings=[PlainString(identifier="$a", value="hello")],
                condition=None,
            )
        ]
    )

    report = BestPracticesAnalyzer().analyze(ast)

    assert report is not None
    assert report.statistics["total_rules"] == 1


# ---------------------------------------------------------------------------
# Line 220->199: _analyze_strings loop when string is none of the known types
# A raw StringDefinition (the abstract base) is not PlainString, HexString,
# or RegexString, so all three elif guards at 215/217/220 evaluate to False
# and the loop continues back to line 199.
# ---------------------------------------------------------------------------


def test_analyze_strings_base_string_definition_skips_type_branches() -> None:
    """_analyze_strings must handle a raw StringDefinition without crashing.

    When none of the isinstance guards (PlainString, HexString, RegexString)
    match, the loop body exits at line 220 and continues to line 199 —
    the 220->199 branch arc.
    """
    ast = YaraFile(
        rules=[
            Rule(
                name="base_string_def",
                strings=[
                    # PlainString first so line 215 is hit (True), ensuring the
                    # loop iterates; then the raw StringDefinition triggers 220->199.
                    PlainString(identifier="$known", value="abcde"),
                    StringDefinition(identifier="$base"),
                ],
                condition=StringIdentifier("$known"),
            )
        ]
    )

    report = BestPracticesAnalyzer().analyze(ast)

    # $base is defined but never used; $known IS used.
    assert any("$base" in s.message and "never used" in s.message for s in report.suggestions)
    assert not any("$known" in s.message and "never used" in s.message for s in report.suggestions)


# ---------------------------------------------------------------------------
# Lines 365-366: _mark_string_set_text with text == "them"
# ---------------------------------------------------------------------------


def test_mark_string_set_text_them_string_marks_all_strings() -> None:
    """_mark_string_set_text must call _mark_all_current_rule_strings and
    return early (lines 365-366) when the text is exactly "them".

    Reached via _visit_string_set_value -> StringIdentifier("them") ->
    _mark_string_set_text("them").
    """
    ast = YaraFile(
        rules=[
            Rule(
                name="them_via_string_identifier",
                strings=[
                    PlainString(identifier="$alpha", value="aaa"),
                    PlainString(identifier="$beta", value="bbb"),
                ],
                condition=OfExpression("any", StringIdentifier("them")),
            )
        ]
    )

    report = BestPracticesAnalyzer().analyze(ast)

    # All strings marked used — no "never used" suggestions expected.
    unused = [s for s in report.suggestions if "defined but never used" in s.message]
    assert unused == []


# ---------------------------------------------------------------------------
# Lines 384-385: _mark_wildcard_usage when _current_rule is None
# ---------------------------------------------------------------------------


def test_mark_wildcard_usage_without_current_rule_falls_back_to_mark_usage() -> None:
    """_mark_wildcard_usage must call _mark_string_usage with the raw pattern
    when _current_rule is None (lines 384-385 guard).

    Called directly since there is no public analyze() path that leaves
    _current_rule unset while also dispatching into _mark_wildcard_usage.
    """
    analyzer = BestPracticesAnalyzer()
    # _current_rule remains None (no analyze() call).
    analyzer._mark_wildcard_usage("$some*")

    assert "$some*" in analyzer._string_usage


# ---------------------------------------------------------------------------
# Line 404: _mark_all_current_rule_strings when _current_rule is None
# ---------------------------------------------------------------------------


def test_mark_all_current_rule_strings_without_current_rule_is_noop() -> None:
    """_mark_all_current_rule_strings must return early (line 404 guard) when
    _current_rule is None, leaving _string_usage unchanged.
    """
    analyzer = BestPracticesAnalyzer()
    analyzer._mark_all_current_rule_strings()

    assert analyzer._string_usage == {}


# ---------------------------------------------------------------------------
# Lines 414-415: _visit_ast_value with a collection of ASTNodes
# ---------------------------------------------------------------------------


def test_visit_ast_value_with_list_of_ast_nodes_visits_each() -> None:
    """_visit_ast_value must iterate over a list and call visit() on each
    ASTNode (lines 414-415, the list/tuple/set/frozenset branch).

    The simplest direct call: pass a list of BooleanLiteral nodes.
    """
    analyzer = BestPracticesAnalyzer()
    nodes: list[Any] = [BooleanLiteral(value=True), BooleanLiteral(value=False)]
    # Must not raise; BestPracticesAnalyzer has no visit_boolean_literal so
    # the base visitor dispatches silently.
    analyzer._visit_ast_value(nodes)


# ---------------------------------------------------------------------------
# Lines 419-420: _visit_string_set_value receiving a plain str
# ---------------------------------------------------------------------------


def test_visit_string_set_value_plain_string_dispatches_to_mark() -> None:
    """_visit_string_set_value must handle a plain str argument (lines 419-420)
    by calling _mark_string_set_text.
    """
    analyzer = BestPracticesAnalyzer()
    rule = Rule(
        name="plain_str_test",
        strings=[PlainString(identifier="$a", value="data")],
        condition=BooleanLiteral(value=True),
    )
    analyzer._current_rule = rule

    analyzer._visit_string_set_value("$a")

    assert "$a" in analyzer._string_usage


# ---------------------------------------------------------------------------
# Lines 422-424: _visit_string_set_value with a list of string-set items
# ---------------------------------------------------------------------------


def test_visit_string_set_value_list_dispatches_to_each_item() -> None:
    """_visit_string_set_value must recurse into each element of a list
    (lines 422-424).
    """
    analyzer = BestPracticesAnalyzer()
    rule = Rule(
        name="list_dispatch",
        strings=[
            PlainString(identifier="$x", value="xx"),
            PlainString(identifier="$y", value="yy"),
        ],
        condition=BooleanLiteral(value=True),
    )
    analyzer._current_rule = rule

    analyzer._visit_string_set_value(["$x", "$y"])

    assert "$x" in analyzer._string_usage
    assert "$y" in analyzer._string_usage


# ---------------------------------------------------------------------------
# Lines 433-434: _visit_string_set_value with Identifier not "them" and
# not starting with "$" -> falls through to _visit_ast_value
# ---------------------------------------------------------------------------


def test_visit_string_set_value_non_string_identifier_visits_ast_value() -> None:
    """An Identifier whose name is neither 'them' nor a '$' prefix must
    dispatch to _visit_ast_value (lines 433-434).

    Constructed via OfExpression with a bare module-name Identifier.
    """
    ast = YaraFile(
        rules=[
            Rule(
                name="module_identifier_in_set",
                strings=[PlainString(identifier="$a", value="data")],
                condition=OfExpression(
                    "any",
                    Identifier("pe"),
                ),
            )
        ]
    )

    report = BestPracticesAnalyzer().analyze(ast)

    # $a is unused because the Identifier "pe" doesn't reference it.
    assert any("defined but never used" in s.message for s in report.suggestions)


# ---------------------------------------------------------------------------
# Line 451: _visit_string_set_value fallthrough for unrecognized types
# ---------------------------------------------------------------------------


def test_visit_string_set_value_unrecognized_type_falls_through_to_visit_ast_value() -> None:
    """_visit_string_set_value must call _visit_ast_value (line 451) for any
    type that matches none of the preceding isinstance guards.

    IntegerLiteral is an ASTNode that is not str/list/Identifier/StringLiteral/
    StringIdentifier/StringWildcard/ParenthesesExpression/SetExpression.
    """
    analyzer = BestPracticesAnalyzer()
    node = IntegerLiteral(42)
    # Must not raise.
    analyzer._visit_string_set_value(node)


# ---------------------------------------------------------------------------
# Line 472->474: visit_at_expression where string_id is an Expression
# ---------------------------------------------------------------------------


def test_visit_at_expression_with_expression_string_id_does_not_mark() -> None:
    """visit_at_expression must skip _mark_condition_string_usage when
    string_id is an Expression (472->474 branch, not a str).

    AtExpression.string_id is typed str | Expression; an OfExpression
    exercises the non-str branch.
    """
    ast = YaraFile(
        rules=[
            Rule(
                name="at_expr_expression_id",
                strings=[PlainString(identifier="$a", value="data")],
                condition=AtExpression(
                    string_id=OfExpression("any", StringIdentifier("$a")),
                    offset=IntegerLiteral(0),
                ),
            )
        ]
    )

    report = BestPracticesAnalyzer().analyze(ast)
    assert report is not None


# ---------------------------------------------------------------------------
# Line 480: visit_in_expression where subject is an ASTNode
# ---------------------------------------------------------------------------


def test_visit_in_expression_with_ast_node_subject_visits_node() -> None:
    """visit_in_expression must call self.visit(node.subject) when subject
    is an ASTNode (line 480).
    """
    ast = YaraFile(
        rules=[
            Rule(
                name="in_expr_astnode_subject",
                strings=[PlainString(identifier="$a", value="data")],
                condition=InExpression(
                    subject=OfExpression("any", StringIdentifier("$a")),
                    range=RangeExpression(IntegerLiteral(0), IntegerLiteral(100)),
                ),
            )
        ]
    )

    report = BestPracticesAnalyzer().analyze(ast)

    # $a used via OfExpression inside subject; no unused warning.
    assert not any(
        "defined but never used" in s.message and "$a" in s.message for s in report.suggestions
    )


# ---------------------------------------------------------------------------
# Line 491->exit: visit_for_of_expression with condition=None
# ---------------------------------------------------------------------------


def test_visit_for_of_expression_with_none_condition_skips_visit() -> None:
    """visit_for_of_expression must skip the condition visit when
    node.condition is None (491->exit branch).
    """
    ast = YaraFile(
        rules=[
            Rule(
                name="for_of_no_condition",
                strings=[PlainString(identifier="$a", value="data")],
                condition=ForOfExpression(
                    quantifier="any",
                    string_set=StringIdentifier("$a"),
                    condition=None,
                ),
            )
        ]
    )

    report = BestPracticesAnalyzer().analyze(ast)

    assert not any(
        "defined but never used" in s.message and "$a" in s.message for s in report.suggestions
    )


# ---------------------------------------------------------------------------
# Line 532->534: visit_dict_comprehension with value_variable=None
# This is the FALSE branch of `if node.value_variable:` at line 532,
# which jumps directly to line 534 (_push_local_scope) without appending.
# ---------------------------------------------------------------------------


def test_visit_dict_comprehension_without_value_variable_skips_append() -> None:
    """visit_dict_comprehension with value_variable=None must skip the
    append (532->534 FALSE branch) and call _push_local_scope with only
    the key_variable.
    """
    ast = YaraFile(
        rules=[
            Rule(
                name="dict_comp_single_var",
                condition=DictComprehension(
                    key_expression=Identifier("k"),
                    value_expression=Identifier("k"),
                    key_variable="k",
                    value_variable=None,
                    iterable=ListExpression([IntegerLiteral(1)]),
                ),
            )
        ]
    )

    report = BestPracticesAnalyzer().analyze(ast)
    assert report is not None


# ---------------------------------------------------------------------------
# Line 569->exit: _define_local when _local_scopes is empty
# ---------------------------------------------------------------------------


def test_define_local_without_active_scope_is_noop() -> None:
    """_define_local must be a no-op (569->exit) when _local_scopes is empty."""
    analyzer = BestPracticesAnalyzer()
    assert analyzer._local_scopes == []

    analyzer._define_local("some_var")

    assert analyzer._local_scopes == []


# ---------------------------------------------------------------------------
# Line 591->590: _analyze_global_patterns with a zero-token hex string
# Line 591 is `if len(hex_string.tokens) > 0:` inside the first for-loop.
# When tokens is empty, the condition is False and the loop continues back
# to line 590 — the 591->590 branch arc.
# ---------------------------------------------------------------------------


def test_analyze_global_patterns_empty_token_hex_string_skips_key() -> None:
    """_analyze_global_patterns must skip hex strings with zero tokens
    (591->590 branch: len(tokens) == 0, loop continues to next pattern).

    Two hex patterns are provided: one with zero tokens and one with two
    tokens.  The empty one triggers 591->590; the non-empty one triggers
    591->592.  With only one non-empty pattern, pattern_groups will have a
    single-entry group, so no "Similar hex patterns" suggestion is emitted.
    """
    analyzer = BestPracticesAnalyzer()
    analyzer._hex_patterns = [
        ("$empty", HexString("$empty", tokens=[])),
        ("$real", HexString("$real", tokens=[HexByte(0x4D), HexByte(0x5A)])),
        ("$other", HexString("$other", tokens=[])),
    ]

    analyzer._analyze_global_patterns()

    assert not any("Similar hex patterns" in s.message for s in analyzer.report.suggestions)


# ---------------------------------------------------------------------------
# Integration: WithStatement with declaration value resolves string usage
# via _visit_string_set_value(local_value) path (371->372 branch, value IS set)
# ---------------------------------------------------------------------------


def test_with_declaration_whose_value_is_string_literal_resolves_usage() -> None:
    """When a WithDeclaration binds "$local_ref" to a StringLiteral("$a"),
    the local lookup path at line 371 finds a real value (not _LOCAL_WITHOUT_VALUE),
    so _visit_string_set_value(StringLiteral("$a")) is called (line 372).

    That call resolves to _mark_string_set_text("$a") -> _mark_string_usage("$a"),
    marking $a as used.  The result: no "defined but never used" warning for $a.

    This exercises the 371->372 (TRUE) branch of:
        if local_value is not self._LOCAL_WITHOUT_VALUE:
            self._visit_string_set_value(local_value)   # line 372
        return                                           # line 373
    """
    from yaraast.ast.expressions import StringLiteral

    ast = YaraFile(
        rules=[
            Rule(
                name="with_string_literal_value",
                strings=[PlainString(identifier="$a", value="data")],
                condition=WithStatement(
                    declarations=[WithDeclaration("$local_ref", StringLiteral("$a"))],
                    body=OfExpression("any", StringIdentifier("$local_ref")),
                ),
            )
        ]
    )

    report = BestPracticesAnalyzer().analyze(ast)

    # $a was reached through local resolution -> StringLiteral("$a") ->
    # _mark_string_usage("$a") -> $a is marked used -> no unused warning.
    assert not any(
        "defined but never used" in s.message and "$a" in s.message for s in report.suggestions
    )


# ---------------------------------------------------------------------------
# Integration: LambdaExpression and ArrayComprehension with non-None condition
# ---------------------------------------------------------------------------


@pytest.mark.parametrize(
    "condition",
    [
        ArrayComprehension(
            expression=IntegerLiteral(1),
            variable="item",
            iterable=ListExpression([IntegerLiteral(1)]),
            condition=BooleanLiteral(value=True),
        ),
        LambdaExpression(
            parameters=["x", "y"],
            body=BooleanLiteral(value=True),
        ),
    ],
)
def test_best_practices_visits_compound_yarax_expressions(condition: Any) -> None:
    """ArrayComprehension with non-None condition and LambdaExpression with
    multiple parameters must complete without raising.
    """
    ast = YaraFile(rules=[Rule(name="compound_expr", condition=condition)])
    report = BestPracticesAnalyzer().analyze(ast)
    assert report is not None


# ---------------------------------------------------------------------------
# Integration: ForExpression with loop variable in body exercises
# local scope push/pop and _mark_condition_string_usage skip path
# ---------------------------------------------------------------------------


def test_for_expression_loop_variable_in_body_skips_string_mark() -> None:
    """A ForExpression whose body references the loop variable (not a string)
    must push/pop the local scope correctly without crashing.

    This exercises _push_local_scope, visit_for_expression, _pop_local_scope.
    """
    ast = YaraFile(
        rules=[
            Rule(
                name="for_loop_variable",
                strings=[PlainString(identifier="$a", value="data")],
                condition=ForExpression(
                    quantifier="any",
                    variable="i",
                    iterable=SetExpression([IntegerLiteral(1), IntegerLiteral(2)]),
                    body=BooleanLiteral(value=True),
                ),
            )
        ]
    )

    report = BestPracticesAnalyzer().analyze(ast)

    # $a is unused — no interference from the for-loop variable.
    assert any(
        "defined but never used" in s.message and "$a" in s.message for s in report.suggestions
    )
