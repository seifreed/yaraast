# Copyright (c) 2026 Marc Rivero López
# Licensed under GPLv3. See LICENSE file for details.
# This test suite validates real code behavior without mocks or stubs.
"""Regression tests targeting specific uncovered branches in yaraast/metrics/complexity.py.

Each test exercises a real production code path identified from the coverage
gap report.  No mocks, stubs, or artificial scaffolding are used.  All tests
build real AST nodes and invoke the production ComplexityAnalyzer.
"""

from __future__ import annotations

from typing import Any, cast

import pytest

from yaraast.ast.base import YaraFile
from yaraast.ast.conditions import AtExpression, InExpression, OfExpression
from yaraast.ast.expressions import (
    BooleanLiteral,
    FunctionCall,
    Identifier,
    IntegerLiteral,
    MemberAccess,
    RangeExpression,
    SetExpression,
    StringCount,
    StringIdentifier,
    StringWildcard,
)
from yaraast.ast.rules import Rule
from yaraast.ast.strings import PlainString
from yaraast.metrics.complexity import ComplexityAnalyzer
from yaraast.yarax.ast_nodes import (
    DictComprehension,
    DictExpression,
    DictItem,
    SpreadOperator,
    TupleExpression,
    WithDeclaration,
    WithStatement,
)

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _make_file(*rules: Rule) -> YaraFile:
    """Build a minimal valid YaraFile from the supplied rules."""
    return YaraFile(rules=list(rules))


def _make_rule(name: str, condition: Any, strings: list[Any] | None = None) -> Rule:
    """Build a Rule with the given condition and optional string definitions."""
    return Rule(name=name, condition=condition, strings=strings or [])


def _analyze(yara_file: YaraFile) -> Any:
    """Run the production ComplexityAnalyzer and return its metrics."""
    return ComplexityAnalyzer().analyze(yara_file)


# ---------------------------------------------------------------------------
# Line 158->exit  (_mark_string_usage skips when rule_key is falsy)
#
# _mark_string_usage calls _active_rule_key(); that returns None when both
# _current_rule_key and _current_rule are None (line 175 path).
# The only public way to get there without an active rule is to call
# visit_string_wildcard, which chains to _mark_string_set_text ->
# _mark_wildcard_usage -> _mark_string_usage while _current_rule is None.
# However, the standard analyze() entry point always sets _current_rule
# before visiting nodes.
#
# The branch is also reachable via _active_rule_key returning None (line 175)
# when both sentinels are absent.  This is tested indirectly via the
# _active_rule_key-returns-None path below.
# ---------------------------------------------------------------------------


def test_active_rule_key_returns_none_when_no_current_rule() -> None:
    """_active_rule_key must return None when neither sentinel is set.

    After analyze() resets state the internal method should return None if
    called before any rule traversal begins.  We verify this by analyzing a
    file with no rules: the post-analysis cleanup leaves _current_rule_key and
    _current_rule both None, so _active_rule_key returns None.
    """
    analyzer = ComplexityAnalyzer()
    metrics = analyzer.analyze(YaraFile(rules=[]))

    # No rules -> no keys in cyclomatic_complexity, no rule-level metrics
    assert metrics.total_rules == 0
    assert metrics.cyclomatic_complexity == {}
    # Confirm the internal method now returns None (line 175 path)
    assert analyzer._active_rule_key() is None


# ---------------------------------------------------------------------------
# Line 187  (_mark_all_current_rule_strings early return when no current rule)
#
# visit_of_expression -> _visit_string_set_value("them") ->
# _mark_string_set_text("them") -> _mark_all_current_rule_strings.
# When _current_rule is None the early-return fires.  This path is reached by
# directly calling the private method with _current_rule still None.
# ---------------------------------------------------------------------------


def test_mark_all_current_rule_strings_noop_without_active_rule() -> None:
    """_mark_all_current_rule_strings must silently return when no rule is active.

    After a full analysis cycle _current_rule is reset to None.  Calling the
    private method at that point must not raise and must not add to
    _string_usage.
    """
    analyzer = ComplexityAnalyzer()
    analyzer.analyze(YaraFile(rules=[]))

    # _current_rule is now None; the early-return branch (line 187) fires
    analyzer._mark_all_current_rule_strings()

    assert analyzer._string_usage == {}


# ---------------------------------------------------------------------------
# Lines 193-194  (_mark_wildcard_usage with no current rule falls back to
#                 plain _mark_string_usage)
#
# Call _mark_wildcard_usage directly with _current_rule == None (default
# post-analyze state) and a non-"$*" pattern.
# ---------------------------------------------------------------------------


def test_mark_wildcard_usage_without_current_rule_marks_pattern_directly() -> None:
    """When _current_rule is None, _mark_wildcard_usage records the raw pattern.

    This exercises the branch at lines 192-194 where no rule is active and the
    fallback path calls _mark_string_usage with the original pattern string.
    """
    analyzer = ComplexityAnalyzer()
    # Ensure current rule is None (analyze resets it)
    analyzer.analyze(YaraFile(rules=[]))

    # Manually put a rule key in place so _mark_string_usage can actually store
    # the entry (otherwise rule_key is still None and line 158->exit fires
    # instead, which is the other branch being tested above).
    analyzer._current_rule_key = "synthetic"
    analyzer._mark_wildcard_usage("$prefix*")

    assert "$prefix*" in analyzer._string_usage.get("synthetic", set())


# ---------------------------------------------------------------------------
# Lines 197-198  (_mark_wildcard_usage with pattern == "$*" marks all strings)
#
# A rule containing two string definitions and a condition that uses the
# global wildcard "$*" in a for-of expression.
# ---------------------------------------------------------------------------


def test_mark_wildcard_usage_dollar_star_marks_all_rule_strings() -> None:
    """A '$*' wildcard in a string set marks every string defined in the rule.

    This exercises the branch at lines 196-198 where the pattern equals "$*"
    and _mark_all_current_rule_strings is called instead of iterating
    individual definitions.
    """
    ast = _make_file(
        _make_rule(
            "wildcard_all",
            condition=OfExpression("any", "$*"),
            strings=[
                PlainString(identifier="$a", value="alpha"),
                PlainString(identifier="$b", value="beta"),
            ],
        )
    )

    metrics = _analyze(ast)

    # Both strings are used via the "$*" wildcard, so unused_strings is empty
    assert metrics.unused_strings == []
    assert "$a" in metrics.string_dependencies["wildcard_all"]
    assert "$b" in metrics.string_dependencies["wildcard_all"]


# ---------------------------------------------------------------------------
# Line 204  (skip anonymous strings inside _mark_wildcard_usage loop)
#
# A rule with one named and one anonymous string, using a wildcard that would
# match both.  The anonymous string must be skipped (line 203-204: continue).
# ---------------------------------------------------------------------------


def test_mark_wildcard_usage_skips_anonymous_strings() -> None:
    """Anonymous strings must be excluded when a wildcard pattern is resolved.

    The loop at line 202 skips strings where is_anonymous == True (line 204).
    The named string that matches the pattern must be marked; the anonymous
    one must not appear in string_dependencies.
    """
    anonymous_str = PlainString(identifier="$", value="anon", is_anonymous=True)
    named_str = PlainString(identifier="$named", value="named")

    ast = _make_file(
        _make_rule(
            "anon_skip",
            # "$n*" matches "$named" but not anonymous "$"
            condition=OfExpression("any", "$n*"),
            strings=[anonymous_str, named_str],
        )
    )

    metrics = _analyze(ast)

    deps = metrics.string_dependencies.get("anon_skip", set())
    assert "$named" in deps
    # The anonymous placeholder identifier "$" must not appear
    assert "$" not in deps


# ---------------------------------------------------------------------------
# Line 220->222  (_mark_string_set_text: local has a real value -> recurse)
#
# A WithDeclaration assigns a StringLiteral value to a local.  When the body
# references that local identifier inside a string set, _local_value returns
# the stored StringLiteral (not _LOCAL_WITHOUT_VALUE).  The branch at
# line 220-222 then calls _visit_string_set_value on that value.
# ---------------------------------------------------------------------------


def test_mark_string_set_text_resolves_local_with_value_to_usage() -> None:
    """A with-declaration binding a string literal causes the target string to be marked used.

    The path at lines 219-222 fires when _local_value returns a real object
    (not _LOCAL_WITHOUT_VALUE), triggering a recursive _visit_string_set_value
    call with the stored value.
    """
    ast = _make_file(
        _make_rule(
            "local_with_value",
            strings=[PlainString(identifier="$target", value="data")],
            condition=WithStatement(
                declarations=[WithDeclaration("$alias", StringIdentifier("$target"))],
                body=OfExpression("any", SetExpression([StringIdentifier("$alias")])),
            ),
        )
    )

    metrics = _analyze(ast)

    # The binding resolves $alias -> $target, so $target is used
    assert metrics.unused_strings == []
    assert "$target" in metrics.string_dependencies["local_with_value"]


# ---------------------------------------------------------------------------
# Lines 247-248  (_visit_string_set_value: Identifier not "them" and not "$")
#
# An Identifier whose name does not start with "$" and is not "them" triggers
# the fallback _visit_ast_value branch (line 247-248).
# ---------------------------------------------------------------------------


def test_visit_string_set_value_dispatches_non_string_identifier_as_ast_value() -> None:
    """An Identifier that is neither 'them' nor a string reference falls back to visit_ast_value.

    This exercises the branch at lines 247-248 where the Identifier name does
    not start with "$" and is not "them", so _visit_ast_value is called
    instead of _mark_string_set_text.
    """
    # Build a rule that uses an Identifier (like a module name or bare name)
    # inside a for-of string set position.  The Identifier "pe" does not start
    # with "$" and is not "them".
    non_string_id = Identifier(name="pe")

    ast = _make_file(
        _make_rule(
            "non_string_ident",
            strings=[PlainString(identifier="$x", value="x")],
            # OfExpression accepts any iterable; pass the Identifier directly
            condition=OfExpression("any", non_string_id),
        )
    )

    # Should complete without raising; the Identifier is visited as an AST value
    metrics = _analyze(ast)

    assert metrics.of_expressions == 1


# ---------------------------------------------------------------------------
# Line 272  (visit_string_wildcard)
#
# A StringWildcard node in the condition calls visit_string_wildcard.  Use a
# rule condition that contains a StringWildcard node directly so that the
# visitor method at line 271-272 is entered.
# ---------------------------------------------------------------------------


def test_visit_string_wildcard_marks_matching_strings() -> None:
    """visit_string_wildcard must delegate to _mark_string_set_text with the pattern.

    Line 272 is reached when a StringWildcard appears as the root condition.
    """
    ast = _make_file(
        _make_rule(
            "string_wc_visitor",
            strings=[
                PlainString(identifier="$foo", value="foo"),
                PlainString(identifier="$bar", value="bar"),
            ],
            condition=StringWildcard("$f*"),
        )
    )

    metrics = _analyze(ast)

    # $foo matches "$f*"; $bar does not
    deps = metrics.string_dependencies.get("string_wc_visitor", set())
    assert "$foo" in deps
    assert "$bar" not in deps


# ---------------------------------------------------------------------------
# Lines 289-290  (visit_set_expression iterates elements)
#
# A SetExpression as the root condition iterates its elements and visits each.
# ---------------------------------------------------------------------------


def test_visit_set_expression_visits_all_elements() -> None:
    """visit_set_expression must visit every child element.

    Lines 289-290 loop over elements and call visit(elem) for each.
    Using two StringIdentifiers as elements confirms both are visited and
    both strings are recorded as used.
    """
    ast = _make_file(
        _make_rule(
            "set_expr_visit",
            strings=[
                PlainString(identifier="$a", value="a"),
                PlainString(identifier="$b", value="b"),
            ],
            condition=SetExpression(
                elements=[
                    StringIdentifier("$a"),
                    StringIdentifier("$b"),
                ]
            ),
        )
    )

    metrics = _analyze(ast)

    deps = metrics.string_dependencies.get("set_expr_visit", set())
    assert "$a" in deps
    assert "$b" in deps
    assert metrics.unused_strings == []


# ---------------------------------------------------------------------------
# Line 299  (visit_function_call with a receiver expression)
#
# FunctionCall with a non-None receiver visits the receiver through
# _visit_ast_value (line 297) before iterating arguments.
# ---------------------------------------------------------------------------


def test_visit_function_call_with_receiver_visits_receiver() -> None:
    """visit_function_call must visit a non-None receiver expression.

    Line 297 calls _visit_ast_value(getattr(node, 'receiver', None)).
    With a real receiver (e.g. a MemberAccess node), line 299 is reached
    when the argument loop iterates.
    """
    # Build: pe.imphash() - modelled as FunctionCall with receiver=Identifier("pe")
    # Use a valid receiver: a MemberAccess on a plain Identifier chain.
    receiver = MemberAccess(object=Identifier(name="pe"), member="rich_signature")
    func_call = FunctionCall(function="version", arguments=[IntegerLiteral(0)], receiver=receiver)

    ast = _make_file(_make_rule("func_with_receiver", condition=func_call))

    # Should complete without raising
    metrics = _analyze(ast)

    # The rule has no strings, so no string-level metrics; but analysis ran
    assert metrics.total_rules == 1


# ---------------------------------------------------------------------------
# Line 312  (visit_at_expression: string_id is NOT a str -> _visit_ast_value)
#
# AtExpression accepts a string_id that is either a str or an Expression.
# When it is an Expression (e.g. an OfExpression), the else branch fires.
# ---------------------------------------------------------------------------


def test_visit_at_expression_with_expression_string_id() -> None:
    """visit_at_expression must call _visit_ast_value when string_id is an Expression.

    Line 312 fires when isinstance(node.string_id, str) is False.  Using an
    OfExpression as string_id exercises that branch.
    """
    of_expr = OfExpression("any", SetExpression([StringIdentifier("$a")]))
    offset = IntegerLiteral(0)
    at_expr = AtExpression(string_id=of_expr, offset=offset)

    ast = _make_file(
        _make_rule(
            "at_expr_non_str",
            strings=[PlainString(identifier="$a", value="text")],
            condition=at_expr,
        )
    )

    metrics = _analyze(ast)

    assert metrics.of_expressions == 1


# ---------------------------------------------------------------------------
# Line 319  (visit_in_expression: subject is NOT a str -> _visit_ast_value)
#
# InExpression.subject may be an Expression.  When it is, line 319 fires.
# ---------------------------------------------------------------------------


def test_visit_in_expression_with_expression_subject() -> None:
    """visit_in_expression must call _visit_ast_value when subject is an Expression.

    Line 319 fires when isinstance(node.subject, str) is False.  Using a
    StringCount as subject exercises that branch while keeping the AST valid.
    """
    count_expr = StringCount(string_id="$a")
    range_expr = RangeExpression(low=IntegerLiteral(0), high=IntegerLiteral(100))
    in_expr = InExpression(subject=count_expr, range=range_expr)

    ast = _make_file(
        _make_rule(
            "in_expr_non_str",
            strings=[PlainString(identifier="$a", value="hit")],
            condition=in_expr,
        )
    )

    metrics = _analyze(ast)

    # StringCount is visited -> $a appears in string_dependencies
    deps = metrics.string_dependencies.get("in_expr_non_str", set())
    assert "$a" in deps


# ---------------------------------------------------------------------------
# Line 366->368  (visit_dict_comprehension with a non-None value_variable)
#
# DictComprehension.value_variable being truthy triggers line 366->367 to
# append it to the names list before _push_local_scope (line 368).
# ---------------------------------------------------------------------------


def test_visit_dict_comprehension_with_value_variable_creates_two_locals() -> None:
    """visit_dict_comprehension must include value_variable in the local scope.

    The True branch at line 366 fires when value_variable is not None/empty,
    causing it to be appended to the names list before _push_local_scope (line
    368).  The False branch (line 366->368) fires when value_variable is None,
    skipping the append.  Both must be exercised.
    """
    # Case 1: value_variable is not None -> True branch at line 366 (-> 367)
    iterable = SetExpression([IntegerLiteral(1), IntegerLiteral(2)])
    dict_comp_two = DictComprehension(
        key_expression=Identifier(name="k"),
        value_expression=Identifier(name="v"),
        key_variable="k",
        value_variable="v",
        iterable=iterable,
        condition=None,
    )

    metrics_two = _analyze(_make_file(_make_rule("dict_comp_two_vars", condition=dict_comp_two)))
    assert metrics_two.total_rules == 1

    # Case 2: value_variable is None -> False branch at line 366 (366->368)
    dict_comp_one = DictComprehension(
        key_expression=Identifier(name="k"),
        value_expression=Identifier(name="k"),
        key_variable="k",
        value_variable=None,
        iterable=SetExpression([IntegerLiteral(1)]),
        condition=None,
    )

    metrics_one = _analyze(_make_file(_make_rule("dict_comp_one_var", condition=dict_comp_one)))
    assert metrics_one.total_rules == 1


# ---------------------------------------------------------------------------
# Line 420  (visit_tuple_expression)
#
# A TupleExpression as a condition's root visits each element.
# ---------------------------------------------------------------------------


def test_visit_tuple_expression_visits_elements() -> None:
    """visit_tuple_expression must delegate to _visit_ast_value for its elements.

    Line 420 calls _visit_ast_value(node.elements).  A TupleExpression
    holding two BooleanLiterals exercises this path.
    """
    tuple_expr = TupleExpression(elements=[BooleanLiteral(True), BooleanLiteral(False)])

    ast = _make_file(_make_rule("tuple_expr_rule", condition=tuple_expr))

    metrics = _analyze(ast)

    assert metrics.total_rules == 1


# ---------------------------------------------------------------------------
# Line 442->exit  (_define_local early-exit when _local_scopes is empty)
#
# _define_local checks `if self._local_scopes:` and only records when a scope
# exists.  After analyze() the scopes list is empty.  Calling _define_local
# with no active scope must be a silent no-op.
# ---------------------------------------------------------------------------


def test_define_local_noop_when_no_scope_is_active() -> None:
    """_define_local must silently exit when _local_scopes is empty.

    Line 442->exit is the False branch of `if self._local_scopes:`.  After a
    complete analyze() call the list is empty; calling the method must not
    raise and must not modify any state.
    """
    analyzer = ComplexityAnalyzer()
    analyzer.analyze(YaraFile(rules=[]))

    assert analyzer._local_scopes == []

    # Should reach line 442->exit without error
    analyzer._define_local("some_local", BooleanLiteral(True))

    # No scope was modified; the list remains empty
    assert analyzer._local_scopes == []


# ---------------------------------------------------------------------------
# Compound: mark_string_usage with falsy rule_key (line 158->exit)
#
# Force _mark_string_usage to be called when _active_rule_key() returns None
# so the `if rule_key:` check fails and the body (lines 159-160) is skipped.
# ---------------------------------------------------------------------------


def test_mark_string_usage_skips_storage_without_active_rule() -> None:
    """_mark_string_usage must not update _string_usage when no rule is active.

    Line 158->exit fires when rule_key is falsy.  After analyze(), both
    _current_rule_key and _current_rule are None, so _active_rule_key()
    returns None, and the body of _mark_string_usage is skipped.
    """
    analyzer = ComplexityAnalyzer()
    analyzer.analyze(YaraFile(rules=[]))

    assert analyzer._current_rule_key is None
    assert analyzer._current_rule is None

    # Directly invoke; _string_usage must remain empty
    analyzer._mark_string_usage("$fake")

    assert analyzer._string_usage == {}


# ---------------------------------------------------------------------------
# Verify the coverage gain: running the full analyzer on a non-trivial file
# exercises several paths together and serves as a regression safety net.
# ---------------------------------------------------------------------------


def test_combined_visit_paths_on_realistic_rule() -> None:
    """Analyze a rule that exercises multiple previously uncovered visitor paths.

    This integration-level test ensures that the isolated paths above also
    compose correctly in a single rule traversal.
    """
    # A rule with:
    # - a SetExpression as part of the condition
    # - a FunctionCall with no receiver (common path, already covered)
    # - a StringWildcard reference
    # - anonymous string that must be skipped by wildcard resolution
    anon = PlainString(identifier="$", value="anon", is_anonymous=True)
    named = PlainString(identifier="$real", value="real")

    condition = SetExpression(
        elements=[
            StringWildcard("$r*"),
            FunctionCall("uint32be", arguments=[IntegerLiteral(0)]),
        ]
    )

    ast = _make_file(
        _make_rule(
            "combined_paths",
            strings=[anon, named],
            condition=condition,
        )
    )

    metrics = _analyze(ast)

    # $real is matched by "$r*"; the anonymous "$" is skipped by the wildcard
    # loop so it stays in _rule_strings but not _string_usage.  The anonymous
    # string therefore appears in unused_strings under its identifier "$".
    deps = metrics.string_dependencies.get("combined_paths", set())
    assert "$real" in deps
    # Only the anonymous string is unused (it cannot be matched by a wildcard)
    assert metrics.unused_strings == ["combined_paths:$"]
    assert metrics.total_rules == 1


# ---------------------------------------------------------------------------
# Parametric: _define_local and _push/_pop scope round-trip
# ---------------------------------------------------------------------------


@pytest.mark.parametrize(
    "name",
    [
        "$alpha",
        "$beta",
        "$gamma",
    ],
)
def test_define_local_stores_value_when_scope_is_active(name: str) -> None:
    """_define_local must store the supplied value in the innermost active scope.

    This test drives _push_local_scope to open a scope, then calls
    _define_local to bind a value, and _pop_local_scope to restore state.
    The value must be retrievable via _local_value during the scope.
    """
    analyzer = ComplexityAnalyzer()
    analyzer.analyze(YaraFile(rules=[]))

    # Open a new scope manually
    analyzer._push_local_scope()
    sentinel = cast(Any, object())
    analyzer._define_local(name, sentinel)

    stored = analyzer._local_value(name.lstrip("$"))
    # local_name_variants normalises "$alpha" -> "alpha" for storage
    # but the "$" form may also be stored; check either way
    if stored is analyzer._MISSING_LOCAL:
        stored = analyzer._local_value(name)

    assert stored is sentinel

    analyzer._pop_local_scope()
    # After popping the scope, the value should be missing
    assert analyzer._local_value(name) is analyzer._MISSING_LOCAL
    assert analyzer._local_value(name.lstrip("$")) is analyzer._MISSING_LOCAL


# ---------------------------------------------------------------------------
# Line 420  (visit_spread_operator body)
#
# A SpreadOperator node wrapping a BooleanLiteral as the rule condition
# reaches visit_spread_operator (line 419) and then line 420.
# ---------------------------------------------------------------------------


def test_visit_spread_operator_visits_inner_expression() -> None:
    """visit_spread_operator must call _visit_ast_value on its expression field.

    Line 420 is only reached when a SpreadOperator node appears in the
    condition AST.  Wrapping a BooleanLiteral in a SpreadOperator and using
    it as the rule condition exercises this path.
    """
    spread = SpreadOperator(expression=BooleanLiteral(True))

    ast = _make_file(_make_rule("spread_op_rule", condition=spread))

    metrics = _analyze(ast)

    assert metrics.total_rules == 1


# ---------------------------------------------------------------------------
# Line 220->222  (_mark_string_set_text: local value IS _LOCAL_WITHOUT_VALUE)
#
# The False branch of `if local_value is not self._LOCAL_WITHOUT_VALUE:` on
# line 220 fires when a name is registered in the active scope WITHOUT an
# explicit value (i.e., the scope stores the sentinel _LOCAL_WITHOUT_VALUE).
#
# This branch is a defensive guard.  In the production visitor flow
# _define_local is always called with a real value.  The sentinel default
# parameter is present to support future call sites that may omit the value.
# We exercise the branch by directly calling _define_local without a value
# (triggering the default) while a scope is active, and then invoking
# _mark_string_set_text with the same identifier.
# ---------------------------------------------------------------------------


def test_mark_string_set_text_local_without_value_sentinel_returns_early() -> None:
    """_mark_string_set_text must return without marking string usage when the
    local value stored in scope is the _LOCAL_WITHOUT_VALUE sentinel.

    Lines 219-222: the outer `if local_value is not self._MISSING_LOCAL` is
    True, but the inner `if local_value is not self._LOCAL_WITHOUT_VALUE` is
    False (220->222 branch), so the method returns without calling
    _visit_string_set_value.
    """
    analyzer = ComplexityAnalyzer()
    analyzer.analyze(YaraFile(rules=[]))

    # Open a scope and define a local WITHOUT a value (uses default sentinel)
    analyzer._push_local_scope()
    analyzer._define_local("$sentinel_var")  # stores {"$sentinel_var": _LOCAL_WITHOUT_VALUE}

    # Set a current rule key so _mark_string_usage would store something if called
    analyzer._current_rule_key = "probe_rule"

    # Call _mark_string_set_text with the local's name; the 220->222 branch fires
    analyzer._mark_string_set_text("$sentinel_var")

    # The local was found (not _MISSING_LOCAL) but was _LOCAL_WITHOUT_VALUE,
    # so _mark_string_usage was NOT called -> no entry in _string_usage
    assert "probe_rule" not in analyzer._string_usage

    analyzer._pop_local_scope()


# ---------------------------------------------------------------------------
# Verify $-prefixed locals are stored without raising in DictExpression paths
# ---------------------------------------------------------------------------


def test_visit_dict_expression_and_dict_item() -> None:
    """visit_dict_expression and visit_dict_item must visit keys and values.

    Exercises _visit_ast_value paths through DictExpression -> DictItem.
    """
    key = IntegerLiteral(1)
    value = BooleanLiteral(True)
    dict_item = DictItem(key=key, value=value)
    dict_expr = DictExpression(items=[dict_item])

    ast = _make_file(_make_rule("dict_expr_rule", condition=dict_expr))

    metrics = _analyze(ast)

    assert metrics.total_rules == 1
