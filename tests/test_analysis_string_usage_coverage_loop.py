# Copyright (c) 2026 Marc Rivero López
# Licensed under GPLv3. See LICENSE file for details.
# This test suite validates real code behavior without mocks or stubs.

"""
Coverage-loop tests for yaraast.analysis.string_usage.

Exercises the specific code paths not reached by
tests/test_analysis_string_usage_more.py, identified from a branch-level
coverage report.  Every test uses the real parser or the real AST builder,
invokes the production StringUsageAnalyzer, and asserts on concrete
observable state.

Missing lines before this file (84.55%):
  114, 135, 193, 204, 207, 213->exit, 243-246, 255,
  297-303, 306-316, 319-323, 345->exit, 353-354,
  368-371, 390, 404->406, 431-432, 437, 441,
  446-447, 453-454, 460, 477, 486, 490-491, 493
"""

from __future__ import annotations

from typing import Any

import pytest

from yaraast.analysis.string_usage import StringUsageAnalyzer
from yaraast.ast.base import YaraFile
from yaraast.ast.conditions import (
    AtExpression,
    ForExpression,
    ForOfExpression,
    InExpression,
    OfExpression,
)
from yaraast.ast.expressions import (
    BinaryExpression,
    Identifier,
    IntegerLiteral,
    ParenthesesExpression,
    SetExpression,
    StringCount,
    StringIdentifier,
    StringLiteral,
    StringWildcard,
)
from yaraast.ast.rules import Rule
from yaraast.ast.strings import PlainString
from yaraast.parser import Parser
from yaraast.yarax.ast_nodes import (
    ArrayComprehension,
    DictComprehension,
    LambdaExpression,
    WithDeclaration,
    WithStatement,
)

# ---------------------------------------------------------------------------
# Helper: build a pre-analyzed analyzer with two rules, one unused, one
# undefined, so that the "all-rules" branches in get_unused_strings /
# get_undefined_strings (lines 114, 135) are reachable without a rule_name.
# ---------------------------------------------------------------------------


def _make_analyzed_two_rule_ast() -> StringUsageAnalyzer:
    ast = Parser().parse("""
rule has_unused {
    strings:
        $used   = "u"
        $unused = "x"
    condition:
        $used
}
rule has_undefined {
    strings:
        $present = "p"
    condition:
        $present and $missing
}
""")
    analyzer = StringUsageAnalyzer()
    analyzer.analyze(ast)
    return analyzer


# ---------------------------------------------------------------------------
# Lines 114, 135 — get_unused_strings / get_undefined_strings all-rules branch
# Only entries that have something to report are inserted into the dict.
# ---------------------------------------------------------------------------


def test_get_unused_strings_all_rules_only_returns_rules_with_unused() -> None:
    """
    Line 114: ``unused[rule] = unused_in_rule`` — reached only when at least
    one string in the rule is unused and the caller omits rule_name.
    """
    analyzer = _make_analyzed_two_rule_ast()

    result = analyzer.get_unused_strings()

    assert "has_unused" in result
    assert "$unused" in result["has_unused"]
    # has_undefined used its only defined string — must not appear in result
    assert "has_undefined" not in result


def test_get_undefined_strings_all_rules_only_returns_rules_with_undefined() -> None:
    """
    Line 135: ``undefined[rule] = undefined_in_rule`` — reached only when at
    least one string used in the condition was never defined.
    """
    analyzer = _make_analyzed_two_rule_ast()

    result = analyzer.get_undefined_strings()

    assert "has_undefined" in result
    assert "$missing" in result["has_undefined"]
    # has_unused has no undefined references — must not appear
    assert "has_unused" not in result


# ---------------------------------------------------------------------------
# Line 193 — visit_string_definition with is_anonymous=True and identifier=="$"
# The analyzer must store the bare "$" key for an anonymous placeholder string.
# ---------------------------------------------------------------------------


def test_visit_string_definition_bare_anonymous_dollar_stored_as_dollar() -> None:
    """
    Line 193: ``normalized = "$"`` — reached when a string node has
    is_anonymous=True and its identifier is literally "$".
    """
    ast = YaraFile(
        rules=[
            Rule(
                name="anon_rule",
                strings=[PlainString(identifier="$", value="v", is_anonymous=True)],
                condition=ForOfExpression("any", "them", condition=None),
            )
        ]
    )

    result = StringUsageAnalyzer().analyze(ast)

    assert result["anon_rule"]["defined"] == ["$"]
    assert result["anon_rule"]["unused"] == []


# ---------------------------------------------------------------------------
# Lines 204, 207 — visit_hex_string / visit_regex_string
# Both delegate to visit_string_definition.  Use the real parser so the
# HexString and RegexString nodes are structurally valid.
# ---------------------------------------------------------------------------


def test_visit_hex_string_registers_hex_string_as_defined() -> None:
    """Line 204: visit_hex_string dispatches to visit_string_definition."""
    ast = Parser().parse("""
rule hex_rule {
    strings:
        $hex = { 41 42 43 }
    condition:
        $hex
}
""")

    result = StringUsageAnalyzer().analyze(ast)

    assert result["hex_rule"]["defined"] == ["$hex"]
    assert result["hex_rule"]["unused"] == []


def test_visit_regex_string_registers_regex_string_as_defined() -> None:
    """Line 207: visit_regex_string dispatches to visit_string_definition."""
    ast = Parser().parse("""
rule regex_rule {
    strings:
        $re = /needle/i
    condition:
        $re
}
""")

    result = StringUsageAnalyzer().analyze(ast)

    assert result["regex_rule"]["defined"] == ["$re"]
    assert result["regex_rule"]["unused"] == []


# ---------------------------------------------------------------------------
# Line 213->exit — visit_string_wildcard returns early when
# _is_explicit_string_wildcard returns False (not in a condition / no rule).
# ---------------------------------------------------------------------------


def test_visit_string_wildcard_does_nothing_outside_condition() -> None:
    """
    Line 213->exit: visit_string_wildcard exits without marking strings when
    _is_explicit_string_wildcard returns False because in_condition is False.
    """
    analyzer = StringUsageAnalyzer()
    analyzer.current_rule = "rule1"
    analyzer.defined_strings["rule1"] = {"$a"}
    analyzer.used_strings["rule1"] = set()
    analyzer.in_condition = False  # wildcard check will return False

    analyzer.visit_string_wildcard(StringWildcard("$a*"))

    assert analyzer.used_strings["rule1"] == set()


# ---------------------------------------------------------------------------
# Lines 243-246 — visit_at_expression when string_id has an accept method
# (i.e. it is an AST expression node, not a plain string).
# ---------------------------------------------------------------------------


def test_visit_at_expression_with_expression_string_id() -> None:
    """
    Lines 243-246: visit_at_expression when string_id is an Identifier (has
    .accept), so the visitor delegates to self.visit rather than the string
    reference handler.
    """
    analyzer = StringUsageAnalyzer()
    analyzer.current_rule = "manual"
    analyzer.current_rule_key = "manual"
    analyzer.defined_strings["manual"] = {"$a"}
    analyzer.used_strings["manual"] = set()
    analyzer.invalid_comparison_string_references["manual"] = set()
    analyzer.in_condition = True

    # Identifier has an .accept method — triggers the hasattr(node.string_id, "accept") branch
    at_expr = AtExpression(Identifier("module.member"), IntegerLiteral(0))
    analyzer.visit_at_expression(at_expr)

    # No string was marked used because the subject is a non-string Identifier
    assert analyzer.used_strings["manual"] == set()


# ---------------------------------------------------------------------------
# Line 255 — visit_in_expression when subject has an accept method
# ---------------------------------------------------------------------------


def test_visit_in_expression_with_expression_subject() -> None:
    """
    Line 255: visit_in_expression when subject is an Identifier (has .accept),
    delegating to self.visit rather than the string reference path.
    """
    analyzer = StringUsageAnalyzer()
    analyzer.current_rule = "manual"
    analyzer.current_rule_key = "manual"
    analyzer.defined_strings["manual"] = {"$a"}
    analyzer.used_strings["manual"] = set()
    analyzer.invalid_comparison_string_references["manual"] = set()
    analyzer.in_condition = True

    in_expr = InExpression(Identifier("module.function"), IntegerLiteral(5))
    analyzer.visit_in_expression(in_expr)

    assert analyzer.used_strings["manual"] == set()


# ---------------------------------------------------------------------------
# Lines 297-303 — visit_for_expression: quantifier, iterable, local scope,
# body are all processed.
# ---------------------------------------------------------------------------


def test_visit_for_expression_tracks_body_string_within_local_scope() -> None:
    """
    Lines 297-303: visit_for_expression pushes a local scope for the loop
    variable, visits the body within it, then pops the scope.
    """
    analyzer = StringUsageAnalyzer()
    analyzer.current_rule = "manual"
    analyzer.current_rule_key = "manual"
    analyzer.defined_strings["manual"] = {"$a", "$b"}
    analyzer.used_strings["manual"] = set()
    analyzer.invalid_comparison_string_references["manual"] = set()
    analyzer.in_condition = True

    fe = ForExpression(
        quantifier=IntegerLiteral(1),
        variable="i",
        iterable=SetExpression([IntegerLiteral(1), IntegerLiteral(2)]),
        body=StringIdentifier("$a"),
    )
    analyzer.visit_for_expression(fe)

    assert "$a" in analyzer.used_strings["manual"]
    # Local scope must be cleaned up after the visit
    assert analyzer.local_scopes == []


def test_visit_for_expression_quantifier_as_string_count_marks_string_used() -> None:
    """
    Lines 297-303: when the quantifier is itself a StringCount node,
    _visit_ast_value dispatches to visit on it so the string is recorded used.
    """
    analyzer = StringUsageAnalyzer()
    analyzer.current_rule = "manual"
    analyzer.current_rule_key = "manual"
    analyzer.defined_strings["manual"] = {"$a", "$b"}
    analyzer.used_strings["manual"] = set()
    analyzer.invalid_comparison_string_references["manual"] = set()
    analyzer.in_condition = True

    fe = ForExpression(
        quantifier=StringCount("$b"),
        variable="i",
        iterable=SetExpression([IntegerLiteral(1)]),
        body=StringIdentifier("$a"),
    )
    analyzer.visit_for_expression(fe)

    assert analyzer.used_strings["manual"] == {"$a", "$b"}


# ---------------------------------------------------------------------------
# Lines 306-316, 319-323 — visit_with_statement / visit_with_declaration
# ---------------------------------------------------------------------------


def test_visit_with_statement_visits_declarations_and_body() -> None:
    """
    Lines 306-316, 319-323: visit_with_statement pushes a local scope,
    visits each declaration (which calls visit_with_declaration), then
    visits the body, and finally pops the scope.
    """
    analyzer = StringUsageAnalyzer()
    analyzer.current_rule = "manual"
    analyzer.current_rule_key = "manual"
    analyzer.defined_strings["manual"] = {"$a"}
    analyzer.used_strings["manual"] = set()
    analyzer.invalid_comparison_string_references["manual"] = set()
    analyzer.in_condition = True

    ws = WithStatement(
        declarations=[WithDeclaration("x", IntegerLiteral(42))],
        body=StringIdentifier("$a"),
    )
    analyzer.visit_with_statement(ws)

    assert "$a" in analyzer.used_strings["manual"]
    assert analyzer.local_scopes == []


def test_visit_with_declaration_value_that_is_string_identifier_marks_string() -> None:
    """
    Lines 319-323: visit_with_declaration calls _visit_ast_value on the value
    (visiting its AST node) and _define_local to register the binding.  When
    the value is a StringIdentifier, visiting it marks the string as used.
    """
    analyzer = StringUsageAnalyzer()
    analyzer.current_rule = "manual"
    analyzer.current_rule_key = "manual"
    analyzer.defined_strings["manual"] = {"$a"}
    analyzer.used_strings["manual"] = set()
    analyzer.invalid_comparison_string_references["manual"] = set()
    analyzer.in_condition = True

    # Push a scope first so _define_local has somewhere to write
    analyzer._push_local_scope("placeholder")

    wd = WithDeclaration("y", StringIdentifier("$a"))
    analyzer.visit_with_declaration(wd)

    assert "$a" in analyzer.used_strings["manual"]


# ---------------------------------------------------------------------------
# Line 345->exit — _define_local when local_scopes is empty: must be a no-op.
# ---------------------------------------------------------------------------


def test_define_local_with_empty_scope_stack_is_noop() -> None:
    """
    Line 345->exit: _define_local exits immediately when local_scopes is empty,
    without raising any error.
    """
    analyzer = StringUsageAnalyzer()
    assert analyzer.local_scopes == []

    # Must not raise
    analyzer._define_local("some_var")

    assert analyzer.local_scopes == []


# ---------------------------------------------------------------------------
# Lines 353-354 — _visit_ast_value when value is a list of AST nodes.
# ---------------------------------------------------------------------------


def test_visit_ast_value_with_list_visits_each_element() -> None:
    """
    Lines 353-354: _visit_ast_value iterates over a list and visits each item.
    Providing a list of StringIdentifiers causes each to be recorded as used.
    """
    analyzer = StringUsageAnalyzer()
    analyzer.current_rule = "manual"
    analyzer.current_rule_key = "manual"
    analyzer.defined_strings["manual"] = {"$a", "$b"}
    analyzer.used_strings["manual"] = set()
    analyzer.invalid_comparison_string_references["manual"] = set()
    analyzer.in_condition = True

    analyzer._visit_ast_value([StringIdentifier("$a"), StringIdentifier("$b")])

    assert analyzer.used_strings["manual"] == {"$a", "$b"}


# ---------------------------------------------------------------------------
# Lines 368-371 — _visit_string_set_value when string_set is an Identifier
# whose name does not start with "$" and is not "them".
# Falls through to _visit_ast_value(string_set).
# ---------------------------------------------------------------------------


def test_visit_string_set_value_identifier_not_string_ref_calls_visit_ast_value() -> None:
    """
    Lines 368-371: when _visit_string_set_value receives an Identifier whose
    name is neither "them" nor starts with "$", it calls _visit_ast_value on
    the node itself (used for module-qualified identifiers like pe.MACHINE_I386).
    """
    analyzer = StringUsageAnalyzer()
    analyzer.current_rule = "manual"
    analyzer.current_rule_key = "manual"
    analyzer.defined_strings["manual"] = set()
    analyzer.used_strings["manual"] = set()
    analyzer.in_condition = True

    # A plain module member — not a string reference
    analyzer._visit_string_set_value(Identifier("pe.machine"))

    # Nothing is marked as a string usage — the visit descends via _visit_ast_value
    assert analyzer.used_strings["manual"] == set()


# ---------------------------------------------------------------------------
# Line 390 — _visit_string_set_value fallthrough to _visit_ast_value
# when the node is not any of the recognised types.
# ---------------------------------------------------------------------------


def test_visit_string_set_value_unrecognised_type_falls_through_to_visit_ast_value() -> None:
    """
    Line 390: the final catch-all in _visit_string_set_value calls
    _visit_ast_value for objects not matched by any of the earlier isinstance
    guards.  An IntegerLiteral is a valid AST node that fits this path.
    """
    analyzer = StringUsageAnalyzer()
    analyzer.current_rule = "manual"
    analyzer.current_rule_key = "manual"
    analyzer.defined_strings["manual"] = set()
    analyzer.used_strings["manual"] = set()
    analyzer.in_condition = True

    # IntegerLiteral is not a str, list/tuple/set, Identifier, StringLiteral,
    # StringIdentifier, StringWildcard, ParenthesesExpression, or SetExpression.
    analyzer._visit_string_set_value(IntegerLiteral(99))

    assert analyzer.used_strings["manual"] == set()


# ---------------------------------------------------------------------------
# Line 404->406 — _mark_string_set_text: local_value is not MISSING and not
# LOCAL_WITHOUT_VALUE, so it re-visits the stored value.
# ---------------------------------------------------------------------------


def test_mark_string_set_text_resolves_local_bound_to_string_literal() -> None:
    """
    Lines 404->406: _mark_string_set_text resolves a local variable whose
    stored value is a concrete AST node (StringLiteral pointing at "$a") and
    recursively visits it, ultimately marking "$a" as used.
    """
    ast = YaraFile(
        rules=[
            Rule(
                name="local_resolve",
                strings=[PlainString("$a", value="needle")],
                condition=WithStatement(
                    declarations=[WithDeclaration("$x", StringLiteral("$a"))],
                    body=OfExpression(
                        "any",
                        SetExpression([StringIdentifier("$x")]),
                    ),
                ),
            )
        ]
    )

    result = StringUsageAnalyzer().analyze(ast)

    assert result["local_resolve"]["used"] == ["$a"]
    assert result["local_resolve"]["unused"] == []
    assert result["local_resolve"]["undefined"] == []


# ---------------------------------------------------------------------------
# Lines 431-432 — _mark_invalid_comparison_string_operand: ParenthesesExpression
# wrapping a StringIdentifier.
# ---------------------------------------------------------------------------


def test_mark_invalid_comparison_string_operand_unwraps_parentheses() -> None:
    """
    Lines 431-432: _mark_invalid_comparison_string_operand recurses when it
    sees a ParenthesesExpression, eventually reaching the inner StringIdentifier.
    """
    analyzer = StringUsageAnalyzer()
    analyzer.current_rule = "manual"
    analyzer.current_rule_key = "manual"
    analyzer.defined_strings["manual"] = {"$a"}
    analyzer.used_strings["manual"] = set()
    analyzer.invalid_comparison_string_references["manual"] = set()
    analyzer.in_condition = True

    paren = ParenthesesExpression(StringIdentifier("$a"))
    analyzer._mark_invalid_comparison_string_operand(paren)

    assert "$a" in analyzer.invalid_comparison_string_references["manual"]


# ---------------------------------------------------------------------------
# Line 437 — _mark_invalid_comparison_string_operand returns early when
# there is no active rule key.
# ---------------------------------------------------------------------------


def test_mark_invalid_comparison_string_operand_noop_without_rule_key() -> None:
    """
    Line 437: when current_rule_key and current_rule are both None, the method
    returns immediately without touching any collection.
    """
    analyzer = StringUsageAnalyzer()
    analyzer.current_rule = None
    analyzer.current_rule_key = None

    # Should not raise even though invalid_comparison_string_references is empty
    analyzer._mark_invalid_comparison_string_operand(StringIdentifier("$a"))


# ---------------------------------------------------------------------------
# Line 441 — _mark_invalid_comparison_string_operand skips strings that are
# in a local scope.
# ---------------------------------------------------------------------------


def test_mark_invalid_comparison_string_operand_skips_local_shadow() -> None:
    """
    Line 441: when the string identifier is shadowed by an enclosing local
    scope, the operand is not recorded as an invalid comparison reference.
    """
    analyzer = StringUsageAnalyzer()
    analyzer.current_rule = "manual"
    analyzer.current_rule_key = "manual"
    analyzer.defined_strings["manual"] = {"$a"}
    analyzer.used_strings["manual"] = set()
    analyzer.invalid_comparison_string_references["manual"] = set()
    analyzer.in_condition = True
    analyzer.local_scopes = [{"$a": object()}]

    analyzer._mark_invalid_comparison_string_operand(StringIdentifier("$a"))

    assert analyzer.invalid_comparison_string_references["manual"] == set()


# ---------------------------------------------------------------------------
# Lines 446-447 — _require_string_reference raises TypeError for non-string.
# ---------------------------------------------------------------------------


def test_require_string_reference_raises_type_error_for_non_string() -> None:
    """
    Lines 446-447: _require_string_reference raises TypeError when the
    argument is not a str.
    """
    analyzer = StringUsageAnalyzer()

    with pytest.raises(TypeError, match="String reference must be a string"):
        analyzer._require_string_reference(42)


# ---------------------------------------------------------------------------
# Lines 453-454 — _required_expression raises TypeError for non-Expression.
# ---------------------------------------------------------------------------


def test_required_expression_raises_type_error_for_non_expression() -> None:
    """
    Lines 453-454: _required_expression raises TypeError when the argument
    is not an Expression subclass.
    """
    analyzer = StringUsageAnalyzer()

    with pytest.raises(TypeError, match="offset field must be an Expression"):
        analyzer._required_expression(99, "offset field")


# ---------------------------------------------------------------------------
# Line 460 — _mark_wildcard_string_set returns immediately when rule_key is None.
# ---------------------------------------------------------------------------


def test_mark_wildcard_string_set_noop_without_rule_key() -> None:
    """
    Line 460: _mark_wildcard_string_set exits without error when no rule is
    active (both current_rule and current_rule_key are None).
    """
    analyzer = StringUsageAnalyzer()
    analyzer.current_rule = None
    analyzer.current_rule_key = None

    # Must not raise and must not touch any data structure
    analyzer._mark_wildcard_string_set("$abc*")


# ---------------------------------------------------------------------------
# Line 477 — _mark_wildcard_string_set stores the raw normalised pattern when
# no defined strings match the wildcard.
# ---------------------------------------------------------------------------


def test_mark_wildcard_string_set_stores_pattern_when_no_matches() -> None:
    """
    Line 477: when the wildcard matches no defined strings, the normalised
    wildcard pattern itself is recorded in used_strings as a sentinel.
    """
    analyzer = StringUsageAnalyzer()
    analyzer.current_rule = "manual"
    analyzer.current_rule_key = "manual"
    analyzer.defined_strings["manual"] = {"$zzz"}
    analyzer.anonymous_strings["manual"] = set()
    analyzer.used_strings["manual"] = set()
    analyzer.in_condition = True

    # "$abc*" cannot match "$zzz"
    analyzer._mark_wildcard_string_set("$abc*")

    assert "$abc*" in analyzer.used_strings["manual"]


# ---------------------------------------------------------------------------
# Line 486 — _mark_all_current_rule_strings adds "$*" to used when the rule
# has no defined strings at all.
# ---------------------------------------------------------------------------


def test_mark_all_current_rule_strings_adds_dollar_star_sentinel_when_empty() -> None:
    """
    Line 486: when defined_strings for the active rule is empty, using "them"
    stores the sentinel "$*" in used_strings rather than an empty update.
    """
    analyzer = StringUsageAnalyzer()
    analyzer.current_rule = "empty_rule"
    analyzer.current_rule_key = "empty_rule"
    analyzer.defined_strings["empty_rule"] = set()
    analyzer.used_strings["empty_rule"] = set()

    analyzer._mark_all_current_rule_strings()

    assert analyzer.used_strings["empty_rule"] == {"$*"}


# ---------------------------------------------------------------------------
# Lines 490-491 — _is_explicit_string_wildcard raises ValueError when pattern
# starts with "#", "@", or "!" (embedded reference operator).
# ---------------------------------------------------------------------------


@pytest.mark.parametrize("pattern", ["#count*", "@offset*", "!length*"])
def test_is_explicit_string_wildcard_raises_for_embedded_operator_patterns(
    pattern: str,
) -> None:
    """
    Lines 490-491: _is_explicit_string_wildcard calls _normalize_string_id for
    patterns starting with "#", "@", or "!".  Those patterns are invalid string
    references and raise ValueError.
    """
    analyzer = StringUsageAnalyzer()
    analyzer.current_rule = "rule1"
    analyzer.in_condition = True

    with pytest.raises(ValueError, match="Invalid string reference"):
        analyzer._is_explicit_string_wildcard(pattern)


# ---------------------------------------------------------------------------
# Line 493 — _is_explicit_string_wildcard returns False when pattern does not
# start with "$", regardless of current_rule and in_condition state.
# ---------------------------------------------------------------------------


def test_is_explicit_string_wildcard_returns_false_for_non_dollar_pattern() -> None:
    """
    Line 493: _is_explicit_string_wildcard returns False for patterns that do
    not begin with "$", even inside an active condition context.
    """
    analyzer = StringUsageAnalyzer()
    analyzer.current_rule = "rule1"
    analyzer.in_condition = True

    result = analyzer._is_explicit_string_wildcard("plain_identifier")

    assert result is False


def test_is_explicit_string_wildcard_returns_false_when_no_current_rule() -> None:
    """
    Line 493: the bool() of (current_rule and in_condition and ...) is False
    when current_rule is None, so the method returns False even for "$" patterns.
    """
    analyzer = StringUsageAnalyzer()
    analyzer.current_rule = None
    analyzer.in_condition = True

    result = analyzer._is_explicit_string_wildcard("$abc*")

    assert result is False


# ---------------------------------------------------------------------------
# End-to-end integration: hex + regex strings in a single real rule ensure
# both visit_hex_string and visit_regex_string are exercised through the
# full analyze() pipeline (including validate_structure).
# ---------------------------------------------------------------------------


def test_analyze_hex_and_regex_strings_end_to_end() -> None:
    """
    Integration test confirming that HexString (line 204) and RegexString
    (line 207) are tracked correctly through the full analysis pipeline.
    """
    ast = Parser().parse("""
rule mixed_types {
    strings:
        $hex   = { DE AD BE EF }
        $regex = /suspicious\\.dll/i
        $plain = "text"
    condition:
        $hex and $regex
}
""")

    result = StringUsageAnalyzer().analyze(ast)["mixed_types"]

    assert result["defined"] == ["$hex", "$plain", "$regex"]
    assert result["used"] == ["$hex", "$regex"]
    assert result["unused"] == ["$plain"]
    assert result["undefined"] == []


# ---------------------------------------------------------------------------
# ForExpression via Parser — exercises visit_for_expression through the
# normal analysis path triggered by parse_yara_source.
# ---------------------------------------------------------------------------


def test_analyze_for_expression_tracks_iterable_and_body_strings() -> None:
    """
    Lines 297-303: visit_for_expression is exercised through the full
    parser + analyze pipeline when a rule uses a ``for`` loop.
    """
    ast = Parser().parse("""
rule for_loop_rule {
    strings:
        $a = "hello"
    condition:
        for any i in (1, 2, 3) : ($a at i)
}
""")

    result = StringUsageAnalyzer().analyze(ast)["for_loop_rule"]

    assert result["used"] == ["$a"]
    assert result["unused"] == []


# ---------------------------------------------------------------------------
# WithStatement via Parser — exercises visit_with_statement /
# visit_with_declaration through the standard yarax parse path.
# ---------------------------------------------------------------------------


def test_analyze_with_statement_tracks_declaration_and_body_strings() -> None:
    """
    Lines 306-316, 319-323: visit_with_statement and visit_with_declaration
    exercised end-to-end via parse_yara_source followed by analyze().
    """
    from yaraast.parser.source import parse_yara_source

    ast = parse_yara_source("""
rule with_rule {
    strings:
        $a = "data"
    condition:
        with size = filesize : $a and size > 10
}
""")

    result = StringUsageAnalyzer().analyze(ast)["with_rule"]

    assert result["used"] == ["$a"]
    assert result["unused"] == []


# ---------------------------------------------------------------------------
# ArrayComprehension visitor — exercises visit_array_comprehension
# (covers _visit_ast_value list sub-path for iterable/condition/expression).
# ---------------------------------------------------------------------------


def test_visit_array_comprehension_tracks_string_in_expression() -> None:
    """
    visit_array_comprehension (and implicitly _visit_ast_value for the
    iterable list) is reachable from the manual visitor interface.
    """
    analyzer = StringUsageAnalyzer()
    analyzer.current_rule = "manual"
    analyzer.current_rule_key = "manual"
    analyzer.defined_strings["manual"] = {"$a"}
    analyzer.used_strings["manual"] = set()
    analyzer.invalid_comparison_string_references["manual"] = set()
    analyzer.in_condition = True

    ac = ArrayComprehension(
        expression=StringIdentifier("$a"),
        variable="x",
        iterable=SetExpression([IntegerLiteral(1), IntegerLiteral(2)]),
        condition=None,
    )
    analyzer.visit_array_comprehension(ac)

    assert "$a" in analyzer.used_strings["manual"]


# ---------------------------------------------------------------------------
# DictComprehension visitor — exercises visit_dict_comprehension.
# ---------------------------------------------------------------------------


def test_visit_dict_comprehension_with_value_variable_tracks_body_strings() -> None:
    """
    visit_dict_comprehension registers both key_variable and value_variable
    as locals, then visits the body expressions.
    """
    analyzer = StringUsageAnalyzer()
    analyzer.current_rule = "manual"
    analyzer.current_rule_key = "manual"
    analyzer.defined_strings["manual"] = {"$a"}
    analyzer.used_strings["manual"] = set()
    analyzer.invalid_comparison_string_references["manual"] = set()
    analyzer.in_condition = True

    dc = DictComprehension(
        key_expression=StringIdentifier("$a"),
        value_expression=IntegerLiteral(0),
        key_variable="k",
        value_variable="v",
        iterable=SetExpression([IntegerLiteral(1)]),
        condition=None,
    )
    analyzer.visit_dict_comprehension(dc)

    assert "$a" in analyzer.used_strings["manual"]


# ---------------------------------------------------------------------------
# LambdaExpression visitor — exercises visit_lambda_expression.
# ---------------------------------------------------------------------------


def test_visit_lambda_expression_tracks_string_in_body() -> None:
    """
    visit_lambda_expression pushes a scope for each parameter, visits the
    body, then pops the scope.  A StringIdentifier in the body is marked used.
    """
    analyzer = StringUsageAnalyzer()
    analyzer.current_rule = "manual"
    analyzer.current_rule_key = "manual"
    analyzer.defined_strings["manual"] = {"$a"}
    analyzer.used_strings["manual"] = set()
    analyzer.invalid_comparison_string_references["manual"] = set()
    analyzer.in_condition = True

    le = LambdaExpression(
        parameters=["x", "y"],
        body=StringIdentifier("$a"),
    )
    analyzer.visit_lambda_expression(le)

    assert "$a" in analyzer.used_strings["manual"]
    assert analyzer.local_scopes == []


# ---------------------------------------------------------------------------
# BinaryExpression with comparison operators — exercises
# _mark_invalid_comparison_string_operand for both left and right operands,
# including the ParenthesesExpression unwrap path (lines 431-432).
# ---------------------------------------------------------------------------


def test_binary_expression_comparison_flags_parenthesised_string_identifier() -> None:
    """
    Lines 431-432, 237-239: visit_binary_expression calls
    _mark_invalid_comparison_string_operand on each operand.  When the operand
    is a ParenthesesExpression wrapping a StringIdentifier, the method recurses
    to unwrap it (line 431-432) and records the string in
    invalid_comparison_string_references.
    """
    analyzer = StringUsageAnalyzer()
    analyzer.current_rule = "manual"
    analyzer.current_rule_key = "manual"
    analyzer.defined_strings["manual"] = {"$a"}
    analyzer.used_strings["manual"] = set()
    analyzer.invalid_comparison_string_references["manual"] = set()
    analyzer.in_condition = True

    bin_expr = BinaryExpression(
        left=ParenthesesExpression(StringIdentifier("$a")),
        operator="==",
        right=IntegerLiteral(1),
    )
    analyzer.visit_binary_expression(bin_expr)

    assert "$a" in analyzer.invalid_comparison_string_references["manual"]


# ---------------------------------------------------------------------------
# Wildcard with no matching defined strings resolves to the pattern sentinel
# (line 477) — also exercisable through the real analyzer pipeline.
# ---------------------------------------------------------------------------


def test_analyze_wildcard_with_no_matching_defined_strings_stores_sentinel() -> None:
    """
    Line 477: when a condition uses ``any of ($xyz*)`` but no strings named
    $xyz... are defined, the normalized wildcard is stored in used_strings.
    """
    analyzer = StringUsageAnalyzer()
    analyzer.current_rule = "manual"
    analyzer.current_rule_key = "manual"
    analyzer.defined_strings["manual"] = {"$other"}
    analyzer.anonymous_strings["manual"] = set()
    analyzer.used_strings["manual"] = set()
    analyzer.in_condition = True

    analyzer.visit(OfExpression("any", StringWildcard("$xyz*")))

    # No defined string matches $xyz* so the normalized pattern is the sentinel
    assert "$xyz*" in analyzer.used_strings["manual"]
    assert "$other" not in analyzer.used_strings["manual"]


# ---------------------------------------------------------------------------
# _is_explicit_string_wildcard: patterns starting with "#" / "@" / "!" but
# inside a condition context — the normalize_string_id call raises ValueError
# for the embedded operator (lines 490-491).
# ---------------------------------------------------------------------------


def test_string_wildcard_with_embedded_at_operator_raises_via_visit() -> None:
    """
    Lines 490-491: visiting a StringWildcard whose pattern starts with "@"
    (embedded reference operator) raises ValueError through the real
    visit path, confirming _is_explicit_string_wildcard triggers the error.
    """
    analyzer = StringUsageAnalyzer()
    analyzer.current_rule = "rule1"
    analyzer.current_rule_key = "rule1"
    analyzer.defined_strings["rule1"] = set()
    analyzer.used_strings["rule1"] = set()
    analyzer.invalid_comparison_string_references["rule1"] = set()
    analyzer.in_condition = True

    with pytest.raises(ValueError, match="Invalid string reference"):
        analyzer.visit_string_wildcard(StringWildcard("@offset*"))


# ---------------------------------------------------------------------------
# Lines 490-491 (TypeError variant) — _is_explicit_string_wildcard raises
# TypeError when pattern is not a string at all.
# ---------------------------------------------------------------------------


def test_is_explicit_string_wildcard_raises_type_error_for_non_string() -> None:
    """
    Lines 490-491: the first guard in _is_explicit_string_wildcard raises
    TypeError when pattern is not a str instance.
    """
    from typing import cast as _cast

    analyzer = StringUsageAnalyzer()
    analyzer.current_rule = "rule1"
    analyzer.in_condition = True

    with pytest.raises(TypeError, match="String reference must be a string"):
        analyzer._is_explicit_string_wildcard(_cast(Any, 42))


# ---------------------------------------------------------------------------
# Line 246 — visit_at_expression raises TypeError when string_id is neither
# a str nor has an .accept method.
# ---------------------------------------------------------------------------


def test_visit_at_expression_raises_for_invalid_string_id_type() -> None:
    """
    Line 246: visit_at_expression calls _require_string_reference(node.string_id)
    when string_id is not a str and has no .accept attribute, raising TypeError.
    """
    from typing import cast as _cast

    analyzer = StringUsageAnalyzer()

    at_expr = AtExpression(_cast(Any, 99), IntegerLiteral(0))
    with pytest.raises(TypeError, match="String reference must be a string"):
        analyzer.visit_at_expression(at_expr)


# ---------------------------------------------------------------------------
# Line 255 — visit_in_expression raises TypeError when subject is neither a
# str nor has an .accept method.
# ---------------------------------------------------------------------------


def test_visit_in_expression_raises_for_invalid_subject_type() -> None:
    """
    Line 255: visit_in_expression calls _require_string_reference(node.subject)
    when subject is not a str and has no .accept attribute, raising TypeError.
    """
    from typing import cast as _cast

    from yaraast.ast.expressions import RangeExpression

    analyzer = StringUsageAnalyzer()

    in_expr = InExpression(
        _cast(Any, 99),
        RangeExpression(IntegerLiteral(0), IntegerLiteral(1)),
    )
    with pytest.raises(TypeError, match="String reference must be a string"):
        analyzer.visit_in_expression(in_expr)


# ---------------------------------------------------------------------------
# Line 308->310 — visit_dict_comprehension when value_variable is None:
# the names list stays as [key_variable] alone (no append of value_variable).
# ---------------------------------------------------------------------------


def test_visit_dict_comprehension_without_value_variable_uses_only_key() -> None:
    """
    Line 308->310: when value_variable is None (falsy), the names list for
    _push_local_scope contains only key_variable.  The body expressions are
    still visited correctly.
    """
    analyzer = StringUsageAnalyzer()
    analyzer.current_rule = "manual"
    analyzer.current_rule_key = "manual"
    analyzer.defined_strings["manual"] = {"$a"}
    analyzer.used_strings["manual"] = set()
    analyzer.invalid_comparison_string_references["manual"] = set()
    analyzer.in_condition = True

    dc = DictComprehension(
        key_expression=StringIdentifier("$a"),
        value_expression=IntegerLiteral(0),
        key_variable="k",
        value_variable=None,  # falsy → only "k" is pushed into the local scope
        iterable=SetExpression([IntegerLiteral(1)]),
        condition=None,
    )
    analyzer.visit_dict_comprehension(dc)

    assert "$a" in analyzer.used_strings["manual"]
    assert analyzer.local_scopes == []


# ---------------------------------------------------------------------------
# Line 369 — _visit_string_set_value when Identifier.name starts with "$"
# (hits the elif branch before the fallthrough to _visit_ast_value).
# ---------------------------------------------------------------------------


def test_visit_string_set_value_dollar_prefixed_identifier_marks_string_used() -> None:
    """
    Line 369: _visit_string_set_value, Identifier branch: when the identifier
    name starts with "$" (but is not "them"), _mark_string_set_text is called
    to record the string as used.
    """
    analyzer = StringUsageAnalyzer()
    analyzer.current_rule = "manual"
    analyzer.current_rule_key = "manual"
    analyzer.defined_strings["manual"] = {"$a"}
    analyzer.used_strings["manual"] = set()
    analyzer.in_condition = True

    # Identifier with a dollar-prefixed name — hits the elif name.startswith("$") branch
    analyzer._visit_string_set_value(Identifier("$a"))

    assert "$a" in analyzer.used_strings["manual"]


# ---------------------------------------------------------------------------
# Line 404->406 — _mark_string_set_text re-visits a local whose stored value
# is a concrete AST node (not LOCAL_WITHOUT_VALUE and not MISSING_LOCAL).
# Replicating via direct visitor API so the path is exercised in isolation.
# ---------------------------------------------------------------------------


def test_mark_string_set_text_re_visits_local_ast_node_value() -> None:
    """
    Lines 404-405: _mark_string_set_text resolves a local variable name to
    a concrete AST node (not LOCAL_WITHOUT_VALUE) and recursively visits it.
    Here the local "$x" is bound to StringLiteral("$a"), so visiting "$x"
    resolves to "$a" being marked as used.
    """
    analyzer = StringUsageAnalyzer()
    analyzer.current_rule = "manual"
    analyzer.current_rule_key = "manual"
    analyzer.defined_strings["manual"] = {"$a"}
    analyzer.used_strings["manual"] = set()
    analyzer.in_condition = True

    # Push a scope binding $x → StringLiteral("$a") (a concrete AST node,
    # not the LOCAL_WITHOUT_VALUE sentinel).
    analyzer._push_local_scope("placeholder_to_init_scope")
    # Overwrite the placeholder to introduce the binding we actually need.
    analyzer.local_scopes[-1]["$x"] = StringLiteral("$a")

    analyzer._mark_string_set_text("$x")

    # "$a" should be resolved and recorded
    assert "$a" in analyzer.used_strings["manual"]


def test_mark_string_set_text_returns_early_for_local_without_value() -> None:
    """
    Line 404->406: _mark_string_set_text, inner branch where local_value IS
    LOCAL_WITHOUT_VALUE.  The variable is in scope (not MISSING_LOCAL) but has
    no concrete value (pushed by _push_local_scope without _define_local
    updating it).  The method must return without visiting or marking anything.

    This sentinel state arises in ForExpression loop variables and WithStatement
    placeholders before declarations have been processed.
    """
    analyzer = StringUsageAnalyzer()
    analyzer.current_rule = "manual"
    analyzer.current_rule_key = "manual"
    analyzer.defined_strings["manual"] = {"$a"}
    analyzer.used_strings["manual"] = set()
    analyzer.in_condition = True

    # Directly inject LOCAL_WITHOUT_VALUE into the scope for "$x".
    sentinel = StringUsageAnalyzer._LOCAL_WITHOUT_VALUE
    analyzer.local_scopes = [{"$x": sentinel}]

    analyzer._mark_string_set_text("$x")

    # Nothing must be recorded as used — the early return is the observed behavior
    assert analyzer.used_strings["manual"] == set()
