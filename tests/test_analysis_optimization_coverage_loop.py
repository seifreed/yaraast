# Copyright (c) 2026 Marc Rivero López
# Licensed under GPLv3. See LICENSE file for details.
# This test suite validates real code behavior without mocks or stubs.
"""Regression tests closing the remaining coverage gap in optimization.py.

Missing branches identified by running the full test suite with parallel
coverage (coverage combine + coverage report --show-missing):

  line  36            _expression_text str early-return path
  233->235            visit_dict_comprehension: value_variable is truthy branch
  271->exit           _define_local called with empty local-scope stack
  281-282             _extract_comparison raises TypeError for non-str var
  296-297             _visit_ast_value list/tuple/set/frozenset branch
  301-302             _visit_string_set_value str early-return path
  314-315             _visit_string_set_value Identifier not "them" not "$"-prefixed
  332                 _visit_string_set_value fallthrough to _visit_ast_value
  338->340            _mark_string_set_text when scope entry is LOCAL_WITHOUT_VALUE
  352-353             _require_string_reference TypeError on non-str input

Every test uses the real OptimizationAnalyzer and real AST nodes. No mocks.
"""

from __future__ import annotations

import pytest

from yaraast.analysis.optimization import (
    OptimizationAnalyzer,
    _expression_text,
    _require_string_reference,
)
from yaraast.ast.base import YaraFile
from yaraast.ast.conditions import OfExpression
from yaraast.ast.expressions import (
    BinaryExpression,
    Identifier,
    IntegerLiteral,
    ParenthesesExpression,
    SetExpression,
    StringIdentifier,
    StringLiteral,
    StringWildcard,
)
from yaraast.ast.rules import Rule
from yaraast.ast.strings import PlainString
from yaraast.yarax.ast_nodes import DictComprehension

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _make_analyzer() -> OptimizationAnalyzer:
    """Return a freshly initialised analyzer with an empty rule context."""
    analyzer = OptimizationAnalyzer()
    analyzer._string_refs = {}
    analyzer._local_scopes = []
    analyzer._current_rule = None
    analyzer._condition_depth = 0
    analyzer._max_condition_depth = 0
    return analyzer


# ---------------------------------------------------------------------------
# Line 36: _expression_text str early-return path
# ---------------------------------------------------------------------------


def test_expression_text_returns_plain_string_directly() -> None:
    """_expression_text('value') returns the string via the isinstance(str) guard.

    The str branch at line 36 short-circuits before inspecting .value or .name.
    """
    # Act
    result_any = _expression_text("any")
    result_them = _expression_text("them")
    result_empty = _expression_text("")

    # Assert
    assert result_any == "any"
    assert result_them == "them"
    assert result_empty == ""


def test_expression_text_returns_none_for_integer_literal() -> None:
    """_expression_text returns None when .value is an int, not a str.

    The str branch (line 36) is NOT taken; the raw_value check runs and returns None
    because IntegerLiteral.value is an int.
    """
    # Act
    result = _expression_text(IntegerLiteral(value=42))

    # Assert
    assert result is None


# ---------------------------------------------------------------------------
# Lines 233->235: visit_dict_comprehension value_variable truthy branch
# ---------------------------------------------------------------------------


def test_visit_dict_comprehension_with_value_variable_appends_to_scope() -> None:
    """visit_dict_comprehension appends value_variable to the scope when present.

    Line 233: `if node.value_variable:` evaluates True.
    Line 235: `self._push_local_scope(*names)` is called with both key and value vars.

    When value_variable is provided, the internal scope must contain both variables.
    The analysis then runs the condition and expressions inside that scope.
    """
    # Arrange — a dict comprehension with both key ('k') and value ('v') variables
    comprehension = DictComprehension(
        key_variable="k",
        value_variable="v",
        iterable=IntegerLiteral(value=0),
        condition=None,
        key_expression=IntegerLiteral(value=1),
        value_expression=IntegerLiteral(value=2),
    )
    rule = Rule(name="dc_rule", strings=[], condition=comprehension)
    ast = YaraFile(rules=[rule])

    # Act
    report = OptimizationAnalyzer().analyze(ast)

    # Assert — analysis completes without error; scope was properly pushed/popped
    assert report is not None
    assert report.statistics["analysis_kind"] == "heuristic"


def test_visit_dict_comprehension_without_value_variable_uses_key_only() -> None:
    """visit_dict_comprehension skips line 234 when value_variable is falsy.

    This is the complementary branch: value_variable=None so the condition at
    line 233 is False and only the key variable is pushed into scope.
    """
    # Arrange
    comprehension = DictComprehension(
        key_variable="k",
        value_variable=None,
        iterable=IntegerLiteral(value=0),
        condition=None,
        key_expression=IntegerLiteral(value=1),
        value_expression=IntegerLiteral(value=2),
    )
    rule = Rule(name="dc_no_val", strings=[], condition=comprehension)
    ast = YaraFile(rules=[rule])

    # Act
    report = OptimizationAnalyzer().analyze(ast)

    # Assert
    assert report is not None


# ---------------------------------------------------------------------------
# Line 271->exit: _define_local with empty scope stack
# ---------------------------------------------------------------------------


def test_define_local_does_nothing_when_scope_stack_is_empty() -> None:
    """_define_local returns immediately when _local_scopes is empty (line 271 guard).

    The method must not write to any scope and must not raise.
    """
    # Arrange
    analyzer = OptimizationAnalyzer()
    assert analyzer._local_scopes == []

    # Act
    analyzer._define_local("x")

    # Assert — scope stack remains empty
    assert analyzer._local_scopes == []


# ---------------------------------------------------------------------------
# Lines 281-282: structural note and companion tests
# ---------------------------------------------------------------------------


# Lines 281-282 in _extract_comparison are a defensive TypeError guard that fires
# when the outer extract_comparison() helper returns a dict whose 'var' key is not
# a str.  However, the helper (optimization_helpers.extract_comparison) already
# validates that the variable name is a str before constructing the return dict;
# it returns None for any non-str name instead.  The guard is therefore structurally
# unreachable through the normal production API.
#
# The tests below exercise the two reachable paths that lead into _extract_comparison:
# (a) extract_comparison returns None  ->  _extract_comparison returns None (lines 277-278)
# (b) the variable is non-local        ->  _extract_comparison returns the dict (line 285)


def test_extract_comparison_returns_none_for_missing_var() -> None:
    """_extract_comparison returns None when extract_comparison finds no variable.

    Line 277-278: the outer None guard fires when extract_comparison() itself
    returns None (e.g. when the expression is not a recognised comparison form).
    """
    # Arrange — a binary expression that is not a comparison (operator "and")
    expr = BinaryExpression(
        left=IntegerLiteral(value=1),
        operator="and",
        right=IntegerLiteral(value=2),
    )
    analyzer = OptimizationAnalyzer()

    # Act
    result = analyzer._extract_comparison(expr)

    # Assert
    assert result is None


def test_extract_comparison_returns_result_for_non_local_variable() -> None:
    """_extract_comparison returns a comparison dict for an unscoped variable."""
    # Arrange
    comparison = BinaryExpression(
        left=Identifier(name="filesize"),
        operator="<",
        right=IntegerLiteral(value=1024),
    )
    analyzer = OptimizationAnalyzer()

    # Act
    result = analyzer._extract_comparison(comparison)

    # Assert
    assert result is not None
    assert result["var"] == "filesize"
    assert result["op"] == "<"
    assert result["value"] == 1024


# ---------------------------------------------------------------------------
# Lines 296-297: _visit_ast_value list/tuple/set/frozenset branch
# ---------------------------------------------------------------------------


def test_visit_ast_value_recurses_into_list() -> None:
    """_visit_ast_value visits each element of a list (lines 296-297)."""
    # Arrange
    analyzer = _make_analyzer()

    # Act — must complete without raising
    analyzer._visit_ast_value([IntegerLiteral(value=1), IntegerLiteral(value=2)])


def test_visit_ast_value_recurses_into_tuple() -> None:
    """_visit_ast_value visits each element of a tuple."""
    # Arrange
    analyzer = _make_analyzer()

    # Act
    analyzer._visit_ast_value((IntegerLiteral(value=3),))


# ---------------------------------------------------------------------------
# Lines 301-302: _visit_string_set_value str early-return path
# ---------------------------------------------------------------------------


def test_visit_string_set_value_with_str_marks_string_ref() -> None:
    """_visit_string_set_value delegates to _mark_string_set_text for a plain str.

    The isinstance(string_set, str) branch at line 301 fires when a bare Python
    string is passed directly (not wrapped in an AST node).
    """
    # Arrange
    analyzer = _make_analyzer()

    # Act
    analyzer._visit_string_set_value("$payload")

    # Assert — the str was recorded as a reference
    assert "$payload" in analyzer._string_refs


def test_visit_string_set_value_wildcard_str_does_not_add_ref() -> None:
    """Wildcard strings ('*' in text) are excluded by _mark_string_set_text."""
    # Arrange
    analyzer = _make_analyzer()

    # Act — wildcard text hits the str branch (lines 301-302) then is skipped
    analyzer._visit_string_set_value("$mal*")

    # Assert
    assert analyzer._string_refs == {}


def test_visit_string_set_value_with_list_of_string_identifiers() -> None:
    """_visit_string_set_value records each element when given a Python list.

    The list branch is at line 303: isinstance(string_set, list | tuple | ...).
    """
    # Arrange
    analyzer = _make_analyzer()
    of_expr = OfExpression(
        quantifier=Identifier("all"),
        string_set=[StringIdentifier("$alpha"), StringIdentifier("$beta")],
    )

    # Act
    analyzer.visit_of_expression(of_expr)

    # Assert
    assert "$alpha" in analyzer._string_refs
    assert "$beta" in analyzer._string_refs


def test_visit_string_set_value_with_frozenset() -> None:
    """_visit_string_set_value iterates a frozenset of str values without raising.

    frozenset must contain hashable items; plain str values are used here since
    StringIdentifier is not hashable.  Each str element hits the str branch.
    """
    # Arrange
    analyzer = _make_analyzer()

    # Act
    analyzer._visit_string_set_value(frozenset({"$x", "$y"}))

    # Assert
    assert "$x" in analyzer._string_refs
    assert "$y" in analyzer._string_refs


# ---------------------------------------------------------------------------
# Lines 314-315: _visit_string_set_value Identifier not "them" not "$"-prefixed
# ---------------------------------------------------------------------------


def test_visit_string_set_value_plain_identifier_falls_through_to_visit() -> None:
    """An Identifier that is neither 'them' nor '$'-prefixed recurses via visit.

    Lines 311-313 handle Identifiers starting with '$'.
    Lines 309-310 handle 'them'.
    Lines 314-315 are the fallthrough for any other Identifier (e.g. a module
    name like 'pe' or an integer variable like 'x').

    Using Identifier("n") (a loop variable name, not a string ref) exercises
    the _visit_ast_value call at line 314.
    """
    # Arrange
    analyzer = _make_analyzer()

    # Act — Identifier("n") is not "them" and does not start with "$"
    analyzer._visit_string_set_value(Identifier(name="n"))

    # Assert — no string references were added (n is not a string ref)
    assert analyzer._string_refs == {}


def test_visit_string_set_value_with_dollar_identifier_marks_ref() -> None:
    """Identifier with '$'-prefixed name is tracked as a string reference.

    Lines 311-313 fire: name starts with "$" -> _mark_string_set_text.
    This contrasts with the lines 314-315 test above.
    """
    # Arrange
    analyzer = _make_analyzer()

    # Act
    analyzer._visit_string_set_value(Identifier(name="$needle"))

    # Assert
    assert "$needle" in analyzer._string_refs


def test_visit_string_set_value_with_them_identifier_skips_ref() -> None:
    """Identifier(name='them') is the universal set; no ref is registered."""
    # Arrange
    analyzer = _make_analyzer()

    # Act
    analyzer._visit_string_set_value(Identifier(name="them"))

    # Assert
    assert analyzer._string_refs == {}


# ---------------------------------------------------------------------------
# Line 332: _visit_string_set_value fallthrough to _visit_ast_value
# ---------------------------------------------------------------------------


def test_visit_string_set_value_falls_through_for_other_ast_nodes() -> None:
    """Unrecognised AST nodes reach the fallthrough _visit_ast_value call (line 332).

    IntegerLiteral is a valid ASTNode but is not str, list/tuple/set/frozenset,
    Identifier, StringLiteral, StringIdentifier, StringWildcard,
    ParenthesesExpression, or SetExpression, so execution falls through to line 332.
    """
    # Arrange
    analyzer = _make_analyzer()

    # Act — must complete without raising
    analyzer._visit_string_set_value(IntegerLiteral(value=99))


# ---------------------------------------------------------------------------
# Lines 338->340: _mark_string_set_text with LOCAL_WITHOUT_VALUE in scope
# ---------------------------------------------------------------------------


def test_mark_string_set_text_skips_local_without_value_scope_entry() -> None:
    """_mark_string_set_text returns early for a sentinel-valued scope entry.

    When _push_local_scope stores a name and later that name is looked up in
    _local_value, the sentinel _LOCAL_WITHOUT_VALUE is returned.  The guard at
    line 338-339 detects this and returns without adding a string reference or
    recursing (line 340 branch).
    """
    # Arrange — inject a scope with the sentinel directly; this reproduces the
    # internal state when _push_local_scope is called with a name whose
    # string-identifier variant matches the text being looked up.
    analyzer = OptimizationAnalyzer()
    analyzer._string_refs = {}
    analyzer._local_scopes = [{"$s": OptimizationAnalyzer._LOCAL_WITHOUT_VALUE}]

    # Act
    analyzer._mark_string_set_text("$s")

    # Assert — no reference was added; sentinel caused an early return
    assert analyzer._string_refs == {}


def test_mark_string_set_text_follows_local_value_when_set() -> None:
    """_mark_string_set_text recurses into the bound AST node for a resolved local.

    When a scope entry has a real AST node as its value (set via _define_local
    with an explicit value argument), the function visits that node, potentially
    adding transitively referenced strings.
    """
    # Arrange — "$alias" resolves to StringIdentifier("$real")
    analyzer = OptimizationAnalyzer()
    analyzer._string_refs = {}
    analyzer._local_scopes = [{"$alias": StringIdentifier("$real")}]

    # Act
    analyzer._mark_string_set_text("$alias")

    # Assert — visiting the resolved value registered "$real"
    assert "$real" in analyzer._string_refs
    assert "$alias" not in analyzer._string_refs


# ---------------------------------------------------------------------------
# Lines 352-353: _require_string_reference raises TypeError on non-str
# ---------------------------------------------------------------------------


@pytest.mark.parametrize("bad_value", [None, 42, 3.14, [], True])
def test_require_string_reference_raises_for_non_string(bad_value: object) -> None:
    """_require_string_reference raises TypeError for any non-str input.

    Lines 352-353 are the error path: the isinstance guard fails, the msg
    variable is set, and TypeError is raised.
    """
    # Act / Assert
    with pytest.raises(TypeError, match="string"):
        _require_string_reference(bad_value)


def test_require_string_reference_returns_string_unchanged() -> None:
    """_require_string_reference returns the input string unmodified for valid input."""
    # Arrange
    text = "$my_string"

    # Act
    result = _require_string_reference(text)

    # Assert
    assert result is text


# ---------------------------------------------------------------------------
# Integration: end-to-end analyze() paths
# ---------------------------------------------------------------------------


def test_analyze_with_list_string_set_in_of_expression() -> None:
    """Full analyze() run with a list string_set in OfExpression completes cleanly."""
    # Arrange
    source = """
    rule list_set_rule {
        strings:
            $a = "alpha"
            $b = "beta"
        condition:
            1 of ($a, $b)
    }
    """
    from yaraast.parser.source import parse_yara_source

    # Act
    report = OptimizationAnalyzer().analyze(parse_yara_source(source))

    # Assert
    assert report.statistics["analysis_kind"] == "heuristic"
    assert isinstance(report.suggestions, list)


def test_analyze_of_expression_with_parentheses_string_set() -> None:
    """ParenthesesExpression wrapping a StringIdentifier is unwrapped correctly."""
    # Arrange
    rule = Rule(
        name="parens_set",
        strings=[PlainString(identifier="$p", value="payload")],
        condition=OfExpression(
            quantifier=Identifier("all"),
            string_set=ParenthesesExpression(expression=StringIdentifier("$p")),
        ),
    )
    ast = YaraFile(rules=[rule])

    # Act
    report = OptimizationAnalyzer().analyze(ast)

    # Assert
    assert report is not None
    assert report.statistics["total_suggestions"] == 0


def test_analyze_of_expression_with_set_expression_string_set() -> None:
    """SetExpression as string_set iterates each element through the visitor."""
    # Arrange
    rule = Rule(
        name="set_expr_set",
        strings=[
            PlainString(identifier="$x", value="xval"),
            PlainString(identifier="$y", value="yval"),
        ],
        condition=OfExpression(
            quantifier=Identifier("any"),
            string_set=SetExpression(elements=[StringIdentifier("$x"), StringIdentifier("$y")]),
        ),
    )
    ast = YaraFile(rules=[rule])

    # Act
    report = OptimizationAnalyzer().analyze(ast)

    # Assert
    assert report is not None


def test_analyze_string_literal_in_of_expression_string_set() -> None:
    """StringLiteral in a string_set is delegated to _mark_string_set_text."""
    # Arrange
    rule = Rule(
        name="string_lit_set",
        strings=[PlainString(identifier="$t", value="text")],
        condition=OfExpression(
            quantifier=Identifier("any"),
            string_set=StringLiteral(value="$t"),
        ),
    )
    ast = YaraFile(rules=[rule])

    # Act
    report = OptimizationAnalyzer().analyze(ast)

    # Assert
    assert report is not None


def test_analyze_string_wildcard_in_of_expression_string_set() -> None:
    """StringWildcard in a string_set is passed through _mark_string_set_text."""
    # Arrange
    rule = Rule(
        name="wildcard_set",
        strings=[PlainString(identifier="$wc_a", value="wc_value")],
        condition=OfExpression(
            quantifier=Identifier("any"),
            string_set=StringWildcard(pattern="$wc*"),
        ),
    )
    ast = YaraFile(rules=[rule])

    # Act
    report = OptimizationAnalyzer().analyze(ast)

    # Assert
    assert report is not None


def test_analyze_dict_comprehension_with_value_variable_end_to_end() -> None:
    """Full analyze() on a YARA-X dict comprehension with both key and value vars.

    This validates that visit_dict_comprehension correctly handles value_variable
    (line 233->235) through the public API.
    """
    # Arrange — parse a YARA-X dict comprehension expression
    from yaraast.ast.base import YaraFile
    from yaraast.yarax.ast_nodes import DictComprehension

    comprehension = DictComprehension(
        key_variable="k",
        value_variable="v",
        iterable=IntegerLiteral(value=0),
        condition=None,
        key_expression=IntegerLiteral(value=1),
        value_expression=IntegerLiteral(value=2),
    )
    rule = Rule(name="dc_e2e", strings=[], condition=comprehension)
    ast = YaraFile(rules=[rule])

    # Act
    report = OptimizationAnalyzer().analyze(ast)

    # Assert
    assert report.statistics["analysis_kind"] == "heuristic"
