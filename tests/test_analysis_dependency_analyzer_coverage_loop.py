# Copyright (c) 2026 Marc Rivero Lopez
# Licensed under GPLv3. See LICENSE file for details.
# This test suite validates real code behavior without mocks or stubs.

"""
Regression tests for yaraast/analysis/dependency_analyzer.py covering
the branches and statements that were not reached by prior tests.

Missing coverage before this file (85.90 %):
  174, 188, 284, 286, 290, 297, 300, 312-327, 331, 337-338, 340,
  351-352, 355->357, 361, 374, 411->413, 441->exit

Every test exercises real production code paths through the public API
or through focused direct calls that are unreachable via the validated
public API (noted in the relevant test's rationale comment).
"""

from __future__ import annotations

from collections import defaultdict

from yaraast.analysis.dependency_analyzer import DependencyAnalyzer
from yaraast.ast.base import YaraFile
from yaraast.ast.conditions import ForOfExpression, OfExpression
from yaraast.ast.expressions import (
    BooleanLiteral,
    Identifier,
    IntegerLiteral,
    MemberAccess,
    ParenthesesExpression,
    StringLiteral,
    StringWildcard,
)
from yaraast.ast.rules import Rule
from yaraast.yarax.ast_nodes import DictComprehension, ListExpression

# ---------------------------------------------------------------------------
# _remove_duplicate_cycles - line 174 (empty body -> else branch)
# ---------------------------------------------------------------------------


def test_remove_duplicate_cycles_empty_cycle_body_is_kept_verbatim() -> None:
    """
    When a cycle entry is an empty list the body is also empty, which makes
    the `if body` guard on line 170 False.  The else branch on line 174 is
    reached and `normalized` is set to the original (empty) cycle.

    Purpose: cover line 174 - the only path where `body` evaluates to False.

    Rationale: _find_circular_dependencies never produces empty-list entries,
    so the only way to exercise this branch is by calling
    _remove_duplicate_cycles directly with a crafted input.
    """
    analyzer = DependencyAnalyzer()

    result = analyzer._remove_duplicate_cycles([[]])

    # The empty list is preserved as-is (unique_cycles starts empty, so the
    # empty cycle is appended once).
    assert result == [[]]


def test_remove_duplicate_cycles_two_empty_cycles_deduplicated() -> None:
    """
    Two identical empty-list entries must collapse to one via the
    `if normalized not in unique_cycles` guard after the else branch.
    Covers line 174 twice in a single call.
    """
    analyzer = DependencyAnalyzer()

    result = analyzer._remove_duplicate_cycles([[], []])

    assert result == [[]]


# ---------------------------------------------------------------------------
# _get_transitive_dependencies - line 188 (continue on already-visited node)
# ---------------------------------------------------------------------------


def test_get_transitive_dependencies_convergent_path_exercises_already_visited_continue() -> None:
    """
    In the graph a->{b,c}, c->b the node 'b' is reachable via two paths:
    directly from 'a' and indirectly via 'c'.  Because the DFS uses a list
    as a stack (LIFO) and Python's set iteration is deterministic for small
    sets, the execution sequence is:

      pop 'a' -> extend with [b, c] -> to_visit=[b, c]
      pop 'c' -> b not yet visited -> extend with [b] -> to_visit=[b, b]
      pop 'b' (first) -> add b to visited
      pop 'b' (second) -> b in visited -> continue (line 188)

    The `continue` on line 188 is therefore executed exactly once.

    Covers line 188.
    """
    analyzer = DependencyAnalyzer()
    analyzer.dependencies = defaultdict(set)
    analyzer.dependencies["a"].update({"b", "c"})
    analyzer.dependencies["c"].add("b")

    result = analyzer._get_transitive_dependencies("a")

    assert result == {"b", "c"}


def test_get_transitive_dependencies_via_real_analyze_reports_correct_transitive_deps() -> None:
    """
    Transitive dependencies reported by the full analyze() pipeline are correct
    for a simple linear chain: b depends on c.
    """
    ast2 = YaraFile(
        rules=[
            Rule(name="c", condition=BooleanLiteral(True)),
            Rule(name="d", condition=BooleanLiteral(True)),
            Rule(name="b", condition=Identifier("c")),
        ]
    )
    results = DependencyAnalyzer().analyze(ast2)
    assert results["dependency_graph"]["b"]["transitive_dependencies"] == ["c"]


# ---------------------------------------------------------------------------
# visit_string_wildcard - line 284 ($-prefixed pattern) and line 286 (return)
# ---------------------------------------------------------------------------


def test_visit_string_wildcard_dollar_prefix_does_not_add_dependency() -> None:
    """
    A StringWildcard whose pattern starts with '$' is a string-identifier
    reference, not a rule wildcard.  The early return on line 286 is taken
    and no dependency is recorded.

    Covers lines 284 (isinstance check) and 286 (return).
    """
    ast = YaraFile(
        rules=[
            Rule(name="caller", condition=OfExpression("any", StringWildcard("$*"))),
        ]
    )

    results = DependencyAnalyzer().analyze(ast)

    assert "caller" not in results["dependencies"]
    assert results["dependency_graph"]["caller"]["is_independent"] is True


# ---------------------------------------------------------------------------
# visit_string_wildcard - line 290 (no active rule key -> early return)
# ---------------------------------------------------------------------------


def test_visit_string_wildcard_without_active_rule_is_a_no_op() -> None:
    """
    visit_string_wildcard checks _active_rule_key().  When the analyzer has
    no current_rule and no current_rule_key the call returns on line 290
    without modifying dependencies.

    Rationale: within analyze() the rule key is always set before visiting
    child nodes, so this branch can only be reached by direct invocation with
    a non-dollar, non-empty pattern and no active rule context.
    """
    analyzer = DependencyAnalyzer()
    analyzer.rule_names = {"a_rule"}
    analyzer._raw_rule_names = {"a_rule"}
    # current_rule and current_rule_key remain None (default)

    analyzer.visit_string_wildcard(StringWildcard("a*"))

    assert dict(analyzer.dependencies) == {}


# ---------------------------------------------------------------------------
# _matching_rule_wildcard_names - line 297 (pattern has no trailing '*')
# ---------------------------------------------------------------------------


def test_matching_rule_wildcard_names_returns_empty_for_literal_pattern() -> None:
    """
    When the pattern does not end with '*' the method returns an empty tuple
    immediately on line 297.

    Covers the early-return branch at line 297.
    """
    analyzer = DependencyAnalyzer()
    analyzer.rule_names = {"foo", "foobar"}
    analyzer._raw_rule_names = {"foo", "foobar"}

    result = analyzer._matching_rule_wildcard_names("foo")

    assert result == ()


# ---------------------------------------------------------------------------
# _matching_rule_wildcard_names - line 300 (empty prefix, i.e. pattern == '*')
# ---------------------------------------------------------------------------


def test_matching_rule_wildcard_names_returns_empty_for_bare_star_pattern() -> None:
    """
    A bare '*' pattern has an empty prefix after stripping the trailing star.
    The guard on line 300 returns an empty tuple to prevent matching every rule.

    Covers the early-return branch at line 300.
    """
    analyzer = DependencyAnalyzer()
    analyzer.rule_names = {"a", "b"}
    analyzer._raw_rule_names = {"a", "b"}

    result = analyzer._matching_rule_wildcard_names("*")

    assert result == ()


# ---------------------------------------------------------------------------
# _record_rule_set_text - lines 312-313 ('them' and '$' early returns)
# ---------------------------------------------------------------------------


def test_record_rule_set_text_them_keyword_is_ignored() -> None:
    """
    'them' is a YARA built-in string-set keyword, not a rule name.  The early
    return on line 313 prevents a spurious dependency being recorded.
    """
    analyzer = DependencyAnalyzer()
    analyzer.rule_names = {"them", "caller"}
    analyzer._raw_rule_names = {"them", "caller"}
    analyzer._rule_keys_by_name = {"them": ["them"]}
    analyzer.current_rule = "caller"
    analyzer.current_rule_key = "caller"
    analyzer.dependencies = defaultdict(set)

    analyzer._record_rule_set_text("them")

    assert dict(analyzer.dependencies) == {}


def test_record_rule_set_text_dollar_prefix_is_ignored() -> None:
    """
    A value starting with '$' is a string identifier, not a rule name.
    The early return on line 313 (via startswith('$') check) is taken.
    """
    analyzer = DependencyAnalyzer()
    analyzer.rule_names = {"caller"}
    analyzer._raw_rule_names = {"caller"}
    analyzer.current_rule = "caller"
    analyzer.current_rule_key = "caller"
    analyzer.dependencies = defaultdict(set)

    analyzer._record_rule_set_text("$mystring")

    assert dict(analyzer.dependencies) == {}


# ---------------------------------------------------------------------------
# _record_rule_set_text - line 316 (no rule_key -> return; is_local -> return)
# ---------------------------------------------------------------------------


def test_record_rule_set_text_no_active_rule_is_a_no_op() -> None:
    """
    When current_rule and current_rule_key are both None, _active_rule_key()
    returns None.  The guard on line 316 fires and no dependency is recorded.
    """
    analyzer = DependencyAnalyzer()
    analyzer.rule_names = {"a1", "caller"}
    analyzer._raw_rule_names = {"a1", "caller"}
    # No current_rule set

    analyzer._record_rule_set_text("a1")

    assert dict(analyzer.dependencies) == {}


def test_record_rule_set_text_local_name_is_not_treated_as_rule_dependency() -> None:
    """
    A name that is shadowed in the innermost local scope must not be treated
    as a rule dependency.  The _is_local guard on line 316 fires.
    """
    analyzer = DependencyAnalyzer()
    analyzer.rule_names = {"a1", "caller"}
    analyzer._raw_rule_names = {"a1", "caller"}
    analyzer._rule_keys_by_name = {"a1": ["a1"]}
    analyzer.current_rule = "caller"
    analyzer.current_rule_key = "caller"
    analyzer.dependencies = defaultdict(set)
    # Shadow 'a1' in the active local scope
    analyzer.local_scopes = [{"a1"}]

    analyzer._record_rule_set_text("a1")

    assert dict(analyzer.dependencies) == {}


# ---------------------------------------------------------------------------
# _record_rule_set_text - lines 319-324 (wildcard expansion path)
# ---------------------------------------------------------------------------


def test_record_rule_set_text_wildcard_expands_to_matching_rules() -> None:
    """
    When the value ends with '*' the wildcard expansion path (lines 319-324)
    is taken instead of the direct-match path.  All matching rule names are
    added as dependencies.

    Rationale: Identifier('a*') fails validate_structure, so this branch is
    unreachable through analyze().  Direct invocation is required.
    """
    analyzer = DependencyAnalyzer()
    analyzer.rule_names = {"a1", "a2", "other", "caller"}
    analyzer._raw_rule_names = {"a1", "a2", "other", "caller"}
    analyzer._rule_keys_by_name = {"a1": ["a1"], "a2": ["a2"]}
    analyzer.current_rule = "caller"
    analyzer.current_rule_key = "caller"
    analyzer.dependencies = defaultdict(set)

    analyzer._record_rule_set_text("a*")

    assert analyzer.dependencies["caller"] == {"a1", "a2"}


def test_record_rule_set_text_wildcard_with_no_matches_records_nothing() -> None:
    """
    A wildcard pattern that matches no rule names still takes the wildcard
    branch (lines 319-324) but adds nothing to dependencies.
    """
    analyzer = DependencyAnalyzer()
    analyzer.rule_names = {"b1", "caller"}
    analyzer._raw_rule_names = {"b1", "caller"}
    analyzer._rule_keys_by_name = {}
    analyzer.current_rule = "caller"
    analyzer.current_rule_key = "caller"
    analyzer.dependencies = defaultdict(set)

    analyzer._record_rule_set_text("a*")

    assert dict(analyzer.dependencies) == {}


# ---------------------------------------------------------------------------
# _record_rule_set_text - lines 326-327 (direct rule name match)
# ---------------------------------------------------------------------------


def test_record_rule_set_text_direct_rule_name_adds_dependency() -> None:
    """
    When the value is an exact rule name (not a self-reference) lines 326-327
    record the dependency.
    """
    analyzer = DependencyAnalyzer()
    analyzer.rule_names = {"a1", "caller"}
    analyzer._raw_rule_names = {"a1", "caller"}
    analyzer._rule_keys_by_name = {"a1": ["a1"]}
    analyzer.current_rule = "caller"
    analyzer.current_rule_key = "caller"
    analyzer.dependencies = defaultdict(set)

    analyzer._record_rule_set_text("a1")

    assert analyzer.dependencies["caller"] == {"a1"}


def test_record_rule_set_text_self_reference_is_not_recorded() -> None:
    """
    When the value equals self.current_rule the condition on line 326
    (value != self.current_rule) is False and no dependency is added.
    """
    analyzer = DependencyAnalyzer()
    analyzer.rule_names = {"caller"}
    analyzer._raw_rule_names = {"caller"}
    analyzer._rule_keys_by_name = {"caller": ["caller"]}
    analyzer.current_rule = "caller"
    analyzer.current_rule_key = "caller"
    analyzer.dependencies = defaultdict(set)

    analyzer._record_rule_set_text("caller")

    assert dict(analyzer.dependencies) == {}


# ---------------------------------------------------------------------------
# _visit_rule_set_value - line 331 (str -> return immediately)
# ---------------------------------------------------------------------------


def test_visit_rule_set_value_plain_string_is_a_no_op() -> None:
    """
    A plain Python str value is not a rule reference (it is a raw YARA
    string-set text token handled elsewhere).  The early return on line 331
    prevents any processing.

    The OfExpression with string_set='them' exercises this path through
    the public API because 'them' is accepted as a valid string_set by
    validate_structure.
    """
    ast = YaraFile(
        rules=[
            Rule(name="a1", condition=BooleanLiteral(True)),
            Rule(name="caller", condition=OfExpression("any", "them")),
        ]
    )

    results = DependencyAnalyzer().analyze(ast)

    assert "caller" not in results["dependencies"]
    assert results["dependency_graph"]["caller"]["is_independent"] is True


# ---------------------------------------------------------------------------
# _visit_rule_set_value - lines 337-338 (Identifier -> _record_rule_set_text)
# ---------------------------------------------------------------------------


def test_visit_rule_set_value_identifier_records_rule_dependency() -> None:
    """
    When the value is an Identifier whose name matches a known rule name the
    Identifier branch on lines 337-338 calls _record_rule_set_text and a
    dependency is recorded.
    """
    ast = YaraFile(
        rules=[
            Rule(name="a1", condition=BooleanLiteral(True)),
            Rule(name="caller", condition=OfExpression("any", Identifier("a1"))),
        ]
    )

    results = DependencyAnalyzer().analyze(ast)

    assert results["dependencies"]["caller"] == ["a1"]
    assert results["dependency_graph"]["a1"]["depended_by"] == ["caller"]


# ---------------------------------------------------------------------------
# _visit_rule_set_value - line 340 (StringLiteral -> return immediately)
# ---------------------------------------------------------------------------


def test_visit_rule_set_value_string_literal_is_a_no_op() -> None:
    """
    A StringLiteral node carries a quoted YARA string value and is never a
    rule reference.  The early return on line 340 is taken.
    """
    ast = YaraFile(
        rules=[
            Rule(name="a1", condition=BooleanLiteral(True)),
            Rule(name="caller", condition=OfExpression("any", StringLiteral("hello"))),
        ]
    )

    results = DependencyAnalyzer().analyze(ast)

    assert "caller" not in results["dependencies"]
    assert results["dependency_graph"]["caller"]["is_independent"] is True


# ---------------------------------------------------------------------------
# _visit_rule_set_value - lines 351-352 (ASTNode fallthrough -> self.visit)
# ---------------------------------------------------------------------------


def test_visit_rule_set_value_generic_ast_node_is_dispatched_via_visit() -> None:
    """
    When the value is an ASTNode that does not match any of the earlier type
    guards the fallthrough branch on lines 351-352 calls self.visit(value).

    BooleanLiteral is an Expression (ASTNode) but it is not a str, list,
    tuple, set, frozenset, Identifier, StringLiteral, StringWildcard,
    ParenthesesExpression, or SetExpression, so it reaches the fallthrough.

    Covers lines 351-352.
    """
    ast = YaraFile(
        rules=[
            Rule(name="caller", condition=OfExpression("any", BooleanLiteral(True))),
        ]
    )

    results = DependencyAnalyzer().analyze(ast)

    # BooleanLiteral carries no rule reference; no dependency is expected.
    assert "caller" not in results["dependencies"]
    assert results["dependency_graph"]["caller"]["is_independent"] is True


# ---------------------------------------------------------------------------
# visit_of_expression - branch 355->357 (non-ASTNode quantifier skips line 356)
# ---------------------------------------------------------------------------


def test_visit_of_expression_string_quantifier_skips_quantifier_visit() -> None:
    """
    When the quantifier is a plain string ('any', 'all', 'none') rather than
    an ASTNode the if-branch on line 355 is False and execution jumps directly
    to line 357 (_visit_rule_set_value), skipping line 356.

    Covers the missing branch 355->357.
    """
    ast = YaraFile(
        rules=[
            Rule(name="a1", condition=BooleanLiteral(True)),
            # 'any' is a string quantifier, not an ASTNode
            Rule(name="caller", condition=OfExpression("any", StringWildcard("a*"))),
        ]
    )

    results = DependencyAnalyzer().analyze(ast)

    assert results["dependencies"]["caller"] == ["a1"]


# ---------------------------------------------------------------------------
# visit_for_of_expression - line 361 (ASTNode quantifier -> self.visit)
# ---------------------------------------------------------------------------


def test_visit_for_of_expression_ast_node_quantifier_is_visited() -> None:
    """
    When the ForOfExpression quantifier is an ASTNode (e.g., an Identifier
    referencing another rule) line 361 visits it, potentially adding a
    dependency on that rule.

    Covers line 361 - self.visit(node.quantifier) inside visit_for_of_expression.
    """
    ast = YaraFile(
        rules=[
            Rule(name="base", condition=BooleanLiteral(True)),
            Rule(
                name="caller",
                condition=ForOfExpression(
                    # Identifier is an ASTNode; referencing 'base' adds a dependency
                    quantifier=Identifier("base"),
                    # dollar-prefixed wildcard: valid string reference, not a rule wildcard
                    string_set=StringWildcard("$*"),
                    condition=BooleanLiteral(True),
                ),
            ),
        ]
    )

    results = DependencyAnalyzer().analyze(ast)

    # The quantifier reference to 'base' must be recorded as a dependency.
    assert results["dependencies"]["caller"] == ["base"]


# ---------------------------------------------------------------------------
# visit_member_access - line 374 (non-Identifier object -> self.visit(object))
# ---------------------------------------------------------------------------


def test_visit_member_access_nested_member_access_visits_inner_object() -> None:
    """
    When the object of a MemberAccess is itself a MemberAccess (not a bare
    Identifier), line 373's isinstance check is False and line 374 calls
    self.visit(node.object), recursing into the inner expression.

    Covers line 374 - the branch where the object is not an Identifier.
    """
    ast = YaraFile(
        rules=[
            Rule(name="base", condition=BooleanLiteral(True)),
            Rule(
                name="caller",
                condition=MemberAccess(
                    # Outer object is another MemberAccess, not an Identifier
                    object=MemberAccess(
                        object=Identifier("pe"),  # module, not a rule -> no dep
                        member="sections",
                    ),
                    member="name",
                ),
            ),
        ]
    )

    results = DependencyAnalyzer().analyze(ast)

    # 'pe' is treated as a module root (Identifier inside MemberAccess) and is
    # not recorded as a rule dependency even though a rule 'base' exists.
    assert "caller" not in results["dependencies"]
    assert results["dependency_graph"]["caller"]["is_independent"] is True


def test_visit_member_access_nested_with_rule_identifier_does_not_add_dependency() -> None:
    """
    When the outermost MemberAccess wraps another MemberAccess whose object
    IS an Identifier that matches a known rule, line 374 recurses into the
    inner MemberAccess.  The inner MemberAccess has an Identifier object so
    its isinstance check on line 373 is True and that Identifier is NOT
    visited (it is treated as a module root).

    This confirms that nested member-access chains do not create spurious
    rule dependencies regardless of identifier names.
    """
    ast = YaraFile(
        rules=[
            Rule(name="pe", condition=BooleanLiteral(True)),
            Rule(
                name="check",
                condition=MemberAccess(
                    object=MemberAccess(
                        object=Identifier("pe"),
                        member="sections",
                    ),
                    member="name",
                ),
            ),
        ]
    )

    results = DependencyAnalyzer().analyze(ast)

    assert "check" not in results["dependencies"]
    assert results["dependency_graph"]["check"]["is_independent"] is True


# ---------------------------------------------------------------------------
# visit_dict_comprehension - branch 411->413 (None value_variable skips append)
# ---------------------------------------------------------------------------


def test_visit_dict_comprehension_without_value_variable_uses_only_key() -> None:
    """
    When DictComprehension.value_variable is None the `if node.value_variable`
    guard on line 411 is False and execution jumps to line 413
    (_push_local_scope with only the key variable), bypassing the append.

    Covers the missing branch 411->413.
    """
    ast = YaraFile(
        rules=[
            Rule(name="k", condition=BooleanLiteral(True)),
            Rule(
                name="caller",
                condition=DictComprehension(
                    key_expression=Identifier("k"),
                    value_expression=BooleanLiteral(True),
                    key_variable="k",
                    value_variable=None,  # triggers the missing branch
                    iterable=ListExpression([IntegerLiteral(1)]),
                ),
            ),
        ]
    )

    results = DependencyAnalyzer().analyze(ast)

    # 'k' is the loop variable and shadows the rule named 'k', so no dep.
    assert "caller" not in results["dependencies"]
    assert results["dependency_graph"]["caller"]["is_independent"] is True


# ---------------------------------------------------------------------------
# _define_local - branch 441->exit (empty local_scopes -> guard is False)
# ---------------------------------------------------------------------------


def test_define_local_with_no_active_scope_is_a_no_op() -> None:
    """
    _define_local guards against an empty local_scopes list with
    `if self.local_scopes:` on line 441.  When the list is empty the call
    is a no-op and local_scopes remains empty.

    Covers the branch 441->exit (guard evaluates to False).

    Rationale: Within the normal visitor flow _define_local is always called
    after _push_local_scope (see visit_with_declaration).  The guard can only
    be False if called directly without a prior push, which is a defensively
    handled invariant violation.
    """
    analyzer = DependencyAnalyzer()
    assert analyzer.local_scopes == []

    analyzer._define_local("x")

    assert analyzer.local_scopes == []


# ---------------------------------------------------------------------------
# _visit_rule_set_value - ParenthesesExpression branch (lines 344-345)
# ---------------------------------------------------------------------------


def test_visit_rule_set_value_parentheses_expression_unwraps_and_recurses() -> None:
    """
    A ParenthesesExpression wrapping an Identifier causes lines 344-345 to
    unwrap the inner expression and recurse, ultimately reaching the Identifier
    branch and recording the dependency.
    """
    ast = YaraFile(
        rules=[
            Rule(name="a1", condition=BooleanLiteral(True)),
            Rule(
                name="caller",
                condition=OfExpression("any", ParenthesesExpression(Identifier("a1"))),
            ),
        ]
    )

    results = DependencyAnalyzer().analyze(ast)

    assert results["dependencies"]["caller"] == ["a1"]


# ---------------------------------------------------------------------------
# visit_string_wildcard - line 284 (invalid pattern type -> TypeError)
# Reachable only via direct invocation; validate_structure raises before the
# visitor runs when using the public analyze() pipeline.
# ---------------------------------------------------------------------------


def test_visit_string_wildcard_non_string_pattern_raises_type_error() -> None:
    """
    visit_string_wildcard checks `isinstance(node.pattern, str)` on line 284
    and raises TypeError when the pattern is not a string.

    Rationale: analyze() calls validate_structure() before visiting any nodes.
    validate_structure() independently rejects a non-string StringWildcard
    pattern, so the visitor guard on line 284 can only be reached by calling
    visit_string_wildcard directly.

    Covers line 284 (the guard itself) and the raise on line 285.
    """
    analyzer = DependencyAnalyzer()

    # Construct a StringWildcard with a non-string pattern by bypassing the
    # constructor's type annotation; use object() to make the type mismatch
    # unambiguous.
    node = StringWildcard.__new__(StringWildcard)
    object.__setattr__(node, "pattern", object())

    try:
        analyzer.visit_string_wildcard(node)
    except TypeError as exc:
        assert "String wildcard pattern must be a string" in str(exc)
    else:
        raise AssertionError("Expected TypeError was not raised")


# ---------------------------------------------------------------------------
# _visit_rule_set_value - branch 351->exit (non-ASTNode, non-matching value)
# Reachable only via direct invocation; validate_structure rejects non-AST
# values inside string sets before the visitor pipeline runs.
# ---------------------------------------------------------------------------


def test_visit_rule_set_value_non_ast_non_collection_value_is_silently_ignored() -> None:
    """
    _visit_rule_set_value exhausts all isinstance guards (str, list/tuple/
    set/frozenset, Identifier, StringLiteral, StringWildcard,
    ParenthesesExpression, SetExpression, ASTNode) without matching when
    the value is a plain integer.  The final `if isinstance(value, ASTNode):`
    on line 351 is False and the function returns implicitly (351->exit).

    Rationale: validate_structure() rejects non-AST, non-string values in
    YARA string sets before the visitor is invoked, so the branch can only be
    reached through direct invocation.

    Covers the branch 351->exit.
    """
    analyzer = DependencyAnalyzer()
    analyzer.current_rule = "caller"
    analyzer.current_rule_key = "caller"

    # An integer is not an ASTNode and does not match any earlier guard.
    analyzer._visit_rule_set_value(42)

    # No dependency should be recorded; the call must be a silent no-op.
    assert dict(analyzer.dependencies) == {}
