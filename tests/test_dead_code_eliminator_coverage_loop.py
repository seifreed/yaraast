# Copyright (c) 2026 Marc Rivero López
# Licensed under GPLv3. See LICENSE file for details.
# This test suite validates real code behavior without mocks or stubs.
"""Coverage-gap tests for yaraast.optimization.dead_code_eliminator.

Each test targets specific uncovered branches identified by the missing-lines
report.  All tests exercise the real optimizer API with real AST nodes; no
mocks or stubs are used.
"""

from __future__ import annotations

from typing import Any, cast

import pytest

from yaraast.ast.base import YaraFile
from yaraast.ast.conditions import AtExpression, ForExpression, ForOfExpression
from yaraast.ast.expressions import (
    BooleanLiteral,
    Identifier,
    IntegerLiteral,
    MemberAccess,
    ParenthesesExpression,
    SetExpression,
    StringCount,
    StringIdentifier,
    StringLength,
    StringLiteral,
    StringOffset,
    StringWildcard,
)
from yaraast.ast.rules import Rule
from yaraast.ast.strings import PlainString
from yaraast.optimization.dead_code_eliminator import (
    DeadCodeEliminator,
    _boolean_literal_value,
)
from yaraast.yarax.ast_nodes import (
    ArrayComprehension,
    DictComprehension,
    ListExpression,
)

# ---------------------------------------------------------------------------
# _boolean_literal_value (line 46)
# ---------------------------------------------------------------------------


def test_boolean_literal_value_returns_none_for_non_bool() -> None:
    """Line 46: _boolean_literal_value returns None when value is not a bool."""
    # Arrange: a BooleanLiteral node carrying a non-bool payload
    node = BooleanLiteral(cast(Any, "yes"))

    # Act
    result = _boolean_literal_value(node)

    # Assert: the non-bool path returns None without raising
    assert result is None


def test_boolean_literal_value_returns_actual_bools() -> None:
    """Complement: _boolean_literal_value returns the bool for valid nodes."""
    assert _boolean_literal_value(BooleanLiteral(True)) is True
    assert _boolean_literal_value(BooleanLiteral(False)) is False


# ---------------------------------------------------------------------------
# _collect_usage — rule with no condition (lines 145->147 branch)
# ---------------------------------------------------------------------------


def test_collect_usage_skips_expression_collection_for_conditionless_rule() -> None:
    """Lines 145-147: _collect_usage skips _collect_from_expression when condition is None.

    A rule with no condition has no string references; its strings are removed.
    """
    ast = YaraFile(
        rules=[
            Rule(
                name="no_condition",
                strings=[PlainString("$unused", value="data")],
                condition=None,
            )
        ]
    )

    optimized, count = DeadCodeEliminator().eliminate(ast)

    # The string was never referenced so it is removed (count == 1).
    assert count == 1
    assert optimized.rules[0].strings == []


# ---------------------------------------------------------------------------
# AtExpression with non-str string_id (lines 169-172)
# ---------------------------------------------------------------------------


def test_collect_from_expression_recurses_into_at_expression_with_expression_string_id() -> None:
    """Lines 169-172: AtExpression whose string_id is an expression, not a bare str.

    The else branch calls _collect_from_expression on the expression so that
    the enclosed StringIdentifier marks its string as used.
    """
    ast = YaraFile(
        rules=[
            Rule(
                name="at_expr_non_str",
                strings=[PlainString("$a", value="needle")],
                condition=AtExpression(
                    string_id=StringIdentifier("$a"),
                    offset=IntegerLiteral(0),
                ),
            )
        ]
    )

    optimized, count = DeadCodeEliminator().eliminate(ast)

    # $a was used via the nested StringIdentifier — it must be kept.
    assert count == 0
    assert [s.identifier for s in optimized.rules[0].strings] == ["$a"]


# ---------------------------------------------------------------------------
# ForOfExpression with ASTNode quantifier (line 186)
# ---------------------------------------------------------------------------


def test_collect_from_expression_handles_for_of_with_astnode_quantifier() -> None:
    """Line 186: ForOfExpression whose quantifier is an ASTNode triggers recursive collect."""
    ast = YaraFile(
        rules=[
            Rule(
                name="for_of_ast_quant",
                strings=[PlainString("$a", value="x")],
                condition=ForOfExpression(
                    quantifier=IntegerLiteral(1),
                    string_set=SetExpression([StringIdentifier("$a")]),
                    condition=BooleanLiteral(True),
                ),
            )
        ]
    )

    optimized, count = DeadCodeEliminator().eliminate(ast)

    # String $a is referenced by the string_set; quantifier is traversed without error.
    assert count == 0
    assert [s.identifier for s in optimized.rules[0].strings] == ["$a"]


# ---------------------------------------------------------------------------
# MemberAccess with non-Identifier object in _collect_from_expression (line 207)
# ---------------------------------------------------------------------------


def test_collect_from_expression_recurses_into_nested_member_access_object() -> None:
    """Line 207: MemberAccess whose object is itself a MemberAccess (not bare Identifier).

    The inner object is recursed into so the entire chain is traversed without
    treating any intermediate node as a rule reference.
    """
    # pe.sections.name — outermost object is MemberAccess(pe, sections)
    ast = YaraFile(
        rules=[
            Rule(
                name="nested_member",
                condition=MemberAccess(
                    object=MemberAccess(object=Identifier("pe"), member="sections"),
                    member="name",
                ),
            ),
            Rule(
                name="pe",
                modifiers=["private"],
                condition=BooleanLiteral(False),
            ),
        ]
    )

    optimized, count = DeadCodeEliminator().eliminate(ast)

    # "pe" appears only as a module root, not a rule reference, so the private rule is removed.
    assert count == 1
    assert [r.name for r in optimized.rules] == ["nested_member"]


# ---------------------------------------------------------------------------
# ForExpression with ASTNode quantifier (line 223)
# ---------------------------------------------------------------------------


def test_collect_for_expression_usage_with_astnode_quantifier() -> None:
    """Line 223: ForExpression with an ASTNode quantifier collects from the quantifier."""
    ast = YaraFile(
        rules=[
            Rule(
                name="for_ast_quant",
                condition=ForExpression(
                    quantifier=IntegerLiteral(2),
                    variable="i",
                    iterable=SetExpression(
                        [IntegerLiteral(1), IntegerLiteral(2), IntegerLiteral(3)]
                    ),
                    body=BooleanLiteral(True),
                ),
            )
        ]
    )

    optimized, count = DeadCodeEliminator().eliminate(ast)

    assert count == 0
    assert [r.name for r in optimized.rules] == ["for_ast_quant"]


# ---------------------------------------------------------------------------
# ArrayComprehension optional fields (lines 249-251, 255-256, 558-560, 564-568)
# ---------------------------------------------------------------------------


def test_array_comprehension_with_all_optional_fields_present() -> None:
    """Lines 255-256, 558-560, 564-568: ArrayComprehension with iterable, condition, expression.

    Exercises both the _collect_array_comprehension_usage path (condition not None,
    expression not None) and the visit_array_comprehension traversal path.
    """
    ast = YaraFile(
        rules=[
            Rule(
                name="arr_full",
                condition=ArrayComprehension(
                    variable="x",
                    iterable=ListExpression([IntegerLiteral(1), IntegerLiteral(2)]),
                    condition=BooleanLiteral(True),
                    expression=IntegerLiteral(42),
                ),
            )
        ]
    )

    optimized, count = DeadCodeEliminator().eliminate(ast)

    assert count == 0
    assert [r.name for r in optimized.rules] == ["arr_full"]


def test_array_comprehension_with_no_iterable_no_condition_no_expression() -> None:
    """Lines 249-251: ArrayComprehension with iterable=None branches are skipped."""
    ast = YaraFile(
        rules=[
            Rule(
                name="arr_empty",
                condition=ArrayComprehension(
                    variable="x",
                    iterable=None,
                    condition=None,
                    expression=None,
                ),
            )
        ]
    )

    optimized, count = DeadCodeEliminator().eliminate(ast)

    assert count == 0
    assert [r.name for r in optimized.rules] == ["arr_empty"]


# ---------------------------------------------------------------------------
# DictComprehension optional fields (lines 263-265, 268-270, 271, 272-277, 573-587)
# ---------------------------------------------------------------------------


def test_dict_comprehension_with_all_optional_fields_present() -> None:
    """Lines 268-277, 573-587: DictComprehension with value_variable, condition, expressions."""
    ast = YaraFile(
        rules=[
            Rule(
                name="dict_full",
                condition=DictComprehension(
                    key_variable="k",
                    value_variable="v",
                    iterable=ListExpression([IntegerLiteral(1)]),
                    condition=BooleanLiteral(True),
                    key_expression=Identifier("k"),
                    value_expression=Identifier("v"),
                ),
            ),
            # "k" and "v" are local variables, not rule references — these should stay.
            Rule(name="k", modifiers=["private"], condition=BooleanLiteral(True)),
            Rule(name="v", modifiers=["private"], condition=BooleanLiteral(True)),
        ]
    )

    optimized, count = DeadCodeEliminator().eliminate(ast)

    # k and v are loop-scoped locals, so the private helper rules are not referenced.
    assert count == 2
    assert [r.name for r in optimized.rules] == ["dict_full"]


def test_dict_comprehension_with_no_optional_fields() -> None:
    """Lines 263-265: DictComprehension with iterable=None skips those branches."""
    ast = YaraFile(
        rules=[
            Rule(
                name="dict_empty",
                condition=DictComprehension(
                    key_variable="k",
                    value_variable=None,
                    iterable=None,
                    condition=None,
                    key_expression=None,
                    value_expression=None,
                ),
            )
        ]
    )

    optimized, count = DeadCodeEliminator().eliminate(ast)

    assert count == 0
    assert [r.name for r in optimized.rules] == ["dict_empty"]


# ---------------------------------------------------------------------------
# _is_private_rule with non-list/tuple modifiers (line 320)
# ---------------------------------------------------------------------------


def test_is_private_rule_returns_false_for_non_iterable_modifiers() -> None:
    """Line 320: _is_private_rule returns False when modifiers is not a list or tuple."""
    rule = Rule(name="test", condition=BooleanLiteral(True))
    # Bypass __post_init__ normalization by setting directly after construction.
    rule.modifiers = "not_a_list"

    dce = DeadCodeEliminator()
    assert dce._is_private_rule(rule) is False


# ---------------------------------------------------------------------------
# _is_private_rule — modifier with .name == "private" (line 328)
# ---------------------------------------------------------------------------


class _PrivateNameOnlyModifier:
    """Modifier stub whose modifier_type.value is NOT 'private' but .name is.

    This exercises line 328 of _is_private_rule: the fallback check
    ``getattr(modifier, "name", None) == "private"`` after the modifier_type
    branch (line 325-326) has already failed to match.
    """

    class _FakeModifierType:
        value = "not_private"

    modifier_type = _FakeModifierType()
    name = "private"


def test_is_private_rule_matches_modifier_via_name_fallback() -> None:
    """Line 328: _is_private_rule falls back to modifier.name when modifier_type.value mismatches."""
    rule = Rule(name="test", condition=BooleanLiteral(True))
    # Bypass __post_init__ normalization: set modifiers directly.
    rule.modifiers = [_PrivateNameOnlyModifier()]

    dce = DeadCodeEliminator()
    assert dce._is_private_rule(rule) is True


# ---------------------------------------------------------------------------
# _mark_used_string returns early for shadowed local variables (line 344)
# ---------------------------------------------------------------------------


def test_mark_used_string_skips_string_shadowed_by_local_variable() -> None:
    """Line 344: _mark_used_string returns early when identifier matches a local variable.

    Exercised through visit_string_identifier with an active local shadowing the string.
    """
    dce = DeadCodeEliminator()
    dce.in_condition = True
    dce.local_variables = ["$a"]
    dce.local_variable_values = [dce._LOCAL_WITHOUT_VALUE]

    dce.visit_string_identifier(StringIdentifier("$a"))

    # The identifier was shadowed; nothing is added to used_strings.
    assert "$a" not in dce.used_strings


# ---------------------------------------------------------------------------
# _matching_rule_wildcard_names edge cases (lines 353, 356)
# ---------------------------------------------------------------------------


def test_matching_rule_wildcard_names_no_star_returns_empty() -> None:
    """Line 353: pattern without trailing * yields an empty tuple."""
    dce = DeadCodeEliminator()
    dce.rule_names = {"aaa", "aab"}

    result = dce._matching_rule_wildcard_names("aaa")

    assert result == ()


def test_matching_rule_wildcard_names_bare_star_returns_empty() -> None:
    """Line 356: pattern '*' has empty prefix and yields an empty tuple."""
    dce = DeadCodeEliminator()
    dce.rule_names = {"aaa", "aab"}

    result = dce._matching_rule_wildcard_names("*")

    assert result == ()


# ---------------------------------------------------------------------------
# _mark_rule_set_reference (lines 366-369)
# ---------------------------------------------------------------------------


def test_mark_rule_set_reference_expands_wildcard_pattern() -> None:
    """Lines 366-368: _mark_rule_set_reference with trailing * adds all matching rules."""
    dce = DeadCodeEliminator()
    dce.rule_names = {"alpha_one", "alpha_two", "beta_three"}
    dce.current_rule = "main"

    dce._mark_rule_set_reference("alpha*")

    assert "alpha_one" in dce.used_rules
    assert "alpha_two" in dce.used_rules
    assert "beta_three" not in dce.used_rules


def test_mark_rule_set_reference_adds_exact_name() -> None:
    """Line 369: _mark_rule_set_reference without * adds the exact name."""
    dce = DeadCodeEliminator()

    dce._mark_rule_set_reference("exact_rule")

    assert "exact_rule" in dce.used_rules


# ---------------------------------------------------------------------------
# _mark_all_current_rule_strings (lines 372-373)
# ---------------------------------------------------------------------------


def test_mark_all_current_rule_strings_marks_every_string_in_rule() -> None:
    """Lines 372-373: _mark_all_current_rule_strings iterates current_rule_strings."""
    dce = DeadCodeEliminator()
    dce.current_rule_key = "r"
    dce.used_strings_by_rule["r"] = set()
    dce.current_rule_strings = {"$a", "$b", "$c"}

    dce._mark_all_current_rule_strings()

    assert dce.used_strings >= {"$a", "$b", "$c"}


# ---------------------------------------------------------------------------
# _collect_string_set_value — local variable with a concrete value (lines 385-387)
# ---------------------------------------------------------------------------


def test_collect_string_set_value_resolves_local_variable_with_concrete_value() -> None:
    """Lines 385-387: when a local variable holds a StringLiteral, its value is recursed.

    _collect_string_set_value looks up the local variable by name; when its
    stored value is not the _LOCAL_WITHOUT_VALUE sentinel, it recurses into
    that concrete value so the real string identifier is marked as used.
    """
    # Arrange: simulate a local variable $x bound to StringLiteral("$a").
    dce = DeadCodeEliminator()
    dce.current_rule_key = "r"
    dce.used_strings_by_rule["r"] = set()
    dce.local_variables = ["$x"]
    dce.local_variable_values = [StringLiteral("$a")]

    # Act: call _collect_string_set_value with the string "$x" — it must
    # resolve the local binding and ultimately mark "$a" as used.
    dce._collect_string_set_value("$x")

    # Assert: the concrete underlying string is marked as used.
    assert "$a" in dce.used_strings
    assert "$x" not in dce.used_strings


# ---------------------------------------------------------------------------
# _collect_string_set_value — "them" as raw string (line 389)
# ---------------------------------------------------------------------------


def test_collect_string_set_value_them_string_marks_all_strings() -> None:
    """Line 389: _collect_string_set_value("them") marks every string in the current rule."""
    dce = DeadCodeEliminator()
    dce.current_rule_key = "r"
    dce.used_strings_by_rule["r"] = set()
    dce.current_rule_strings = {"$a", "$b"}

    dce._collect_string_set_value("them")

    assert dce.used_strings >= {"$a", "$b"}


# ---------------------------------------------------------------------------
# _collect_string_set_value — Identifier("them") (lines 398-399)
# ---------------------------------------------------------------------------


def test_collect_string_set_value_them_identifier_marks_all_strings() -> None:
    """Lines 398-399: Identifier with name 'them' marks all current-rule strings."""
    dce = DeadCodeEliminator()
    dce.current_rule_key = "r"
    dce.used_strings_by_rule["r"] = set()
    dce.current_rule_strings = {"$x", "$y"}

    dce._collect_string_set_value(Identifier("them"))

    assert dce.used_strings >= {"$x", "$y"}


# ---------------------------------------------------------------------------
# _collect_string_set_value — Identifier not starting with $ (lines 404-405)
# ---------------------------------------------------------------------------


def test_collect_string_set_value_non_dollar_identifier_marks_rule_reference() -> None:
    """Lines 404-405: Identifier that does not start with '$' calls _mark_rule_set_reference."""
    dce = DeadCodeEliminator()
    dce.rule_names = {"helper_rule"}
    dce.current_rule = "main"

    dce._collect_string_set_value(Identifier("helper_rule"))

    assert "helper_rule" in dce.used_rules


# ---------------------------------------------------------------------------
# _collect_for_of_string_set_value — ParenthesesExpression (lines 428-429)
# ---------------------------------------------------------------------------


def test_collect_for_of_string_set_value_recurses_into_parentheses_expression() -> None:
    """Lines 428-429: ParenthesesExpression in _collect_for_of_string_set_value is unwrapped."""
    dce = DeadCodeEliminator()
    dce.current_rule_key = "r"
    dce.used_strings_by_rule["r"] = set()

    dce._collect_for_of_string_set_value(ParenthesesExpression(StringIdentifier("$z")))

    assert "$z" in dce.used_strings


# ---------------------------------------------------------------------------
# _collect_for_of_string_set_value — dollar StringWildcard (line 436)
# ---------------------------------------------------------------------------


def test_collect_for_of_string_set_value_marks_dollar_wildcard() -> None:
    """Line 436: StringWildcard starting with '$' is marked as used in _collect_for_of."""
    dce = DeadCodeEliminator()
    dce.current_rule_key = "r"
    dce.used_strings_by_rule["r"] = set()
    dce.current_rule_strings = {"$api_x"}

    dce._collect_for_of_string_set_value(StringWildcard("$api*"))

    assert "$api*" in dce.used_strings


# ---------------------------------------------------------------------------
# _collect_for_of_string_set_value — Identifier not them/$ is ignored (line 441)
# ---------------------------------------------------------------------------


def test_collect_for_of_string_set_value_ignores_non_dollar_non_them_identifier() -> None:
    """Line 441: Identifier whose name is not 'them' and doesn't start with '$' is skipped."""
    dce = DeadCodeEliminator()
    dce.current_rule_key = "r"
    dce.used_strings_by_rule["r"] = set()
    dce.rule_names = {"some_rule"}
    dce.current_rule = "main"

    # In for_of context, rule-name Identifiers must be ignored.
    dce._collect_for_of_string_set_value(Identifier("some_rule"))

    assert "some_rule" not in dce.used_rules


# ---------------------------------------------------------------------------
# visit_rule — condition not None path traverses condition (lines 487-492)
# ---------------------------------------------------------------------------


def test_visit_rule_optimizes_condition_when_present() -> None:
    """Lines 487-492: visit_rule visits the rule's condition through the visitor."""
    ast = YaraFile(
        rules=[
            Rule(
                name="with_cond",
                strings=[
                    PlainString("$used", value="a"),
                    PlainString("$unused", value="b"),
                ],
                condition=StringIdentifier("$used"),
            )
        ]
    )

    optimized, count = DeadCodeEliminator().eliminate(ast)

    assert count == 1
    assert [s.identifier for s in optimized.rules[0].strings] == ["$used"]
    assert optimized.rules[0].condition == StringIdentifier("$used")


# ---------------------------------------------------------------------------
# visit_string_wildcard when not in_condition (lines 507-509)
# ---------------------------------------------------------------------------


def test_visit_string_wildcard_does_not_track_when_not_in_condition() -> None:
    """Lines 507-509: visit_string_wildcard skips tracking when in_condition is False."""
    dce = DeadCodeEliminator()
    dce.in_condition = False

    returned = dce.visit_string_wildcard(StringWildcard("$x*"))

    assert returned == StringWildcard("$x*")
    assert "$x*" not in dce.used_strings


# ---------------------------------------------------------------------------
# visit_for_expression with ASTNode quantifier (line 523)
# ---------------------------------------------------------------------------


def test_visit_for_expression_visits_astnode_quantifier() -> None:
    """Line 523: visit_for_expression visits the quantifier when it is an ASTNode."""
    ast = YaraFile(
        rules=[
            Rule(
                name="for_quant",
                condition=ForExpression(
                    quantifier=IntegerLiteral(2),
                    variable="x",
                    iterable=SetExpression(
                        [IntegerLiteral(1), IntegerLiteral(2), IntegerLiteral(3)]
                    ),
                    body=BooleanLiteral(True),
                ),
            )
        ]
    )

    optimized, count = DeadCodeEliminator().eliminate(ast)

    assert count == 0
    rule = optimized.rules[0]
    assert isinstance(rule.condition, ForExpression)
    assert rule.condition.quantifier == IntegerLiteral(2)


# ---------------------------------------------------------------------------
# visit_for_of_expression with ASTNode quantifier (line 536)
# ---------------------------------------------------------------------------


def test_visit_for_of_expression_visits_astnode_quantifier() -> None:
    """Line 536: visit_for_of_expression visits the quantifier when it is an ASTNode."""
    ast = YaraFile(
        rules=[
            Rule(
                name="forof_quant",
                strings=[PlainString("$a", value="x")],
                condition=ForOfExpression(
                    quantifier=IntegerLiteral(1),
                    string_set=StringIdentifier("$a"),
                    condition=None,
                ),
            )
        ]
    )

    optimized, count = DeadCodeEliminator().eliminate(ast)

    assert count == 0
    rule = optimized.rules[0]
    assert isinstance(rule.condition, ForOfExpression)
    assert rule.condition.quantifier == IntegerLiteral(1)


# ---------------------------------------------------------------------------
# visit_member_access — non-Identifier object (line 604)
# ---------------------------------------------------------------------------


def test_visit_member_access_recurses_into_non_identifier_object() -> None:
    """Line 604: visit_member_access visits the object when it is not a bare Identifier."""
    # pe.sections.name — the outer MemberAccess has object = MemberAccess(pe, sections)
    ast = YaraFile(
        rules=[
            Rule(
                name="deep_member",
                condition=MemberAccess(
                    object=MemberAccess(object=Identifier("pe"), member="sections"),
                    member="name",
                ),
            )
        ]
    )

    optimized, count = DeadCodeEliminator().eliminate(ast)

    assert count == 0
    assert [r.name for r in optimized.rules] == ["deep_member"]


# ---------------------------------------------------------------------------
# visit_string_count / visit_string_offset / visit_string_length
# when in_condition is True (lines 630-642)
# ---------------------------------------------------------------------------


def test_visit_string_count_marks_string_when_in_condition() -> None:
    """Lines 630-632: visit_string_count marks the string as used when in_condition is True."""
    dce = DeadCodeEliminator()
    dce.in_condition = True
    dce.current_rule_key = "r"
    dce.used_strings_by_rule["r"] = set()

    dce.visit_string_count(StringCount("$c"))

    assert "$c" in dce.used_strings


def test_visit_string_offset_marks_string_when_in_condition() -> None:
    """Lines 635-637: visit_string_offset marks the string as used when in_condition is True."""
    dce = DeadCodeEliminator()
    dce.in_condition = True
    dce.current_rule_key = "r"
    dce.used_strings_by_rule["r"] = set()

    dce.visit_string_offset(StringOffset("$o"))

    assert "$o" in dce.used_strings


def test_visit_string_length_marks_string_when_in_condition() -> None:
    """Lines 640-642: visit_string_length marks the string as used when in_condition is True."""
    dce = DeadCodeEliminator()
    dce.in_condition = True
    dce.current_rule_key = "r"
    dce.used_strings_by_rule["r"] = set()

    dce.visit_string_length(StringLength("$l"))

    assert "$l" in dce.used_strings


def test_visit_count_offset_length_do_not_mark_when_not_in_condition() -> None:
    """Complement: count/offset/length nodes do not track when in_condition is False."""
    dce = DeadCodeEliminator()
    dce.in_condition = False

    dce.visit_string_count(StringCount("$c"))
    dce.visit_string_offset(StringOffset("$o"))
    dce.visit_string_length(StringLength("$l"))

    assert dce.used_strings == set()


# ---------------------------------------------------------------------------
# DeadCodeEliminator.eliminate() — condition is None
# ---------------------------------------------------------------------------


def test_eliminate_dead_code_single_rule_with_no_condition_removes_all_strings() -> None:
    """A rule with no condition has no string references, so all strings are removed."""
    dce = DeadCodeEliminator()
    rule = Rule(
        name="no_cond_single",
        strings=[PlainString("$x", value="data")],
        condition=None,
    )

    result = dce.eliminate(YaraFile(rules=[rule]))[0].rules[0]

    assert result.strings == []


# ---------------------------------------------------------------------------
# DeadCodeEliminator.eliminate() — condition and strings
# ---------------------------------------------------------------------------


def test_eliminate_dead_code_single_rule_with_condition_prunes_unused_strings() -> None:
    """Dead-code elimination removes strings not referenced by the condition.

    Arrange a rule with two strings where only one is used.  The method must
    iterate the strings block, check each identifier against the usage set, and
    remove unreferenced entries.
    """
    dce = DeadCodeEliminator()
    rule = Rule(
        name="prune_single",
        strings=[
            PlainString("$kept", value="useful"),
            PlainString("$dropped", value="dead"),
        ],
        condition=StringIdentifier("$kept"),
    )

    result = dce.eliminate(YaraFile(rules=[rule]))[0].rules[0]

    assert [s.identifier for s in result.strings] == ["$kept"]


@pytest.mark.parametrize(
    ("used_str", "kept"),
    [
        ("$first", ["$first"]),
        ("$second", ["$second"]),
    ],
)
def test_eliminate_dead_code_single_rule_parametrized_string_selection(
    used_str: str, kept: list[str]
) -> None:
    """Dead-code elimination keeps exactly the referenced string."""
    dce = DeadCodeEliminator()
    rule = Rule(
        name="param_single",
        strings=[
            PlainString("$first", value="alpha"),
            PlainString("$second", value="beta"),
        ],
        condition=StringIdentifier(used_str),
    )

    result = dce.eliminate(YaraFile(rules=[rule]))[0].rules[0]

    assert [s.identifier for s in result.strings] == kept


# ---------------------------------------------------------------------------
# AtExpression with bare-string string_id (line 170)
# ---------------------------------------------------------------------------


def test_collect_from_expression_marks_at_expression_with_str_string_id() -> None:
    """Line 170: AtExpression whose string_id is a plain str triggers _mark_used_string.

    _collect_from_expression checks isinstance(expr.string_id, str) first; when
    True it calls _mark_used_string directly (line 170).  The expression path
    (line 172) is a separate branch already covered by
    test_collect_from_expression_recurses_into_at_expression_with_expression_string_id.
    """
    dce = DeadCodeEliminator()
    dce.current_rule_key = "r"
    dce.used_strings_by_rule["r"] = set()

    # Call _collect_from_expression directly with an AtExpression whose
    # string_id is the plain string "$a".
    from yaraast.ast.conditions import AtExpression as _AtExpression

    dce._collect_from_expression(_AtExpression(string_id="$a", offset=IntegerLiteral(0)))

    assert "$a" in dce.used_strings


# ---------------------------------------------------------------------------
# _is_private_rule — raw string "private" in modifiers list (line 323)
# ---------------------------------------------------------------------------


def test_is_private_rule_returns_true_for_raw_string_private_modifier() -> None:
    """Line 323: _is_private_rule returns True when a modifier is the raw string 'private'.

    Rule.__post_init__ normalises string modifiers to RuleModifier objects, so
    to reach this branch we build a rule without invoking __post_init__ and
    then call _is_private_rule directly — which is the only caller of this
    internal helper.
    """
    rule = Rule.__new__(Rule)
    rule.name = "stub"
    rule.modifiers = ["private"]  # raw string, not RuleModifier
    rule.tags = []
    rule.meta = []
    rule.strings = []
    rule.condition = BooleanLiteral(True)
    rule.pragmas = []

    dce = DeadCodeEliminator()
    assert dce._is_private_rule(rule) is True


# ---------------------------------------------------------------------------
# _mark_used_wildcard — non-str pattern raises TypeError (line 344)
# ---------------------------------------------------------------------------


def test_mark_used_wildcard_raises_for_non_str_pattern() -> None:
    """Line 344: _mark_used_wildcard raises TypeError when pattern is not a str."""
    dce = DeadCodeEliminator()

    with pytest.raises(TypeError, match="String wildcard pattern must be a string"):
        dce._mark_used_wildcard(cast(Any, False))


# ---------------------------------------------------------------------------
# _collect_string_set_value — local variable with _LOCAL_WITHOUT_VALUE sentinel
# (arc 385->387: local exists but has no concrete value, so no recursion)
# ---------------------------------------------------------------------------


def test_collect_string_set_value_skips_recursion_for_sentinel_local_value() -> None:
    """Arc 385->387: when a local variable holds the sentinel _LOCAL_WITHOUT_VALUE,
    _collect_string_set_value returns immediately without recursing.

    This covers the branch where a for-loop variable (which has no concrete
    assigned value) shadows a string name and the set reference is skipped.
    """
    dce = DeadCodeEliminator()
    dce.current_rule_key = "r"
    dce.used_strings_by_rule["r"] = set()
    # Simulate a for-expression loop variable that has no bound value.
    dce.local_variables = ["$i"]
    dce.local_variable_values = [dce._LOCAL_WITHOUT_VALUE]

    # Calling _collect_string_set_value with "$i" must find the local, see the
    # sentinel value, and return without marking anything as used.
    dce._collect_string_set_value("$i")

    assert "$i" not in dce.used_strings
    assert dce.used_strings == set()


# ---------------------------------------------------------------------------
# DeadCodeEliminator.eliminate() — rule with no strings
# ---------------------------------------------------------------------------


def test_eliminate_dead_code_single_rule_with_no_strings_skips_pruning() -> None:
    """A rule with no strings remains unchanged."""
    dce = DeadCodeEliminator()
    rule = Rule(
        name="no_strings",
        strings=[],
        condition=BooleanLiteral(True),
    )

    result = dce.eliminate(YaraFile(rules=[rule]))[0].rules[0]

    # A rule with no strings is returned unchanged; state is properly reset.
    assert result.strings == []
    assert dce.in_condition is False
    assert dce.current_rule is None
