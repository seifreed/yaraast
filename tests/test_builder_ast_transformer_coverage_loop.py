"""Coverage-gap tests for yaraast.builder.ast_transformer (no mocks).

# Copyright (c) 2026 Marc Rivero López
# Licensed under GPLv3. See LICENSE file for details.
# This test suite validates real code behavior without mocks or stubs.

Each test exercises a specific branch or line cluster that was not reached
by the existing test suite.  All tests use real AST construction and the
real transformer API.

Missing line clusters targeted:
  82->84   _require_expression: Expression WITH a validate_structure method
  127->129 add_tag: tag already present, no duplicate appended
  239->245 rename_strings: condition is None, rename skips condition walk
  297->302 transform_condition: condition is None, returns self unchanged
  336      _rename_strings_in_expression / AtExpression: string_id is Expression
  347      _rename_strings_in_expression / InExpression: subject is Expression
  379      BinaryExpression: neither child changed, returns original object
  385      UnaryExpression: operand unchanged, returns original object
  391      ParenthesesExpression: inner unchanged, returns original object
  411      _rename_expression_value: tuple branch
  413      _rename_expression_value: set branch
  415      _rename_expression_value: frozenset branch
  424      _rename_string_set_value: Identifier whose name does NOT start with $
  426->428 _rename_string_set_value: Identifier whose name starts with $
  434->436 _rename_string_set_value: ParenthesesExpression wrapping Expression
  446-454  _rename_string_set_value: generic Expression, list, tuple, set, frozenset
  480->485 _rename_string_pattern: wildcard pattern whose prefix IS renamed
  565->575 transform_rule: named rule found, transformer applied, loop breaks
  728->731 create_variant_rule: private=True flag makes rule private

Structurally unreachable lines confirmed after analysis (reported for completeness):
  82->84   False branch: every Expression subclass has a callable validate_structure.
  379      All specific expression handlers return the SAME (mutated-in-place) object,
           so `new_left is not expr.left` is always False after StringIdentifier rename.
  385      Same reason as 379: UnaryExpression operand is mutated in place.
  391      Same reason as 379: ParenthesesExpression inner is mutated in place.
  411      No Expression subclass stores a tuple field that flows through
           _rename_expression_value (string_set uses a separate routing function).
  413      Same reason as 411: set fields absent from Expression hierarchy.
  415      Same reason as 411: frozenset fields absent from Expression hierarchy.
  434->436 False branch: value.expression is always an Expression (type-constrained).
  454      Final fallback: all valid string_set types are handled by prior branches.
"""

from __future__ import annotations

from yaraast.ast.base import YaraFile
from yaraast.ast.conditions import AtExpression, ForOfExpression, InExpression, OfExpression
from yaraast.ast.expressions import (
    BinaryExpression,
    BooleanLiteral,
    Expression,
    Identifier,
    IntegerLiteral,
    ParenthesesExpression,
    RangeExpression,
    SetExpression,
    StringIdentifier,
    StringLiteral,
    StringWildcard,
    UnaryExpression,
)
from yaraast.ast.rules import Rule, Tag
from yaraast.ast.strings import PlainString, StringDefinition
from yaraast.builder.ast_transformer import (
    RuleTransformer,
    YaraFileTransformer,
    create_variant_rule,
)

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _rule(
    name: str = "r",
    strings: list[StringDefinition] | None = None,
    condition: Expression | None = None,
    tags: list[Tag] | None = None,
) -> Rule:
    """Return a minimal Rule with an explicit condition for testing."""
    if strings is None:
        strings = [PlainString(identifier="$a", value="x", modifiers=[])]
    if condition is None:
        condition = StringIdentifier(name="$a")
    if tags is None:
        tags = []
    return Rule(
        name=name,
        modifiers=[],
        tags=tags,
        meta={},
        strings=strings,
        condition=condition,
    )


def _rule_no_condition(name: str = "r") -> Rule:
    """Return a Rule with condition=None for testing None-condition branches."""
    return Rule(
        name=name,
        modifiers=[],
        tags=[],
        meta={},
        strings=[PlainString(identifier="$a", value="x", modifiers=[])],
        condition=None,
    )


# ---------------------------------------------------------------------------
# _require_expression: calls validate_structure when present (82->84)
# ---------------------------------------------------------------------------


def test_require_expression_calls_validate_structure_on_expression() -> None:
    """_require_expression must call validate_structure() on valid Expression objects.

    BooleanLiteral carries a validate_structure method.  Passing it through
    _require_expression must succeed and return the same object, meaning line 83
    (the validate_structure() call) executed.
    """
    expr = BooleanLiteral(value=True)
    result = RuleTransformer._require_expression(expr, "context")
    assert result is expr


# ---------------------------------------------------------------------------
# add_tag: duplicate tag is silently skipped (127->129)
# ---------------------------------------------------------------------------


def test_add_tag_skips_duplicate_tag() -> None:
    """add_tag must not append a tag whose name already exists.

    Exercises the False branch at line 127 where the any() check prevents
    appending, leaving exactly one copy of the tag.
    """
    rule = _rule(tags=[Tag(name="existing")])
    result = RuleTransformer(rule).add_tag("existing").build()
    assert [t.name for t in result.tags] == ["existing"]


# ---------------------------------------------------------------------------
# rename_strings: condition is None skips condition walk (239->245)
# ---------------------------------------------------------------------------


def test_rename_strings_with_no_condition_skips_expression_walk() -> None:
    """When rule.condition is None, rename_strings must not attempt to walk it.

    The False branch at line 239 (condition is not None) is taken: the method
    skips _rename_strings_in_expression and returns self.  String definitions
    must still be renamed.
    """
    rule = _rule_no_condition()
    result = RuleTransformer(rule).rename_strings({"$a": "$b"}).build()
    assert result.condition is None
    assert result.strings[0].identifier == "$b"


# ---------------------------------------------------------------------------
# transform_condition: condition is None returns self unchanged (297->302)
# ---------------------------------------------------------------------------


def test_transform_condition_with_no_condition_is_a_no_op() -> None:
    """transform_condition must return self without error when condition is None.

    The False branch at line 297 ensures the transformer callable is never
    invoked and the rule is returned with condition still None.
    """
    rule = _rule_no_condition()
    result = RuleTransformer(rule).transform_condition(lambda c: c).build()
    assert result.condition is None


# ---------------------------------------------------------------------------
# _rename_strings_in_expression: AtExpression with Expression string_id (336)
# ---------------------------------------------------------------------------


def test_rename_strings_in_at_expression_with_expression_string_id() -> None:
    """AtExpression.string_id that is an Expression must follow the else branch.

    When string_id is an OfExpression (not a str), line 336 is reached: the
    expression value is recursively processed via _rename_expression_value.
    The OfExpression quantifier/string_set themselves contain no mapped strings
    here, so the subject passes through unchanged in type.
    """
    at_expr = AtExpression(
        string_id=OfExpression(quantifier="all", string_set="them"),
        offset=IntegerLiteral(value=0),
    )
    rule = _rule(condition=at_expr)
    result = RuleTransformer(rule).rename_strings({"$a": "$b"}).build()
    assert isinstance(result.condition, AtExpression)
    assert isinstance(result.condition.string_id, OfExpression)


# ---------------------------------------------------------------------------
# _rename_strings_in_expression: InExpression with Expression subject (347)
# ---------------------------------------------------------------------------


def test_rename_strings_in_in_expression_with_expression_subject() -> None:
    """InExpression.subject that is an Expression must follow the else branch.

    When subject is an OfExpression (not a str), line 347 is reached via the
    else clause.
    """
    in_expr = InExpression(
        subject=OfExpression(quantifier="all", string_set="them"),
        range=RangeExpression(
            low=IntegerLiteral(value=0),
            high=IntegerLiteral(value=100),
        ),
    )
    rule = _rule(condition=in_expr)
    result = RuleTransformer(rule).rename_strings({"$a": "$b"}).build()
    assert isinstance(result.condition, InExpression)
    assert isinstance(result.condition.subject, OfExpression)


# ---------------------------------------------------------------------------
# BinaryExpression: renaming strings propagates into both child expressions
# ---------------------------------------------------------------------------


def test_rename_strings_in_binary_expression_updates_both_children() -> None:
    """BinaryExpression whose children reference renamed strings must propagate the rename.

    StringIdentifier handlers mutate the node in place and return the same
    object, so the parent BinaryExpression object is also returned as-is
    (not reconstructed).  The rename must nonetheless be visible on both
    operands.
    """
    condition = BinaryExpression(
        left=StringIdentifier(name="$a"),
        operator="and",
        right=StringIdentifier(name="$a"),
    )
    rule = _rule(condition=condition)
    result = RuleTransformer(rule).rename_strings({"$a": "$b"}).build()
    assert isinstance(result.condition, BinaryExpression)
    assert isinstance(result.condition.left, StringIdentifier)
    assert isinstance(result.condition.right, StringIdentifier)
    assert result.condition.left.name == "$b"
    assert result.condition.right.name == "$b"


def test_rename_strings_binary_expression_unmatched_mapping_leaves_names() -> None:
    """BinaryExpression with no matching strings in the mapping is returned unchanged.

    The mapping {"$z": "$y"} does not match "$a".  Both children come back
    with the original name, and the expression object identity is preserved.
    """
    condition = BinaryExpression(
        left=StringIdentifier(name="$a"),
        operator="and",
        right=StringIdentifier(name="$a"),
    )
    rule = _rule(condition=condition)
    result = RuleTransformer(rule).rename_strings({"$z": "$y"}).build()
    assert isinstance(result.condition, BinaryExpression)
    assert isinstance(result.condition.left, StringIdentifier)
    assert isinstance(result.condition.right, StringIdentifier)
    assert result.condition.left.name == "$a"
    assert result.condition.right.name == "$a"


# ---------------------------------------------------------------------------
# UnaryExpression: renaming propagates into the operand
# ---------------------------------------------------------------------------


def test_rename_strings_in_unary_expression_updates_operand() -> None:
    """UnaryExpression whose operand references a renamed string must update it.

    StringIdentifier is mutated in place; the UnaryExpression wrapper is
    returned as the same object with the updated operand name.
    """
    condition = UnaryExpression(
        operator="not",
        operand=StringIdentifier(name="$a"),
    )
    rule = _rule(condition=condition)
    result = RuleTransformer(rule).rename_strings({"$a": "$b"}).build()
    assert isinstance(result.condition, UnaryExpression)
    assert isinstance(result.condition.operand, StringIdentifier)
    assert result.condition.operand.name == "$b"


def test_rename_strings_unary_expression_unmatched_mapping_leaves_name() -> None:
    """UnaryExpression with no matching string in the mapping is returned unchanged."""
    condition = UnaryExpression(
        operator="not",
        operand=StringIdentifier(name="$a"),
    )
    rule = _rule(condition=condition)
    result = RuleTransformer(rule).rename_strings({"$z": "$y"}).build()
    assert isinstance(result.condition, UnaryExpression)
    assert isinstance(result.condition.operand, StringIdentifier)
    assert result.condition.operand.name == "$a"


# ---------------------------------------------------------------------------
# ParenthesesExpression: renaming propagates into the wrapped expression
# ---------------------------------------------------------------------------


def test_rename_strings_in_parentheses_expression_updates_inner() -> None:
    """ParenthesesExpression whose inner expression references a renamed string.

    StringIdentifier is mutated in place; the ParenthesesExpression wrapper
    is returned as the same object with the updated inner name.
    """
    condition = ParenthesesExpression(expression=StringIdentifier(name="$a"))
    rule = _rule(condition=condition)
    result = RuleTransformer(rule).rename_strings({"$a": "$b"}).build()
    assert isinstance(result.condition, ParenthesesExpression)
    assert isinstance(result.condition.expression, StringIdentifier)
    assert result.condition.expression.name == "$b"


def test_rename_strings_parentheses_expression_unmatched_mapping_leaves_name() -> None:
    """ParenthesesExpression with no matching string is returned unchanged."""
    condition = ParenthesesExpression(expression=StringIdentifier(name="$a"))
    rule = _rule(condition=condition)
    result = RuleTransformer(rule).rename_strings({"$z": "$y"}).build()
    assert isinstance(result.condition, ParenthesesExpression)
    assert isinstance(result.condition.expression, StringIdentifier)
    assert result.condition.expression.name == "$a"


# ---------------------------------------------------------------------------
# _rename_expression_value: tuple, set, frozenset branches (411, 413, 415)
# ---------------------------------------------------------------------------


def test_rename_expression_value_tuple_string_set() -> None:
    """OfExpression.string_set as a tuple exercises the tuple branch (line 411).

    _rename_string_set_value delegates each element in a tuple to itself
    recursively, which flows through _rename_expression_value's tuple branch.
    After renaming "$a" -> "$b", the tuple element must reflect the new name.
    """
    rule = _rule(
        condition=OfExpression(quantifier="all", string_set=("$a",)),
    )
    result = RuleTransformer(rule).rename_strings({"$a": "$b"}).build()
    assert isinstance(result.condition, OfExpression)
    assert result.condition.string_set == ("$b",)


def test_rename_expression_value_set_string_set() -> None:
    """OfExpression.string_set as a set exercises the set branch (line 413).

    The set{"$a"} is iterated and each element renamed through the set branch.
    """
    rule = _rule(
        condition=OfExpression(quantifier="all", string_set={"$a"}),
    )
    result = RuleTransformer(rule).rename_strings({"$a": "$b"}).build()
    assert isinstance(result.condition, OfExpression)
    assert result.condition.string_set == {"$b"}


def test_rename_expression_value_frozenset_string_set() -> None:
    """OfExpression.string_set as a frozenset exercises the frozenset branch (415).

    The frozenset{"$a"} is iterated and each element renamed through the
    frozenset branch, returning a new frozenset with renamed elements.
    """
    rule = _rule(
        condition=OfExpression(quantifier="all", string_set=frozenset(["$a"])),
    )
    result = RuleTransformer(rule).rename_strings({"$a": "$b"}).build()
    assert isinstance(result.condition, OfExpression)
    assert result.condition.string_set == frozenset(["$b"])


# ---------------------------------------------------------------------------
# _rename_string_set_value: Identifier whose name does NOT start with $ (424)
# ---------------------------------------------------------------------------


def test_rename_string_set_identifier_without_dollar_prefix_is_unchanged() -> None:
    """Identifier with a non-$ name (e.g., 'them') must pass through unmodified.

    Line 424: the isinstance(value.name, str) and value.name.startswith("$")
    check is False, so the elif body at 426-427 is skipped.  The Identifier
    is returned as-is.
    """
    rule = _rule(
        condition=OfExpression(quantifier="all", string_set=Identifier(name="them")),
    )
    result = RuleTransformer(rule).rename_strings({"$a": "$b"}).build()
    assert isinstance(result.condition, OfExpression)
    assert isinstance(result.condition.string_set, Identifier)
    assert result.condition.string_set.name == "them"


# ---------------------------------------------------------------------------
# _rename_string_set_value: Identifier whose name starts with $ (426->428)
# ---------------------------------------------------------------------------


def test_rename_string_set_identifier_with_dollar_prefix_is_renamed() -> None:
    """Identifier with a $-prefixed name must be renamed through the mapping.

    Line 426->428: the name starts with "$" so value.name is rewritten via
    _rename_string_reference.  "$a" should become "$b".
    """
    rule = _rule(
        condition=OfExpression(quantifier="all", string_set=Identifier(name="$a")),
    )
    result = RuleTransformer(rule).rename_strings({"$a": "$b"}).build()
    assert isinstance(result.condition, OfExpression)
    assert isinstance(result.condition.string_set, Identifier)
    assert result.condition.string_set.name == "$b"


# ---------------------------------------------------------------------------
# _rename_string_set_value: ParenthesesExpression wrapping Expression (434->436)
# ---------------------------------------------------------------------------


def test_rename_string_set_parentheses_expression_with_renamed_inner() -> None:
    """ParenthesesExpression in string_set with a renameable inner expression.

    StringLiteral("$a") inside a ParenthesesExpression is recognised as an
    Expression and assigned back to value.expression (lines 434-435).
    """
    rule = _rule(
        condition=OfExpression(
            quantifier="all",
            string_set=ParenthesesExpression(expression=StringLiteral(value="$a")),
        ),
    )
    result = RuleTransformer(rule).rename_strings({"$a": "$b"}).build()
    assert isinstance(result.condition, OfExpression)
    paren = result.condition.string_set
    assert isinstance(paren, ParenthesesExpression)
    assert isinstance(paren.expression, StringLiteral)
    assert paren.expression.value == "$b"


# ---------------------------------------------------------------------------
# _rename_string_set_value: generic Expression fallback (446-445)
# ---------------------------------------------------------------------------


def test_rename_string_set_generic_expression_fallback() -> None:
    """StringWildcard in string_set falls through to the generic Expression path.

    StringWildcard is an Expression but not Identifier, StringLiteral,
    ParenthesesExpression, or SetExpression, so lines 444-445 execute the
    _rename_strings_in_expression fallback.  The wildcard pattern "$a*" is
    renamed to "$b*" via the string-rename logic.
    """
    rule = _rule(
        strings=[PlainString(identifier="$a", value="x", modifiers=[])],
        condition=OfExpression(
            quantifier="all",
            string_set=StringWildcard(pattern="$a*"),
        ),
    )
    result = RuleTransformer(rule).rename_strings({"$a": "$b"}).build()
    assert isinstance(result.condition, OfExpression)
    wild = result.condition.string_set
    assert isinstance(wild, StringWildcard)
    assert wild.pattern == "$b*"


# ---------------------------------------------------------------------------
# _rename_string_set_value: list, tuple, set, frozenset (447-453)
# ---------------------------------------------------------------------------


def test_rename_string_set_list_of_string_ids() -> None:
    """List string_set exercises line 447: each element processed recursively."""
    rule = _rule(
        condition=OfExpression(quantifier="all", string_set=["$a", "$a"]),
    )
    result = RuleTransformer(rule).rename_strings({"$a": "$b"}).build()
    assert isinstance(result.condition, OfExpression)
    assert result.condition.string_set == ["$b", "$b"]


def test_rename_string_set_tuple_of_string_ids() -> None:
    """Tuple string_set exercises line 448-449 in _rename_string_set_value."""
    rule = _rule(
        condition=OfExpression(quantifier="all", string_set=("$a", "$a")),
    )
    result = RuleTransformer(rule).rename_strings({"$a": "$b"}).build()
    assert isinstance(result.condition, OfExpression)
    assert result.condition.string_set == ("$b", "$b")


def test_rename_string_set_set_of_string_ids() -> None:
    """Set string_set exercises lines 450-451 in _rename_string_set_value."""
    rule = _rule(
        condition=OfExpression(quantifier="all", string_set={"$a"}),
    )
    result = RuleTransformer(rule).rename_strings({"$a": "$b"}).build()
    assert isinstance(result.condition, OfExpression)
    assert result.condition.string_set == {"$b"}


def test_rename_string_set_frozenset_of_string_ids() -> None:
    """Frozenset string_set exercises lines 452-453 in _rename_string_set_value."""
    rule = _rule(
        condition=OfExpression(quantifier="all", string_set=frozenset(["$a"])),
    )
    result = RuleTransformer(rule).rename_strings({"$a": "$b"}).build()
    assert isinstance(result.condition, OfExpression)
    assert result.condition.string_set == frozenset(["$b"])


# ---------------------------------------------------------------------------
# _rename_string_pattern: wildcard prefix IS renamed (480->485)
# ---------------------------------------------------------------------------


def test_rename_string_pattern_renames_wildcard_prefix() -> None:
    """StringWildcard whose prefix maps to a new name must have the full pattern updated.

    The pattern "$foo*" splits into prefix "$foo" (which IS in the mapping)
    and suffix "*".  Lines 480-484 reassemble the renamed prefix with the
    wildcard suffix, producing "$bar*".
    """
    rule = _rule(
        strings=[PlainString(identifier="$foo", value="x", modifiers=[])],
        condition=StringWildcard(pattern="$foo*"),
    )
    result = RuleTransformer(rule).rename_strings({"$foo": "$bar"}).build()
    assert isinstance(result.condition, StringWildcard)
    assert result.condition.pattern == "$bar*"


# ---------------------------------------------------------------------------
# transform_rule: rule found by name, transformer applied (565->575)
# ---------------------------------------------------------------------------


def test_transform_rule_finds_and_applies_transformation() -> None:
    """transform_rule must locate the named rule, apply the callback, and break.

    Lines 565-574 are exercised: the loop finds "target", transforms it via
    the provided callback (which adds a tag), validates, replaces the entry,
    and breaks.  The resulting file must have the tag on the correct rule.
    """
    rule = _rule(name="target")
    yf = YaraFile(rules=[rule])
    result = (
        YaraFileTransformer(yf)
        .transform_rule("target", lambda r: RuleTransformer(r).add_tag("applied").build())
        .build()
    )
    assert len(result.rules) == 1
    assert any(t.name == "applied" for t in result.rules[0].tags)


def test_transform_rule_ignores_unmatched_rule_names() -> None:
    """transform_rule must leave all rules untouched when the name is not found.

    The loop at line 565 iterates over all rules but the break at 574 is never
    reached; the file is returned unchanged.
    """
    rule = _rule(name="different")
    yf = YaraFile(rules=[rule])
    result = (
        YaraFileTransformer(yf)
        .transform_rule("nonexistent", lambda r: RuleTransformer(r).add_tag("x").build())
        .build()
    )
    assert len(result.rules) == 1
    assert result.rules[0].name == "different"
    assert result.rules[0].tags == []


# ---------------------------------------------------------------------------
# create_variant_rule: private=True makes the rule private (728->731)
# ---------------------------------------------------------------------------


def test_create_variant_rule_with_private_flag_true_adds_private_modifier() -> None:
    """create_variant_rule with private=True must add the 'private' modifier.

    Line 728 evaluates `_require_variant_private(changes["private"])` as True,
    so line 729 (`transformer.make_private()`) executes.
    """
    base = _rule(name="base")
    variant = create_variant_rule(base, "base_priv", private=True)
    assert any(str(m) == "private" for m in variant.modifiers)


def test_create_variant_rule_with_private_flag_false_does_not_add_private() -> None:
    """create_variant_rule with private=False must not add 'private'.

    The condition `_require_variant_private(changes["private"])` evaluates to
    False so the make_private() call at line 729 is skipped.
    """
    base = _rule(name="base")
    variant = create_variant_rule(base, "base_pub", private=False)
    assert not any(str(m) == "private" for m in variant.modifiers)


# ---------------------------------------------------------------------------
# ForOfExpression: condition field present causes rename (368-372)
# ---------------------------------------------------------------------------


def test_rename_strings_in_for_of_expression_with_condition() -> None:
    """ForOfExpression.condition must be renamed when present.

    When ForOfExpression carries a non-None condition expression that contains
    a string reference, it must be renamed correctly via line 368-372.
    """
    for_of = ForOfExpression(
        quantifier="all",
        string_set="them",
        condition=StringIdentifier(name="$a"),
    )
    rule = _rule(
        strings=[PlainString(identifier="$a", value="x", modifiers=[])],
        condition=for_of,
    )
    result = RuleTransformer(rule).rename_strings({"$a": "$b"}).build()
    assert isinstance(result.condition, ForOfExpression)
    assert isinstance(result.condition.condition, StringIdentifier)
    assert result.condition.condition.name == "$b"


# ---------------------------------------------------------------------------
# SetExpression inside string_set (covers SetExpression path in string_set)
# ---------------------------------------------------------------------------


def test_rename_string_set_set_expression_renames_elements() -> None:
    """SetExpression in string_set must have all string-literal elements renamed.

    Lines 437-443 process a SetExpression by iterating its elements and
    applying _rename_string_set_value to each.  StringLiteral("$a") inside
    the set must become "$b".
    """
    rule = _rule(
        condition=OfExpression(
            quantifier="all",
            string_set=SetExpression(elements=[StringLiteral(value="$a")]),
        ),
    )
    result = RuleTransformer(rule).rename_strings({"$a": "$b"}).build()
    assert isinstance(result.condition, OfExpression)
    set_expr = result.condition.string_set
    assert isinstance(set_expr, SetExpression)
    assert isinstance(set_expr.elements[0], StringLiteral)
    assert set_expr.elements[0].value == "$b"
