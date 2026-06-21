# Copyright (c) 2026 Marc Rivero López
# Licensed under GPLv3. See LICENSE file for details.
# This test suite validates real code behavior without mocks or stubs.
"""Coverage-loop tests for yaraast.lsp.authoring_rewriters.

Missing-line analysis (88.14% before this file):

  36   -- _replace_id: `return string_id` when the key has no dollar prefix and
         looking up `$key` also finds no match.
  37   -- _replace_id: `return replacement.removeprefix("$")` when the key has no
         dollar prefix but `$key` IS present in the replacements dict.
  67->69 -- visit_at_expression: branch entered when `node.string_id` is a `str`
            (AtExpression.string_id is typed `str | Expression`).
  73->75 -- visit_in_expression: branch entered when `node.subject` is a `str`
            (InExpression.subject is typed `str | Expression`).
  98   -- _can_compress: the `isinstance(element, StringLiteral)` branch which
         extracts `element.value` as the representative string.
  104  -- _can_compress: `return False` when a SetExpression element is not a
         StringLiteral, StringIdentifier, or dollar-prefixed Identifier.
  120-121 -- visit_for_of_expression expand path: string_set is `Identifier(name="them")`.
  122->124 -- visit_for_of_expression compress path: `_can_compress` returns True.

All paths exercise real production constructors with controlled inputs; no mocks
are used anywhere in this file.
"""

from __future__ import annotations

import pytest

from yaraast.ast.conditions import AtExpression, ForOfExpression, InExpression, OfExpression
from yaraast.ast.expressions import (
    Identifier,
    IntegerLiteral,
    RangeExpression,
    SetExpression,
    StringIdentifier,
    StringLiteral,
)
from yaraast.lsp.authoring_rewriters import OfThemTransformer, StringReferenceRewriter

# ---------------------------------------------------------------------------
# StringReferenceRewriter._replace_id — lines 36 and 37
#
# _replace_id has three branches after the initial direct-key lookup fails:
#
#   Branch A (lines 31-33): key starts with "$" — strip it and look up bare key.
#   Branch B (lines 34-36): key has no "$" — prepend "$" and look up; if not
#       found, return the original key (line 36).
#   Branch C (line 37): same as B but the "$"-prefixed key IS found; strip the
#       "$" from the replacement value and return it.
#
# Existing tests only cover the direct-key path and branch A.  Branch B (line
# 36) and branch C (line 37) are covered here.
# ---------------------------------------------------------------------------


def test_replace_id_returns_original_when_bare_key_has_no_mapping() -> None:
    """_replace_id returns the unchanged string_id (line 36) when the key has
    no dollar prefix and neither the bare key nor the dollar-prefixed key
    appears in the replacements dictionary.

    Arrange: replacements maps only "$a" -> "$b".
    Act: call _replace_id with "xyz" (no dollar, not in map, "$xyz" not in map).
    Assert: the original key "xyz" is returned unmodified.
    """
    # Arrange
    rewriter = StringReferenceRewriter({"$a": "$b"})

    # Act
    result = rewriter._replace_id("xyz")

    # Assert
    assert result == "xyz"


def test_replace_id_strips_dollar_from_replacement_when_bare_key_matches_dollar_prefixed() -> None:
    """_replace_id returns `replacement.removeprefix("$")` (line 37) when the
    key has no dollar prefix but looking up "$key" succeeds.

    Arrange: replacements maps "$xyz" -> "$new".
    Act: call _replace_id with "xyz".
    Assert: the bare replacement "new" (with "$" stripped) is returned.
    """
    # Arrange
    rewriter = StringReferenceRewriter({"$xyz": "$new"})

    # Act
    result = rewriter._replace_id("xyz")

    # Assert: the "$" is removed from the replacement so condition text stays valid
    assert result == "new"


@pytest.mark.parametrize(
    ("key", "replacements", "expected"),
    [
        # Branch B: no match anywhere — return original
        ("abc", {"$x": "$y"}, "abc"),
        ("", {"$x": "$y"}, ""),
        # Branch C: "$key" is in map
        ("a", {"$a": "$b"}, "b"),
        ("ref", {"$ref": "$canonical"}, "canonical"),
    ],
    ids=[
        "no_match_simple",
        "no_match_empty_string",
        "dollar_prefixed_match_single_char",
        "dollar_prefixed_match_word",
    ],
)
def test_replace_id_non_dollar_key_parametrized(
    key: str, replacements: dict[str, str], expected: str
) -> None:
    """Parametrized coverage of _replace_id lines 34-37 for non-dollar keys."""
    rewriter = StringReferenceRewriter(replacements)
    assert rewriter._replace_id(key) == expected


# ---------------------------------------------------------------------------
# StringReferenceRewriter.visit_at_expression — lines 67->69
#
# AtExpression.string_id is typed `str | Expression`.  The rewriter only
# rewrites when it is a `str` (line 67).  Providing a str value sends
# execution through the branch; providing an Identifier bypasses it.
# ---------------------------------------------------------------------------


def test_visit_at_expression_rewrites_str_string_id() -> None:
    """visit_at_expression replaces the string_id when it is a str (line 67->69).

    Arrange: AtExpression with string_id="$a" and a real IntegerLiteral offset.
    Act: apply the rewriter that maps "$a" -> "$b".
    Assert: node.string_id is updated to "$b".
    """
    # Arrange
    rewriter = StringReferenceRewriter({"$a": "$b"})
    offset = IntegerLiteral(value=0)
    node = AtExpression(string_id="$a", offset=offset)

    # Act
    result = rewriter.visit_at_expression(node)

    # Assert: str string_id was rewritten
    assert result.string_id == "$b"
    # Offset is unchanged
    assert isinstance(result.offset, IntegerLiteral)
    assert result.offset.value == 0


def test_visit_at_expression_leaves_expression_string_id_as_identifier_type() -> None:
    """visit_at_expression skips the str-specific _replace_id call when
    string_id is not a str.  The ASTTransformer still descends into the
    Identifier child node via visit_identifier, but that is a separate visit
    path — the branch at line 67 is not taken for non-str values.

    Arrange: AtExpression with string_id as an Identifier whose name is not in
             the replacements dict, so the child-visit produces no change either.
    Act: apply the rewriter.
    Assert: the Identifier remains an Identifier (not a str), confirming that
            the str-branch (lines 67-68) was bypassed.
    """
    # Arrange: "$z" is not in the replacements map, so visit_identifier is a no-op
    rewriter = StringReferenceRewriter({"$a": "$b"})
    offset = IntegerLiteral(value=0)
    id_node = Identifier(name="$z")
    node = AtExpression(string_id=id_node, offset=offset)

    # Act
    result = rewriter.visit_at_expression(node)

    # Assert: string_id is still an Identifier (not converted to a str)
    assert isinstance(result.string_id, Identifier)
    assert result.string_id.name == "$z"


# ---------------------------------------------------------------------------
# StringReferenceRewriter.visit_in_expression — lines 73->75
#
# InExpression.subject is `str | Expression`.  The rewriter only rewrites when
# subject is a `str`.  Both branches are validated.
# ---------------------------------------------------------------------------


def test_visit_in_expression_rewrites_str_subject() -> None:
    """visit_in_expression replaces the subject when it is a str (line 73->75).

    Arrange: InExpression with subject="$a" and a real RangeExpression range.
    Act: apply the rewriter that maps "$a" -> "$b".
    Assert: node.subject is updated to "$b".
    """
    # Arrange
    rewriter = StringReferenceRewriter({"$a": "$b"})
    range_expr = RangeExpression(low=IntegerLiteral(value=0), high=IntegerLiteral(value=100))
    node = InExpression(subject="$a", range=range_expr)

    # Act
    result = rewriter.visit_in_expression(node)

    # Assert: str subject was rewritten
    assert result.subject == "$b"


def test_visit_in_expression_leaves_expression_subject_as_identifier_type() -> None:
    """visit_in_expression skips the str-specific _replace_id call when subject
    is not a str.  The ASTTransformer descends into child nodes via
    visit_identifier, but the branch at line 73 is not taken for non-str values.

    Arrange: InExpression with subject as an Identifier whose name is not in the
             replacements dict, so the child-visit is also a no-op.
    Act: apply the rewriter.
    Assert: subject remains an Identifier (not converted to a str), confirming
            the str-branch (lines 73-74) was bypassed.
    """
    # Arrange: "$z" is not in the replacements map
    rewriter = StringReferenceRewriter({"$a": "$b"})
    range_expr = RangeExpression(low=IntegerLiteral(value=0), high=IntegerLiteral(value=100))
    id_node = Identifier(name="$z")
    node = InExpression(subject=id_node, range=range_expr)

    # Act
    result = rewriter.visit_in_expression(node)

    # Assert: Identifier subject is still an Identifier, not a str
    assert isinstance(result.subject, Identifier)
    assert result.subject.name == "$z"


# ---------------------------------------------------------------------------
# OfThemTransformer._can_compress — lines 98 and 104
#
# _can_compress iterates each element of a SetExpression and extracts a
# representative string via one of three branches:
#
#   Line 97-98: element is a StringLiteral  -> value = element.value
#   Line 99-102: element is StringIdentifier or dollar-prefixed Identifier
#                -> value = element.name
#   Line 103-104: any other element type   -> return False immediately
#
# Existing tests cover only the StringIdentifier/Identifier path.
# Line 98 (StringLiteral) and line 104 (else return False) are covered below.
# ---------------------------------------------------------------------------


def test_can_compress_accepts_set_with_string_literals() -> None:
    """_can_compress returns True when every element is a StringLiteral whose
    value matches a string_id (line 98 path).

    Arrange: OfThemTransformer with string_ids ["$a", "$b"].
             SetExpression whose elements are StringLiteral("$a"), StringLiteral("$b").
    Act: call _can_compress.
    Assert: True — the values match the string_ids (order-independent).
    """
    # Arrange
    transformer = OfThemTransformer(["$a", "$b"], "compress")
    string_set = SetExpression(elements=[StringLiteral(value="$a"), StringLiteral(value="$b")])

    # Act
    result = transformer._can_compress(string_set)

    # Assert
    assert result is True


def test_can_compress_returns_false_for_unsupported_element_type() -> None:
    """_can_compress returns False immediately when an element is not a
    StringLiteral, StringIdentifier, or dollar-prefixed Identifier (line 104).

    Arrange: OfThemTransformer with string_ids ["$a"].
             SetExpression containing an IntegerLiteral (invalid element type).
    Act: call _can_compress.
    Assert: False — the unsupported element triggers the early return.
    """
    # Arrange
    transformer = OfThemTransformer(["$a"], "compress")
    string_set = SetExpression(elements=[IntegerLiteral(value=42)])

    # Act
    result = transformer._can_compress(string_set)

    # Assert
    assert result is False


def test_can_compress_returns_false_when_any_element_is_unsupported() -> None:
    """_can_compress returns False even when only one element is unsupported,
    confirming the early return at line 104 fires on the first bad element."""
    # Arrange: one valid StringIdentifier followed by one unsupported IntegerLiteral
    transformer = OfThemTransformer(["$a", "$b"], "compress")
    string_set = SetExpression(elements=[StringIdentifier(name="$a"), IntegerLiteral(value=99)])

    # Act
    result = transformer._can_compress(string_set)

    # Assert
    assert result is False


def test_can_compress_with_mixed_literal_and_identifier_elements() -> None:
    """_can_compress handles a mix of StringLiteral and StringIdentifier elements
    and returns True when the combined values equal the string_ids.

    This confirms that both the line-98 branch and the line-99 branch cooperate
    correctly in a single set.
    """
    # Arrange: string_ids = ["$a", "$b"]
    #          elements = [StringLiteral("$a"), StringIdentifier("$b")]
    transformer = OfThemTransformer(["$a", "$b"], "compress")
    string_set = SetExpression(elements=[StringLiteral(value="$a"), StringIdentifier(name="$b")])

    # Act
    result = transformer._can_compress(string_set)

    # Assert
    assert result is True


# ---------------------------------------------------------------------------
# OfThemTransformer.visit_for_of_expression — lines 120-121 and 122->124
#
# visit_for_of_expression mirrors visit_of_expression but operates on
# ForOfExpression nodes.  The expand branch (120-121) replaces an Identifier
# named "them" with a SetExpression.  The compress branch (122->124) replaces
# a matching SetExpression with Identifier("them").
#
# Existing tests in test_lsp_authoring_phase5.py cover the compress path only
# with Identifier elements; these tests add explicit expand coverage and confirm
# both branches work independently on ForOfExpression.
# ---------------------------------------------------------------------------


def test_visit_for_of_expression_expands_them_identifier_to_set() -> None:
    """visit_for_of_expression replaces string_set=Identifier("them") with the
    expanded SetExpression when mode is "expand" (lines 120-121).

    Arrange: ForOfExpression with string_set=Identifier("them"), mode="expand".
    Act: call visit_for_of_expression.
    Assert: string_set is now a SetExpression containing the transformer's
            string_ids as StringIdentifier elements.
    """
    # Arrange
    transformer = OfThemTransformer(["$a", "$b"], "expand")
    node = ForOfExpression(quantifier="any", string_set=Identifier(name="them"))

    # Act
    result = transformer.visit_for_of_expression(node)

    # Assert: "them" was expanded
    assert isinstance(result.string_set, SetExpression)
    names = [e.name for e in result.string_set.elements if isinstance(e, StringIdentifier)]
    assert names == ["$a", "$b"]


def test_visit_for_of_expression_compresses_matching_set_to_them() -> None:
    """visit_for_of_expression replaces a matching SetExpression with
    Identifier("them") when mode is "compress" and _can_compress returns True
    (line 122->124).

    Arrange: ForOfExpression with a SetExpression whose elements exactly match
             the transformer's string_ids, mode="compress".
    Act: call visit_for_of_expression.
    Assert: string_set is replaced with Identifier(name="them").
    """
    # Arrange
    transformer = OfThemTransformer(["$a", "$b"], "compress")
    string_set = SetExpression(elements=[StringIdentifier(name="$a"), StringIdentifier(name="$b")])
    node = ForOfExpression(quantifier="all", string_set=string_set)

    # Act
    result = transformer.visit_for_of_expression(node)

    # Assert
    assert isinstance(result.string_set, Identifier)
    assert result.string_set.name == "them"


def test_visit_for_of_expression_leaves_non_them_identifier_in_expand_mode() -> None:
    """visit_for_of_expression does NOT replace an Identifier whose name is not
    "them" in expand mode (the inner condition at line 120 is False).

    Arrange: ForOfExpression with string_set=Identifier("other"), mode="expand".
    Act: call visit_for_of_expression.
    Assert: string_set remains unchanged.
    """
    # Arrange
    transformer = OfThemTransformer(["$a", "$b"], "expand")
    node = ForOfExpression(quantifier="any", string_set=Identifier(name="other"))

    # Act
    result = transformer.visit_for_of_expression(node)

    # Assert: non-"them" identifier is left alone
    assert isinstance(result.string_set, Identifier)
    assert result.string_set.name == "other"


def test_visit_for_of_expression_leaves_non_matching_set_in_compress_mode() -> None:
    """visit_for_of_expression does NOT compress a SetExpression that does not
    match the transformer's string_ids (line 122 condition is False).

    Arrange: ForOfExpression with a SetExpression that contains a string_id not
             in the transformer's list, mode="compress".
    Act: call visit_for_of_expression.
    Assert: string_set is unchanged (remains a SetExpression).
    """
    # Arrange: transformer has ["$a", "$b"] but the set contains ["$a", "$c"]
    transformer = OfThemTransformer(["$a", "$b"], "compress")
    string_set = SetExpression(elements=[StringIdentifier(name="$a"), StringIdentifier(name="$c")])
    node = ForOfExpression(quantifier="any", string_set=string_set)

    # Act
    result = transformer.visit_for_of_expression(node)

    # Assert: mismatched set is not compressed
    assert isinstance(result.string_set, SetExpression)


def test_visit_for_of_expression_expand_mirrors_of_expression_expand_behavior() -> None:
    """visit_for_of_expression in expand mode produces the same string_set
    structure as visit_of_expression in expand mode for the same string_ids.

    This confirms the two visitor methods share the same semantics without
    branching asymmetry.
    """
    # Arrange
    string_ids = ["$x", "$y", "$z"]
    transformer = OfThemTransformer(string_ids, "expand")

    of_node = OfExpression(quantifier="any", string_set=Identifier(name="them"))
    for_of_node = ForOfExpression(quantifier="any", string_set=Identifier(name="them"))

    # Act
    of_result = transformer.visit_of_expression(of_node)
    for_of_result = transformer.visit_for_of_expression(for_of_node)

    # Assert: both produce a SetExpression with the same element names
    assert isinstance(of_result.string_set, SetExpression)
    assert isinstance(for_of_result.string_set, SetExpression)
    of_names = [e.name for e in of_result.string_set.elements if isinstance(e, StringIdentifier)]
    for_of_names = [
        e.name for e in for_of_result.string_set.elements if isinstance(e, StringIdentifier)
    ]
    assert of_names == for_of_names == string_ids
