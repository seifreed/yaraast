"""Regression tests closing the remaining coverage gaps in yaraast.visitor.defaults.

Two categories of uncovered lines targeted:

  1. Line 89  -- DefaultASTVisitor._default_visit returns self._default.
     The individual visit_* overrides in DefaultASTVisitor each return
     self._default directly, so _default_visit is only reached when called
     explicitly or when a subclass inherits the ASTVisitor base dispatch and
     that dispatch lands on DefaultASTVisitor._default_visit.

  2. Lines 263-302 -- the fourteen YARA-X visitor methods
     (visit_with_statement ... visit_spread_operator).  The pre-existing test
     suite exercises only the classic-YARA visit_* methods; the YARA-X group
     was never invoked through a DefaultASTVisitor instance.

All tests use real AST node instances from yaraast.yarax.ast_nodes and
yaraast.ast.expressions.  No mocks, stubs, or artificial scaffolding.
"""

# Copyright (c) 2026 Marc Rivero López
# Licensed under GPLv3. See LICENSE file for details.
# This test suite validates real code behavior without mocks or stubs.

from __future__ import annotations

import pytest

from yaraast.ast.expressions import IntegerLiteral
from yaraast.visitor.defaults import DefaultASTVisitor
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
# Shared fixtures
# ---------------------------------------------------------------------------

_SENTINEL = object()


def _visitor() -> DefaultASTVisitor[object]:
    """Return a DefaultASTVisitor whose default value is _SENTINEL."""
    return DefaultASTVisitor(_SENTINEL)


def _int_literal() -> IntegerLiteral:
    """Return a minimal IntegerLiteral for use as a child node."""
    return IntegerLiteral(value=42)


# ---------------------------------------------------------------------------
# Line 89: DefaultASTVisitor._default_visit
# ---------------------------------------------------------------------------


class TestDefaultVisitMethod:
    """DefaultASTVisitor._default_visit must return the configured default value."""

    def test_default_visit_returns_configured_default(self) -> None:
        """Calling _default_visit directly must return the value supplied at init."""
        # Arrange
        sentinel = object()
        visitor = DefaultASTVisitor(sentinel)
        node = _int_literal()

        # Act
        result = visitor._default_visit(node)

        # Assert: the return value is the exact object passed to __init__
        assert result is sentinel

    def test_default_visit_returns_none_when_none_is_the_default(self) -> None:
        """None is a valid default; _default_visit must propagate it faithfully."""
        visitor: DefaultASTVisitor[None] = DefaultASTVisitor(None)
        assert visitor._default_visit(_int_literal()) is None

    def test_default_visit_returns_integer_default(self) -> None:
        """An integer default value must be returned unchanged."""
        visitor: DefaultASTVisitor[int] = DefaultASTVisitor(0)
        assert visitor._default_visit(_int_literal()) == 0

    def test_default_visit_accepts_any_astnode_subclass(self) -> None:
        """_default_visit must accept any ASTNode without inspecting its type."""
        visitor = _visitor()
        # TupleExpression is a real YARA-X AST node; it must pass through.
        node = TupleExpression(elements=[_int_literal()])
        assert visitor._default_visit(node) is _SENTINEL


# ---------------------------------------------------------------------------
# Lines 263-302: YARA-X visitor methods on DefaultASTVisitor
#
# Each test arranges the minimal valid AST node, passes it to the matching
# visit_* method on a DefaultASTVisitor instance, and asserts that the method
# returns the configured default value.  No method should raise or mutate state.
# ---------------------------------------------------------------------------


class TestYaraXVisitorMethods:
    """DefaultASTVisitor must return its default for every YARA-X visit method."""

    # -- visit_with_statement (line 263) -------------------------------------

    def test_visit_with_statement_returns_default(self) -> None:
        """visit_with_statement must return the configured default."""
        visitor = _visitor()
        decl = WithDeclaration(identifier="$a", value=_int_literal())
        node = WithStatement(declarations=[decl], body=_int_literal())

        result = visitor.visit_with_statement(node)

        assert result is _SENTINEL

    # -- visit_with_declaration (line 266) -----------------------------------

    def test_visit_with_declaration_returns_default(self) -> None:
        """visit_with_declaration must return the configured default."""
        visitor = _visitor()
        node = WithDeclaration(identifier="$b", value=_int_literal())

        result = visitor.visit_with_declaration(node)

        assert result is _SENTINEL

    # -- visit_array_comprehension (line 269) --------------------------------

    def test_visit_array_comprehension_returns_default(self) -> None:
        """visit_array_comprehension must return the configured default."""
        visitor = _visitor()
        node = ArrayComprehension(variable="x", iterable=_int_literal())

        result = visitor.visit_array_comprehension(node)

        assert result is _SENTINEL

    # -- visit_dict_comprehension (line 272) ---------------------------------

    def test_visit_dict_comprehension_returns_default(self) -> None:
        """visit_dict_comprehension must return the configured default."""
        visitor = _visitor()
        node = DictComprehension(key_variable="k", iterable=_int_literal())

        result = visitor.visit_dict_comprehension(node)

        assert result is _SENTINEL

    # -- visit_tuple_expression (line 275) -----------------------------------

    def test_visit_tuple_expression_returns_default(self) -> None:
        """visit_tuple_expression must return the configured default."""
        visitor = _visitor()
        node = TupleExpression(elements=[_int_literal()])

        result = visitor.visit_tuple_expression(node)

        assert result is _SENTINEL

    # -- visit_tuple_indexing (line 278) -------------------------------------

    def test_visit_tuple_indexing_returns_default(self) -> None:
        """visit_tuple_indexing must return the configured default."""
        visitor = _visitor()
        tuple_node = TupleExpression(elements=[_int_literal()])
        node = TupleIndexing(tuple_expr=tuple_node, index=_int_literal())

        result = visitor.visit_tuple_indexing(node)

        assert result is _SENTINEL

    # -- visit_list_expression (line 281) ------------------------------------

    def test_visit_list_expression_returns_default(self) -> None:
        """visit_list_expression must return the configured default."""
        visitor = _visitor()
        node = ListExpression(elements=[_int_literal()])

        result = visitor.visit_list_expression(node)

        assert result is _SENTINEL

    # -- visit_dict_expression (line 284) ------------------------------------

    def test_visit_dict_expression_returns_default(self) -> None:
        """visit_dict_expression must return the configured default."""
        visitor = _visitor()
        item = DictItem(key=_int_literal(), value=_int_literal())
        node = DictExpression(items=[item])

        result = visitor.visit_dict_expression(node)

        assert result is _SENTINEL

    # -- visit_dict_item (line 287) ------------------------------------------

    def test_visit_dict_item_returns_default(self) -> None:
        """visit_dict_item must return the configured default."""
        visitor = _visitor()
        node = DictItem(key=_int_literal(), value=_int_literal())

        result = visitor.visit_dict_item(node)

        assert result is _SENTINEL

    # -- visit_slice_expression (line 290) -----------------------------------

    def test_visit_slice_expression_returns_default(self) -> None:
        """visit_slice_expression must return the configured default."""
        from yaraast.ast.expressions import Identifier

        visitor = _visitor()
        node = SliceExpression(target=Identifier(name="arr"))

        result = visitor.visit_slice_expression(node)

        assert result is _SENTINEL

    # -- visit_lambda_expression (line 293) ----------------------------------

    def test_visit_lambda_expression_returns_default(self) -> None:
        """visit_lambda_expression must return the configured default."""
        visitor = _visitor()
        node = LambdaExpression(parameters=["x"], body=_int_literal())

        result = visitor.visit_lambda_expression(node)

        assert result is _SENTINEL

    # -- visit_pattern_match (line 296) --------------------------------------

    def test_visit_pattern_match_returns_default(self) -> None:
        """visit_pattern_match must return the configured default."""
        visitor = _visitor()
        case = MatchCase(pattern=_int_literal(), result=_int_literal())
        node = PatternMatch(value=_int_literal(), cases=[case])

        result = visitor.visit_pattern_match(node)

        assert result is _SENTINEL

    # -- visit_match_case (line 299) -----------------------------------------

    def test_visit_match_case_returns_default(self) -> None:
        """visit_match_case must return the configured default."""
        visitor = _visitor()
        node = MatchCase(pattern=_int_literal(), result=_int_literal())

        result = visitor.visit_match_case(node)

        assert result is _SENTINEL

    # -- visit_spread_operator (line 302) ------------------------------------

    def test_visit_spread_operator_returns_default(self) -> None:
        """visit_spread_operator must return the configured default."""
        visitor = _visitor()
        node = SpreadOperator(expression=_int_literal())

        result = visitor.visit_spread_operator(node)

        assert result is _SENTINEL

    def test_visit_spread_operator_dict_variant_returns_default(self) -> None:
        """visit_spread_operator with is_dict=True must also return the default."""
        visitor = _visitor()
        node = SpreadOperator(expression=_int_literal(), is_dict=True)

        result = visitor.visit_spread_operator(node)

        assert result is _SENTINEL


# ---------------------------------------------------------------------------
# Parametric cross-check: all YARA-X methods return the SAME default object
# ---------------------------------------------------------------------------


@pytest.mark.parametrize(
    "method_name,node_factory",
    [
        (
            "visit_with_statement",
            lambda: WithStatement(
                declarations=[WithDeclaration(identifier="$v", value=IntegerLiteral(value=0))],
                body=IntegerLiteral(value=0),
            ),
        ),
        (
            "visit_with_declaration",
            lambda: WithDeclaration(identifier="$v", value=IntegerLiteral(value=0)),
        ),
        (
            "visit_array_comprehension",
            lambda: ArrayComprehension(variable="x", iterable=IntegerLiteral(value=0)),
        ),
        (
            "visit_dict_comprehension",
            lambda: DictComprehension(key_variable="k", iterable=IntegerLiteral(value=0)),
        ),
        (
            "visit_tuple_expression",
            lambda: TupleExpression(elements=[IntegerLiteral(value=0)]),
        ),
        (
            "visit_tuple_indexing",
            lambda: TupleIndexing(
                tuple_expr=TupleExpression(elements=[IntegerLiteral(value=0)]),
                index=IntegerLiteral(value=0),
            ),
        ),
        (
            "visit_list_expression",
            lambda: ListExpression(elements=[IntegerLiteral(value=0)]),
        ),
        (
            "visit_dict_expression",
            lambda: DictExpression(
                items=[DictItem(key=IntegerLiteral(value=0), value=IntegerLiteral(value=0))]
            ),
        ),
        (
            "visit_dict_item",
            lambda: DictItem(key=IntegerLiteral(value=0), value=IntegerLiteral(value=0)),
        ),
        (
            "visit_slice_expression",
            lambda: SliceExpression(target=IntegerLiteral(value=0)),
        ),
        (
            "visit_lambda_expression",
            lambda: LambdaExpression(parameters=["p"], body=IntegerLiteral(value=0)),
        ),
        (
            "visit_pattern_match",
            lambda: PatternMatch(
                value=IntegerLiteral(value=0),
                cases=[MatchCase(pattern=IntegerLiteral(value=0), result=IntegerLiteral(value=0))],
            ),
        ),
        (
            "visit_match_case",
            lambda: MatchCase(pattern=IntegerLiteral(value=0), result=IntegerLiteral(value=0)),
        ),
        (
            "visit_spread_operator",
            lambda: SpreadOperator(expression=IntegerLiteral(value=0)),
        ),
    ],
)
def test_yarax_visit_method_returns_default_for_every_node_type(
    method_name: str,
    node_factory: object,
) -> None:
    """Every YARA-X visit method on DefaultASTVisitor must return the configured default.

    This parametric test independently exercises each of the fourteen YARA-X
    visitor methods, ensuring the return value is identity-equal to the default
    object supplied at construction time.
    """
    # Arrange
    sentinel = object()
    visitor: DefaultASTVisitor[object] = DefaultASTVisitor(sentinel)
    node = node_factory()  # type: ignore[operator]

    # Act
    result = getattr(visitor, method_name)(node)

    # Assert
    message = f"{method_name} returned {result!r} instead of the configured sentinel"
    assert result is sentinel, message
