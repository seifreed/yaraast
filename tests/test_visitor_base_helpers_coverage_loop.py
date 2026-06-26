"""Regression coverage for yaraast.visitor.base_helpers.

Targets the lines reported missing by coverage:
  - line 28  : BaseVisitorHelpersMixin._default_visit return value
  - lines 52-54 : _visit_value dict branch (isinstance + iteration)
  - line 55  : _visit_value list/tuple/set/frozenset branch exit

Protocol stub bodies (lines 15, 17, 19, 21) belong to
VisitorHelperProtocol which is a structural Protocol[T].  The `...`
bodies are never executed at runtime — Protocol methods are only used
for static type checking.  They are documented here as genuinely
unreachable, not missing tests.

Copyright (c) 2026 Marc Rivero López
Licensed under GPLv3. See LICENSE file for details.
This test suite validates real code behavior without mocks or stubs.
"""

from __future__ import annotations

import pytest

from yaraast.ast.expressions import Identifier, IntegerLiteral
from yaraast.visitor.base import BaseVisitor
from yaraast.visitor.base_helpers import BaseVisitorHelpersMixin

# ---------------------------------------------------------------------------
# Minimal concrete visitor that routes everything through _default_visit so
# we can call helper methods directly without triggering dispatch errors.
# ---------------------------------------------------------------------------


class _NullVisitor(BaseVisitor[None]):
    """Accept every node silently; record which identifiers are visited."""

    def __init__(self) -> None:
        self.visited_names: list[str] = []

    def visit_identifier(self, node: Identifier) -> None:
        self.visited_names.append(node.name)

    def visit_integer_literal(self, node: IntegerLiteral) -> None:
        self.visited_names.append(str(node.value))


# ---------------------------------------------------------------------------
# line 28 — BaseVisitorHelpersMixin._default_visit returns None
# ---------------------------------------------------------------------------


def test_default_visit_returns_none_for_any_node() -> None:
    """_default_visit on the mixin level casts None and returns it.

    BaseVisitor inherits BaseVisitorHelpersMixin._default_visit which
    overrides ASTVisitor's raising implementation and silently returns
    None.  Calling an unhandled visit method exercises line 28.
    """

    # Arrange: BaseVisitor already provides the default no-op dispatch.
    visitor = BaseVisitor[None]()
    node = IntegerLiteral(value=42)

    # Act: visit_integer_literal falls through to _default_visit (line 28)
    result = visitor.visit(node)

    # Assert: the mixin's _default_visit casts None and returns it
    assert result is None


def test_default_visit_called_directly_returns_none() -> None:
    """Direct invocation of _default_visit confirms the cast(T, None) path.

    The mixin can be reached via super() or direct attribute access.
    This exercises line 28 without relying on the dispatch mechanism.
    """
    visitor = _NullVisitor()
    node = Identifier(name="direct_test")

    # Act: bypass visit() dispatch and call the mixin method directly
    result = BaseVisitorHelpersMixin._default_visit(visitor, node)

    assert result is None


# ---------------------------------------------------------------------------
# lines 52-54 — _visit_value dict branch
# ---------------------------------------------------------------------------


def test_visit_value_recurses_into_dict_values() -> None:
    """_visit_value must iterate dict.values() and recurse for ASTNode values.

    Passing a plain dict to _visit_value exercises the ``elif isinstance(value,
    dict)`` guard on line 52 and the ``for item in value.values()`` loop on
    line 53-54.
    """
    # Arrange
    visitor = _NullVisitor()
    node_a = Identifier(name="alpha")
    node_b = Identifier(name="beta")
    # A dict whose values are ASTNodes — typical of structured field storage
    data: dict[str, object] = {"first": node_a, "second": node_b}

    # Act: call the mixin helper directly with a dict
    BaseVisitorHelpersMixin._visit_value(visitor, data)

    # Assert: both ASTNode values inside the dict were visited
    assert "alpha" in visitor.visited_names
    assert "beta" in visitor.visited_names


def test_visit_value_dict_with_nested_non_node_scalars_is_skipped() -> None:
    """Non-ASTNode scalars inside a dict must be silently ignored.

    The recursion bottoms out when the dict value is not an ASTNode, dict,
    or sequence.  This exercises the full dict iteration path with mixed values
    to confirm no TypeError is raised.
    """
    # Arrange
    visitor = _NullVisitor()
    mixed: dict[str, object] = {"name": "just_a_string", "count": 99, "flag": True}

    # Act: must complete without error and visit nothing
    BaseVisitorHelpersMixin._visit_value(visitor, mixed)

    # Assert: no identifiers were collected (scalars are silently skipped)
    assert visitor.visited_names == []


def test_visit_value_dict_with_nested_dict_recurses_deeply() -> None:
    """A dict nested inside another dict must be traversed recursively.

    This confirms the recursive call on line 54 reaches nested dicts.
    """
    # Arrange
    visitor = _NullVisitor()
    inner_node = Identifier(name="deep")
    nested: dict[str, object] = {"outer": {"inner": inner_node}}

    # Act
    BaseVisitorHelpersMixin._visit_value(visitor, nested)

    # Assert
    assert visitor.visited_names == ["deep"]


# ---------------------------------------------------------------------------
# line 55 — _visit_value list/tuple/set/frozenset branch exit
# ---------------------------------------------------------------------------


def test_visit_value_recurses_into_list() -> None:
    """A list of ASTNodes is traversed by the list|tuple|set|frozenset branch.

    Line 55 is the ``elif isinstance(value, list | tuple | set | frozenset)``
    guard.  Passing a list exercises that branch and its exit.
    """
    # Arrange
    visitor = _NullVisitor()
    nodes = [Identifier(name="x"), Identifier(name="y")]

    # Act
    BaseVisitorHelpersMixin._visit_value(visitor, nodes)

    # Assert
    assert visitor.visited_names == ["x", "y"]


def test_visit_value_recurses_into_tuple() -> None:
    """A tuple of ASTNodes is traversed by the sequence branch."""
    visitor = _NullVisitor()
    nodes = (Identifier(name="p"), IntegerLiteral(value=7))

    BaseVisitorHelpersMixin._visit_value(visitor, nodes)

    assert "p" in visitor.visited_names
    assert "7" in visitor.visited_names


def test_visit_value_set_branch_is_entered_with_scalar_members() -> None:
    """A set value enters the list|tuple|set|frozenset branch on line 55.

    ASTNode dataclasses are not hashable (Python's @dataclass with eq=True
    clears __hash__), so a set of scalars is the only realistic production
    value that exercises this branch with a set container.  The scalars are
    recursed into and silently skipped; what matters is that the branch is
    entered without error.
    """
    visitor = _NullVisitor()
    # A set of plain integers — still exercises the isinstance branch on line 55
    scalar_set: set[int] = {1, 2, 3}

    BaseVisitorHelpersMixin._visit_value(visitor, scalar_set)

    # Scalars produce no visits; branch is exercised with no side effects
    assert visitor.visited_names == []


def test_visit_value_frozenset_branch_is_entered_with_scalar_members() -> None:
    """A frozenset value enters the list|tuple|set|frozenset branch on line 55.

    Same reasoning as the set case: ASTNode subclasses are unhashable, so a
    frozenset of scalars is used to enter the branch and confirm it exits cleanly.
    """
    visitor = _NullVisitor()
    scalar_frozenset: frozenset[str] = frozenset({"a", "b"})

    BaseVisitorHelpersMixin._visit_value(visitor, scalar_frozenset)

    assert visitor.visited_names == []


def test_visit_value_list_with_non_node_scalars_is_skipped() -> None:
    """Non-ASTNode elements inside a list are silently ignored.

    The recursion bottoms out when an element is not an ASTNode, dict, or
    sequence.  Mixed lists must not raise.
    """
    visitor = _NullVisitor()
    mixed: list[object] = ["string", 42, None, True]

    BaseVisitorHelpersMixin._visit_value(visitor, mixed)

    assert visitor.visited_names == []


def test_visit_value_list_with_mixed_nodes_and_scalars() -> None:
    """ASTNodes inside a mixed list are visited; scalars are ignored."""
    visitor = _NullVisitor()
    node = Identifier(name="present")
    mixed: list[object] = ["skip_me", node, 99]

    BaseVisitorHelpersMixin._visit_value(visitor, mixed)

    assert visitor.visited_names == ["present"]


def test_visit_value_empty_list_does_not_visit_anything() -> None:
    """An empty list must produce no visits and no errors."""
    visitor = _NullVisitor()

    BaseVisitorHelpersMixin._visit_value(visitor, [])

    assert visitor.visited_names == []


def test_visit_value_empty_dict_does_not_visit_anything() -> None:
    """An empty dict must produce no visits and no errors."""
    visitor = _NullVisitor()

    BaseVisitorHelpersMixin._visit_value(visitor, {})

    assert visitor.visited_names == []


# ---------------------------------------------------------------------------
# Combined path: dict containing a list containing ASTNodes
# ---------------------------------------------------------------------------


def test_visit_value_dict_containing_list_of_nodes() -> None:
    """A dict whose value is a list of ASTNodes is fully traversed.

    This exercises both the dict branch (lines 52-54) and the list branch
    (line 55) in a single call, confirming the recursive structure is correct.
    """
    visitor = _NullVisitor()
    node_a = Identifier(name="from_list_in_dict_a")
    node_b = Identifier(name="from_list_in_dict_b")
    data: dict[str, object] = {"items": [node_a, node_b]}

    BaseVisitorHelpersMixin._visit_value(visitor, data)

    assert visitor.visited_names == ["from_list_in_dict_a", "from_list_in_dict_b"]


# ---------------------------------------------------------------------------
# Confirm Protocol stubs are not callable at runtime (structural-only)
# ---------------------------------------------------------------------------


def test_visitor_helper_protocol_is_structural_only() -> None:
    """VisitorHelperProtocol cannot be instantiated; it is a static typing aid.

    The stub method bodies (...) on lines 15, 17, 19, 21 are never executed
    at runtime because Protocol classes raise TypeError on direct instantiation.
    This test documents and verifies that boundary.

    The class is accessed through a plain ``type`` variable so mypy does not
    flag the call site as a static error (mypy correctly prevents calling a
    Protocol type in typed code; we exercise the runtime guard instead).
    """
    from yaraast.visitor.base_helpers import VisitorHelperProtocol

    # Route through a plain `type` binding so mypy treats the call as a
    # generic type instantiation rather than a Protocol-specific error.
    protocol_cls: type = VisitorHelperProtocol
    with pytest.raises(TypeError, match="Protocols cannot be instantiated"):
        protocol_cls()
