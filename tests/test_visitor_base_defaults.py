"""Coverage for the base ``ASTVisitor`` default dispatch behavior.

Every ``visit_*`` method on the base visitor forwards to ``_default_visit``;
subclasses override only what they need. These tests exercise the full set of
default methods plus the ``visit`` entry point's dispatch and validation.
"""

from __future__ import annotations

import pytest

from yaraast.ast.expressions import Identifier
from yaraast.visitor.visitor import ASTVisitor

_VISIT_METHODS = sorted(name for name in dir(ASTVisitor) if name.startswith("visit_"))


class _Collector(ASTVisitor[str]):
    def _default_visit(self, node: object) -> str:
        return "default"


@pytest.mark.parametrize("method_name", _VISIT_METHODS)
def test_default_visit_method_forwards_to_default(method_name: str) -> None:
    collector = _Collector()
    assert getattr(collector, method_name)(object()) == "default"


def test_base_default_visit_raises_not_implemented() -> None:
    with pytest.raises(NotImplementedError, match="does not implement visit"):
        ASTVisitor().visit_rule(object())


def test_visit_rejects_non_astnode() -> None:
    with pytest.raises(TypeError, match="must be an ASTNode"):
        _Collector().visit(object())


def test_visit_dispatches_through_accept() -> None:
    class _IdentityVisitor(ASTVisitor[str]):
        def visit_identifier(self, node: Identifier) -> str:
            return f"id:{node.name}"

    assert _IdentityVisitor().visit(Identifier(name="foo")) == "id:foo"
