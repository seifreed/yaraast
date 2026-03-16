"""Additional tests for module-related AST nodes (no mocks)."""

from __future__ import annotations

from yaraast.ast.expressions import Identifier, IntegerLiteral
from yaraast.ast.modules import DictionaryAccess, ModuleReference


class _Visitor:
    def visit_module_reference(self, node: ModuleReference) -> str:
        return f"module:{node.module}"

    def visit_dictionary_access(self, node: DictionaryAccess) -> str:
        key = node.key if isinstance(node.key, str) else "expr"
        return f"dict:{key}"


def test_module_reference_accept() -> None:
    visitor = _Visitor()
    ref = ModuleReference(module="pe")
    assert ref.accept(visitor) == "module:pe"


def test_dictionary_access_accept() -> None:
    visitor = _Visitor()
    access_str = DictionaryAccess(object=Identifier(name="pe"), key="CompanyName")
    access_expr = DictionaryAccess(object=Identifier(name="pe"), key=IntegerLiteral(value=1))

    assert access_str.accept(visitor) == "dict:CompanyName"
    assert access_expr.accept(visitor) == "dict:expr"
