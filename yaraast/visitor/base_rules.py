"""Rule/meta traversal mixin for BaseVisitor."""

from __future__ import annotations

from collections.abc import Iterable
from typing import TypeVar

from yaraast.ast.base import ASTNode, YaraFile
from yaraast.ast.meta import Meta
from yaraast.ast.rules import Import, Include, Rule, Tag
from yaraast.visitor.base_helpers import VisitorHelperProtocol

T = TypeVar("T")


class BaseVisitorRulesMixin:
    """Rule/meta traversal methods."""

    def visit_yara_file(self: VisitorHelperProtocol[T], node: YaraFile) -> T:
        self._visit_all(node.imports)
        self._visit_all(node.includes)
        self._visit_all(node.rules)
        self._visit_all(node.extern_rules)
        self._visit_all(node.extern_imports)
        self._visit_all(node.pragmas)
        self._visit_all(node.namespaces)
        return self._noop()

    def visit_import(self: VisitorHelperProtocol[T], node: Import) -> T:
        return self._noop()

    def visit_include(self: VisitorHelperProtocol[T], node: Include) -> T:
        return self._noop()

    def visit_rule(self: VisitorHelperProtocol[T], node: Rule) -> T:
        self._visit_all(node.tags)
        meta_values: Iterable[object]
        if isinstance(node.meta, dict):
            meta_values = node.meta.values()
        elif isinstance(node.meta, list | tuple):
            meta_values = node.meta
        else:
            meta_values = ()
        for item in meta_values:
            if isinstance(item, ASTNode):
                self._visit_if(item)
        self._visit_all(node.strings)
        self._visit_if(node.condition)
        self._visit_all(node.pragmas)
        return self._noop()

    def visit_tag(self: VisitorHelperProtocol[T], node: Tag) -> T:
        return self._noop()

    def visit_meta(self: VisitorHelperProtocol[T], node: Meta) -> T:
        return self._noop()
