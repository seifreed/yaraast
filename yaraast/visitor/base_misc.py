"""Comment/extern/pragma traversal mixin for BaseVisitor."""

from __future__ import annotations

from typing import TypeVar

from yaraast.ast.comments import Comment, CommentGroup
from yaraast.ast.extern import ExternImport, ExternNamespace, ExternRule, ExternRuleReference
from yaraast.ast.pragmas import InRulePragma, Pragma, PragmaBlock
from yaraast.visitor.base_helpers import VisitorHelperProtocol

T = TypeVar("T")


class BaseVisitorMiscMixin:
    """Misc traversal methods."""

    def visit_comment(self: VisitorHelperProtocol[T], node: Comment) -> T:
        return self._noop()

    def visit_comment_group(self: VisitorHelperProtocol[T], node: CommentGroup) -> T:
        return self._noop()

    def visit_extern_import(self: VisitorHelperProtocol[T], node: ExternImport) -> T:
        return self._noop()

    def visit_extern_namespace(self: VisitorHelperProtocol[T], node: ExternNamespace) -> T:
        return self._noop()

    def visit_extern_rule(self: VisitorHelperProtocol[T], node: ExternRule) -> T:
        return self._noop()

    def visit_extern_rule_reference(self: VisitorHelperProtocol[T], node: ExternRuleReference) -> T:
        return self._noop()

    def visit_pragma(self: VisitorHelperProtocol[T], node: Pragma) -> T:
        return self._noop()

    def visit_in_rule_pragma(self: VisitorHelperProtocol[T], node: InRulePragma) -> T:
        self._visit_if(node.pragma)
        return self._noop()

    def visit_pragma_block(self: VisitorHelperProtocol[T], node: PragmaBlock) -> T:
        self._visit_all(node.pragmas)
        return self._noop()
