"""AST rewrite helpers for LSP authoring actions."""

from __future__ import annotations

from typing import Any

from yaraast.ast.conditions import AtExpression, ForOfExpression, InExpression, OfExpression
from yaraast.ast.expressions import (
    Identifier,
    SetExpression,
    StringCount,
    StringIdentifier,
    StringLength,
    StringLiteral,
    StringOffset,
)
from yaraast.visitor.transformer_impl import ASTTransformer


class StringReferenceRewriter(ASTTransformer):
    """Rewrite all references to a duplicated string identifier."""

    def __init__(self, replacements: dict[str, str]) -> None:
        super().__init__()
        self.replacements = replacements

    def _replace_id(self, string_id: str) -> str:
        replacement = self.replacements.get(string_id)
        if replacement is not None:
            return replacement
        if string_id.startswith("$"):
            replacement = self.replacements.get(string_id.removeprefix("$"))
            return replacement if replacement is not None else string_id
        replacement = self.replacements.get(f"${string_id}")
        if replacement is None:
            return string_id
        return replacement.removeprefix("$")

    def visit_string_identifier(self, node: StringIdentifier) -> Any:
        node = self._transform_node(node)
        node.name = self._replace_id(node.name)
        return node

    def visit_string_count(self, node: StringCount) -> Any:
        node = self._transform_node(node)
        node.string_id = self._replace_id(node.string_id)
        return node

    def visit_string_offset(self, node: StringOffset) -> Any:
        node = self._transform_node(node)
        node.string_id = self._replace_id(node.string_id)
        return node

    def visit_string_length(self, node: StringLength) -> Any:
        node = self._transform_node(node)
        node.string_id = self._replace_id(node.string_id)
        return node

    def visit_at_expression(self, node: AtExpression) -> Any:
        node = self._transform_node(node)
        if isinstance(node.string_id, str):
            node.string_id = self._replace_id(node.string_id)
        return node

    def visit_in_expression(self, node: InExpression) -> Any:
        node = self._transform_node(node)
        if isinstance(node.subject, str):
            node.subject = self._replace_id(node.subject)
        return node


class OfThemTransformer(ASTTransformer):
    """Expand/compress `of them` expressions against current string ids."""

    def __init__(self, string_ids: list[str], mode: str) -> None:
        super().__init__()
        self.string_ids = string_ids
        self.mode = mode

    def _expanded_set(self) -> SetExpression:
        return SetExpression(
            elements=[StringIdentifier(name=string_id) for string_id in self.string_ids]
        )

    def _can_compress(self, string_set: object) -> bool:
        if not isinstance(string_set, SetExpression):
            return False
        values = []
        for element in string_set.elements:
            value: str
            if isinstance(element, StringLiteral):
                value = element.value
            elif isinstance(element, StringIdentifier) or (
                isinstance(element, Identifier) and element.name.startswith("$")
            ):
                value = element.name
            else:
                return False
            values.append(value)
        return sorted(values) == sorted(self.string_ids)

    def visit_of_expression(self, node: OfExpression) -> Any:
        node = self._transform_node(node)
        if self.mode == "expand":
            if isinstance(node.string_set, Identifier) and node.string_set.name == "them":
                node.string_set = self._expanded_set()
        elif self.mode == "compress" and self._can_compress(node.string_set):
            node.string_set = Identifier(name="them")
        return node

    def visit_for_of_expression(self, node: ForOfExpression) -> Any:
        node = self._transform_node(node)
        if self.mode == "expand":
            if isinstance(node.string_set, Identifier) and node.string_set.name == "them":
                node.string_set = self._expanded_set()
        elif self.mode == "compress" and self._can_compress(node.string_set):
            node.string_set = Identifier(name="them")
        return node
