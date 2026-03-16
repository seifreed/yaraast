"""AST-first reference collection for LSP document queries."""

from __future__ import annotations

from collections.abc import Iterable
from typing import TYPE_CHECKING

from lsprotocol.types import Location, TextEdit

from yaraast.ast.base import ASTNode
from yaraast.ast.expressions import (
    Identifier,
    StringCount,
    StringIdentifier,
    StringLength,
    StringOffset,
)
from yaraast.lsp.utils import location_to_range

if TYPE_CHECKING:
    from yaraast.lsp.document_context import DocumentContext


def collect_string_reference_locations_from_ast(
    ctx: DocumentContext,
    identifier: str,
    *,
    include_declaration: bool,
) -> list[Location] | None:
    ast = ctx.ast()
    if ast is None:
        return None
    normalized = identifier if identifier.startswith("$") else f"${identifier}"
    locations: list[Location] = []
    saw_supported_node = False
    definition = ctx.find_string_definition(normalized)
    if include_declaration and definition is not None:
        locations.append(definition)
    for rule in ctx._iter_rules(ast):
        condition = getattr(rule, "condition", None)
        if condition is None:
            continue
        for node in iter_ast_nodes(condition):
            node_name = string_reference_name(node)
            if node_name is None:
                continue
            saw_supported_node = True
            if node_name != normalized:
                continue
            node_location = getattr(node, "location", None)
            if node_location is None:
                return None
            locations.append(
                Location(uri=ctx.uri, range=location_to_range(node_location, ctx.text))
            )
    if not saw_supported_node and definition is not None:
        return locations
    if not saw_supported_node:
        return None
    return locations


def collect_rule_reference_locations_from_ast(
    ctx: DocumentContext, rule_name: str
) -> list[Location] | None:
    ast = ctx.ast()
    if ast is None:
        return None
    locations: list[Location] = []
    saw_supported_node = False
    definition = ctx.find_rule_definition(rule_name)
    if definition is not None:
        locations.append(definition)
    for rule in ctx._iter_rules(ast):
        condition = getattr(rule, "condition", None)
        if condition is None:
            continue
        for node in iter_ast_nodes(condition):
            if not isinstance(node, Identifier):
                continue
            saw_supported_node = True
            if node.name != rule_name:
                continue
            node_location = getattr(node, "location", None)
            if node_location is None:
                return None
            locations.append(
                Location(uri=ctx.uri, range=location_to_range(node_location, ctx.text))
            )
    if not saw_supported_node and definition is not None:
        return locations
    if not saw_supported_node:
        return None
    return locations


def build_string_rename_edits_from_ast(
    ctx: DocumentContext,
    identifier: str,
    new_name: str,
) -> list[TextEdit] | None:
    ast = ctx.ast()
    if ast is None:
        return None
    normalized = identifier if identifier.startswith("$") else f"${identifier}"
    replacement = new_name if new_name.startswith("$") else f"${new_name}"
    edits: list[TextEdit] = []

    definition = ctx.find_string_definition(normalized)
    if definition is not None:
        edits.append(TextEdit(range=definition.range, new_text=replacement))

    saw_supported_node = False
    for rule in ctx._iter_rules(ast):
        condition = getattr(rule, "condition", None)
        if condition is None:
            continue
        for node in iter_ast_nodes(condition):
            node_name = string_reference_name(node)
            if node_name is None:
                continue
            saw_supported_node = True
            if node_name != normalized:
                continue
            node_location = getattr(node, "location", None)
            if node_location is None:
                return None
            edits.append(
                TextEdit(
                    range=location_to_range(node_location, ctx.text),
                    new_text=string_reference_replacement(node, replacement),
                )
            )
    if not saw_supported_node and definition is not None:
        return edits
    if not saw_supported_node:
        return None
    return edits


def iter_ast_nodes(node: ASTNode) -> Iterable[ASTNode]:
    yield node
    for child in node.children():
        yield from iter_ast_nodes(child)


def string_reference_name(node: ASTNode) -> str | None:
    if isinstance(node, StringIdentifier):
        return node.name
    if isinstance(node, StringCount):
        return f"${node.string_id}"
    if isinstance(node, StringOffset):
        return f"${node.string_id}"
    if isinstance(node, StringLength):
        return f"${node.string_id}"
    return None


def string_reference_replacement(node: ASTNode, replacement: str) -> str:
    if isinstance(node, StringIdentifier):
        return replacement
    suffix = replacement[1:] if replacement.startswith("$") else replacement
    if isinstance(node, StringCount):
        return f"#{suffix}"
    if isinstance(node, StringOffset):
        return f"@{suffix}"
    if isinstance(node, StringLength):
        return f"!{suffix}"
    return replacement
