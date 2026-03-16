"""AST-driven resolution helpers for LSP document queries."""

from __future__ import annotations

from typing import TYPE_CHECKING

from yaraast.ast.conditions import AtExpression, InExpression, OfExpression
from yaraast.ast.expressions import (
    FunctionCall,
    Identifier,
    MemberAccess,
    StringCount,
    StringIdentifier,
    StringLength,
    StringOffset,
)
from yaraast.ast.modules import ModuleReference
from yaraast.ast.rules import Rule as RuleNode
from yaraast.lsp.document_query_resolution_ranges import narrow_range_to_name, resolved_if_contains
from yaraast.lsp.document_types import ResolvedSymbol
from yaraast.lsp.utils import find_node_at_position, get_word_at_position, location_to_range

if TYPE_CHECKING:
    from lsprotocol.types import Position

    from yaraast.lsp.document_context import DocumentContext


def resolve_symbol_from_ast(ctx: DocumentContext, position: Position) -> ResolvedSymbol | None:
    ast = ctx.ast()
    if ast is None:
        return None
    node = find_node_at_position(ast, position)
    if node is None:
        return None
    node_location = getattr(node, "location", None)
    if node_location is None:
        return None
    node_range = location_to_range(node_location, ctx.text)
    if isinstance(node, StringIdentifier):
        return resolved_if_contains(
            position, ResolvedSymbol(ctx.uri, node.name, node.name, "string", node_range)
        )
    if isinstance(node, StringCount | StringOffset | StringLength):
        normalized = f"${node.string_id}"
        word, _word_range = get_word_at_position(ctx.text, position)
        name = word or normalized
        return resolved_if_contains(
            position, ResolvedSymbol(ctx.uri, name, normalized, "string", node_range)
        )
    if isinstance(node, ModuleReference):
        return resolved_if_contains(
            position, ResolvedSymbol(ctx.uri, node.module, node.module, "module", node_range)
        )
    if isinstance(node, MemberAccess):
        full_name = member_access_to_string(node)
        kind = "module_member" if member_access_root_is_module(node) else "identifier"
        return resolved_if_contains(
            position,
            ResolvedSymbol(
                ctx.uri,
                full_name,
                full_name,
                kind,
                narrow_range_to_name(ctx, node_range, full_name),
            ),
        )
    if isinstance(node, FunctionCall) and "." in node.function:
        return resolved_if_contains(
            position,
            ResolvedSymbol(
                ctx.uri,
                node.function,
                node.function,
                "module_member",
                narrow_range_to_name(ctx, node_range, node.function),
            ),
        )
    if isinstance(node, RuleNode):
        return resolved_if_contains(
            position,
            ResolvedSymbol(
                ctx.uri,
                node.name,
                node.name,
                "rule",
                narrow_range_to_name(ctx, node_range, node.name),
            ),
        )
    if isinstance(node, Identifier):
        kind = "rule" if ctx.find_rule_definition(node.name) is not None else "identifier"
        return resolved_if_contains(
            position, ResolvedSymbol(ctx.uri, node.name, node.name, kind, node_range)
        )
    if isinstance(node, AtExpression | InExpression | OfExpression):
        word, word_range = get_word_at_position(ctx.text, position)
        if word.startswith(("$", "#", "@", "!")):
            normalized = word.lstrip("#@!")
            if not normalized.startswith("$"):
                normalized = f"${normalized}"
            return resolved_if_contains(
                position, ResolvedSymbol(ctx.uri, word, normalized, "string", word_range)
            )
    return None


def member_access_to_string(node: MemberAccess) -> str:
    if isinstance(node.object, ModuleReference):
        return f"{node.object.module}.{node.member}"
    if isinstance(node.object, Identifier):
        return f"{node.object.name}.{node.member}"
    if isinstance(node.object, MemberAccess):
        return f"{member_access_to_string(node.object)}.{node.member}"
    return node.member


def member_access_root_is_module(node: MemberAccess) -> bool:
    current = node.object
    while isinstance(current, MemberAccess):
        current = current.object
    return isinstance(current, ModuleReference)
