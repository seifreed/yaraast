"""AST-driven resolution helpers for LSP document queries."""

from __future__ import annotations

from typing import TYPE_CHECKING, Any

from lsprotocol.types import Position, Range

from yaraast.ast.base import ASTNode
from yaraast.ast.conditions import AtExpression, ForExpression, InExpression, OfExpression
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
from yaraast.lsp.document_query_reference_ast import (
    iter_ast_nodes,
    node_has_local_binding,
    string_reference_range,
)
from yaraast.lsp.document_query_resolution_ranges import narrow_range_to_name, resolved_if_contains
from yaraast.lsp.document_types import ResolvedSymbol
from yaraast.lsp.utf16 import utf8_col_to_utf16, utf16_col_to_utf8
from yaraast.lsp.utils import find_node_at_position, get_word_at_position, location_to_range
from yaraast.yarax.ast_nodes import ArrayComprehension, DictComprehension, WithStatement

if TYPE_CHECKING:
    from yaraast.lsp.document_context import DocumentContext


def resolve_symbol_from_ast(ctx: DocumentContext, position: Position) -> ResolvedSymbol | None:
    ast = ctx.ast()
    if ast is None:
        return None
    local_declaration = _resolve_local_declaration_identifier(ctx, ast, position)
    if local_declaration is not None:
        return local_declaration
    node = find_node_at_position(ast, position, ctx.text)
    if node is None:
        return None
    node_location = getattr(node, "location", None)
    if node_location is None:
        return None
    node_range = location_to_range(node_location, ctx.text)

    result = _resolve_typed_node(ctx, position, node, node_range, ast)
    if result is not None:
        return result
    return _resolve_expression_context(ctx, position, node)


def _resolve_local_declaration_identifier(
    ctx: DocumentContext,
    root: Any,
    position: Position,
) -> ResolvedSymbol | None:
    word, _word_range = get_word_at_position(ctx.text, position)
    if not word:
        return None
    for node in iter_ast_nodes(root):
        if not isinstance(node, WithStatement):
            resolved = _resolve_loop_declaration_identifier(ctx, node, word, position)
            if resolved is not None:
                return resolved
            continue
        resolved = _resolve_with_declaration_identifier(ctx, node, word, position)
        if resolved is not None:
            return resolved
    return None


def _resolve_with_declaration_identifier(
    ctx: DocumentContext,
    node: WithStatement,
    word: str,
    position: Position,
) -> ResolvedSymbol | None:
    for declaration in node.declarations:
        if word != declaration.identifier:
            continue
        declaration_range = _with_declaration_identifier_range(
            ctx, declaration.identifier, declaration.value
        )
        if declaration_range is None:
            continue
        resolved = _resolved_local_identifier(
            ctx, declaration.identifier, declaration_range, position
        )
        if resolved is not None:
            return resolved
    return None


def _resolve_loop_declaration_identifier(
    ctx: DocumentContext,
    node: ASTNode,
    word: str,
    position: Position,
) -> ResolvedSymbol | None:
    if isinstance(node, ForExpression | ArrayComprehension):
        return _resolve_names_before_iterable(ctx, [node.variable], node.iterable, word, position)
    if isinstance(node, DictComprehension):
        names = [node.key_variable]
        if node.value_variable:
            names.append(node.value_variable)
        return _resolve_names_before_iterable(ctx, names, node.iterable, word, position)
    return None


def _resolve_names_before_iterable(
    ctx: DocumentContext,
    identifiers: list[str],
    iterable: Any,
    word: str,
    position: Position,
) -> ResolvedSymbol | None:
    if word not in identifiers:
        return None
    iterable_range = _first_value_range(iterable, ctx.text)
    if iterable_range is None:
        return None
    line_index = iterable_range.start.line
    if line_index < 0 or line_index >= len(ctx.lines):
        return None
    line = ctx.lines[line_index]
    iterable_start = utf16_col_to_utf8(line, iterable_range.start.character)
    declaration_start = line.rfind("for", 0, iterable_start)
    separator_start = line.rfind("in", declaration_start, iterable_start)
    if declaration_start < 0 or separator_start < 0:
        return None
    identifier_start = line.find(word, declaration_start + len("for"), separator_start)
    while identifier_start >= 0:
        declaration_range = _same_line_identifier_range(line, line_index, identifier_start, word)
        if declaration_range is not None:
            resolved = _resolved_local_identifier(ctx, word, declaration_range, position)
            if resolved is not None:
                return resolved
        identifier_start = line.find(word, identifier_start + len(word), separator_start)
    return None


def _first_value_range(value: Any, source_text: str) -> Range | None:
    value_location = getattr(value, "location", None)
    if value_location is not None:
        return location_to_range(value_location, source_text)
    if isinstance(value, ASTNode):
        child_ranges = [
            child_range
            for child in value.children()
            if (child_range := _first_value_range(child, source_text)) is not None
        ]
        return min(
            child_ranges,
            key=lambda range_: (range_.start.line, range_.start.character),
            default=None,
        )
    return None


def _with_declaration_identifier_range(
    ctx: DocumentContext,
    identifier: str,
    value: Any,
) -> Range | None:
    value_range = _first_value_range(value, ctx.text)
    if value_range is None:
        return None
    line_index = value_range.start.line
    if line_index < 0 or line_index >= len(ctx.lines):
        return None
    line = ctx.lines[line_index]
    value_start = utf16_col_to_utf8(line, value_range.start.character)
    identifier_start = line.rfind(identifier, 0, value_start)
    if identifier_start < 0:
        return None
    between_identifier_and_value = line[identifier_start + len(identifier) : value_start]
    if "=" not in between_identifier_and_value:
        return None
    return _same_line_identifier_range(line, line_index, identifier_start, identifier)


def _same_line_identifier_range(
    line: str,
    line_index: int,
    identifier_start: int,
    identifier: str,
) -> Range | None:
    if identifier_start < 0:
        return None
    identifier_end = identifier_start + len(identifier)
    if identifier_start > 0 and _is_identifier_char(line[identifier_start - 1]):
        return None
    if identifier_end < len(line) and _is_identifier_char(line[identifier_end]):
        return None
    return Range(
        start=Position(
            line=line_index,
            character=utf8_col_to_utf16(line, identifier_start),
        ),
        end=Position(
            line=line_index,
            character=utf8_col_to_utf16(line, identifier_start + len(identifier)),
        ),
    )


def _is_identifier_char(char: str) -> bool:
    return char.isalnum() or char in "_$"


def _resolved_local_identifier(
    ctx: DocumentContext,
    name: str,
    range_: Range,
    position: Position,
) -> ResolvedSymbol | None:
    return resolved_if_contains(
        position,
        ResolvedSymbol(ctx.uri, name, name, "identifier", range_),
    )


def _resolve_typed_node(
    ctx: DocumentContext,
    position: Position,
    node: Any,
    node_range: Range,
    root: Any,
) -> ResolvedSymbol | None:
    if isinstance(node, StringIdentifier):
        reference_range = string_reference_range(node, ctx.text)
        if node_has_local_binding(root, node, node.name):
            return resolved_if_contains(
                position,
                ResolvedSymbol(ctx.uri, node.name, node.name, "identifier", reference_range),
            )
        return resolved_if_contains(
            position, ResolvedSymbol(ctx.uri, node.name, node.name, "string", reference_range)
        )
    if isinstance(node, StringCount | StringOffset | StringLength):
        suffix = node.string_id[1:] if node.string_id.startswith("$") else node.string_id
        normalized = f"${suffix}"
        word, _word_range = get_word_at_position(ctx.text, position)
        name = word or normalized
        reference_range = string_reference_range(node, ctx.text)
        if node_has_local_binding(root, node, normalized):
            return resolved_if_contains(
                position, ResolvedSymbol(ctx.uri, name, normalized, "identifier", reference_range)
            )
        return resolved_if_contains(
            position, ResolvedSymbol(ctx.uri, name, normalized, "string", reference_range)
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
        kind = (
            "rule"
            if ctx.find_rule_definition(node.name) is not None
            and not node_has_local_binding(root, node, node.name)
            else "identifier"
        )
        return resolved_if_contains(
            position, ResolvedSymbol(ctx.uri, node.name, node.name, kind, node_range)
        )
    return None


def _resolve_expression_context(
    ctx: DocumentContext,
    position: Position,
    node: Any,
) -> ResolvedSymbol | None:
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
