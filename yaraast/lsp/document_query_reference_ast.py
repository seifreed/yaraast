"""AST-first reference collection for LSP document queries."""

from __future__ import annotations

from collections.abc import Iterable, Mapping
from typing import TYPE_CHECKING

from lsprotocol.types import Location, Position, Range, TextEdit

from yaraast.ast.base import ASTNode
from yaraast.ast.conditions import ForExpression
from yaraast.ast.expressions import (
    Identifier,
    StringCount,
    StringIdentifier,
    StringLength,
    StringOffset,
)
from yaraast.lsp.utf16 import utf8_col_to_utf16, utf16_col_to_utf8
from yaraast.lsp.utils import location_to_range
from yaraast.shared.local_scope import local_name_variants
from yaraast.yarax.ast_nodes import (
    ArrayComprehension,
    DictComprehension,
    LambdaExpression,
    WithDeclaration,
    WithStatement,
)

if TYPE_CHECKING:
    from yaraast.lsp.document_context import DocumentContext


def collect_string_reference_locations_from_ast(
    ctx: DocumentContext,
    identifier: str,
    *,
    include_declaration: bool,
    rule_scope: str | None = None,
) -> list[Location] | None:
    ast = ctx.ast()
    if ast is None:
        return None
    normalized = identifier if identifier.startswith("$") else f"${identifier}"
    locations: list[Location] = []
    saw_supported_node = False
    definition = ctx.find_string_definition(normalized, rule_scope=rule_scope)
    if include_declaration and definition is not None:
        locations.append(definition)
    for rule in ctx._iter_rules(ast):
        if rule_scope is not None and getattr(rule, "name", None) != rule_scope:
            continue
        condition = getattr(rule, "condition", None)
        if condition is None:
            continue
        for node, local_scopes in iter_ast_nodes_with_local_scopes(condition):
            node_name = string_reference_name(node)
            if node_name is None:
                continue
            saw_supported_node = True
            if node_name != normalized or name_is_local(node_name, local_scopes):
                continue
            node_location = getattr(node, "location", None)
            if node_location is None:
                return None
            locations.append(Location(uri=ctx.uri, range=string_reference_range(node, ctx.text)))
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
        for node, local_scopes in iter_ast_nodes_with_local_scopes(condition):
            if not isinstance(node, Identifier):
                continue
            saw_supported_node = True
            if node.name != rule_name or name_is_local(node.name, local_scopes):
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
    *,
    rule_scope: str | None = None,
) -> list[TextEdit] | None:
    ast = ctx.ast()
    if ast is None:
        return None
    normalized = identifier if identifier.startswith("$") else f"${identifier}"
    replacement = new_name if new_name.startswith("$") else f"${new_name}"
    edits: list[TextEdit] = []

    definition = ctx.find_string_definition(normalized, rule_scope=rule_scope)
    if definition is not None:
        edits.append(TextEdit(range=definition.range, new_text=replacement))

    saw_supported_node = False
    for rule in ctx._iter_rules(ast):
        if rule_scope is not None and getattr(rule, "name", None) != rule_scope:
            continue
        condition = getattr(rule, "condition", None)
        if condition is None:
            continue
        for node, local_scopes in iter_ast_nodes_with_local_scopes(condition):
            node_name = string_reference_name(node)
            if node_name is None:
                continue
            saw_supported_node = True
            if node_name != normalized or name_is_local(node_name, local_scopes):
                continue
            node_location = getattr(node, "location", None)
            if node_location is None:
                return None
            edits.append(
                TextEdit(
                    range=string_reference_range(node, ctx.text),
                    new_text=string_reference_replacement(node, replacement),
                )
            )
    if not saw_supported_node and definition is not None:
        return edits
    if not saw_supported_node:
        return None
    return edits


def iter_ast_nodes(node: ASTNode) -> Iterable[ASTNode]:
    for child, _local_scopes in iter_ast_nodes_with_local_scopes(node):
        yield child


def iter_ast_nodes_with_local_scopes(
    node: ASTNode,
) -> Iterable[tuple[ASTNode, tuple[frozenset[str], ...]]]:
    yield from _iter_ast_nodes_with_local_scopes(node, ())


def node_has_local_binding(root: ASTNode, target: ASTNode, name: str) -> bool:
    for node, local_scopes in iter_ast_nodes_with_local_scopes(root):
        if node is target:
            return name_is_local(name, local_scopes)
    return False


def name_is_local(name: str, local_scopes: tuple[frozenset[str], ...]) -> bool:
    normalized = _normalized_local_lookup_name(name)
    return any(normalized in scope for scope in reversed(local_scopes))


def _iter_ast_nodes_with_local_scopes(
    node: ASTNode,
    local_scopes: tuple[frozenset[str], ...],
) -> Iterable[tuple[ASTNode, tuple[frozenset[str], ...]]]:
    yield node, local_scopes
    if isinstance(node, WithStatement):
        local_names: set[str] = set()
        for declaration in node.declarations:
            active_scopes = _extend_scopes(local_scopes, local_names)
            yield declaration, active_scopes
            yield from _iter_ast_value_with_local_scopes(declaration.value, active_scopes)
            local_names.update(
                local_name_variants(declaration.identifier, allow_string_identifier=True)
            )
        yield from _iter_ast_value_with_local_scopes(
            node.body, _extend_scopes(local_scopes, local_names)
        )
        return
    if isinstance(node, WithDeclaration):
        yield from _iter_ast_value_with_local_scopes(node.value, local_scopes)
        return
    if isinstance(node, ForExpression):
        yield from _iter_ast_value_with_local_scopes(node.quantifier, local_scopes)
        yield from _iter_ast_value_with_local_scopes(node.iterable, local_scopes)
        yield from _iter_ast_value_with_local_scopes(
            node.body, _extend_scopes(local_scopes, local_name_variants(node.variable))
        )
        return
    if isinstance(node, ArrayComprehension):
        yield from _iter_ast_value_with_local_scopes(node.iterable, local_scopes)
        scoped = _extend_scopes(local_scopes, local_name_variants(node.variable))
        yield from _iter_ast_value_with_local_scopes(node.condition, scoped)
        yield from _iter_ast_value_with_local_scopes(node.expression, scoped)
        return
    if isinstance(node, DictComprehension):
        yield from _iter_ast_value_with_local_scopes(node.iterable, local_scopes)
        dict_local_names = local_name_variants(node.key_variable)
        if node.value_variable:
            dict_local_names.update(local_name_variants(node.value_variable))
        scoped = _extend_scopes(local_scopes, dict_local_names)
        yield from _iter_ast_value_with_local_scopes(node.condition, scoped)
        yield from _iter_ast_value_with_local_scopes(node.key_expression, scoped)
        yield from _iter_ast_value_with_local_scopes(node.value_expression, scoped)
        return
    if isinstance(node, LambdaExpression):
        lambda_local_names: set[str] = set()
        for parameter in node.parameters:
            lambda_local_names.update(local_name_variants(parameter))
        yield from _iter_ast_value_with_local_scopes(
            node.body, _extend_scopes(local_scopes, lambda_local_names)
        )
        return
    for child in node.children():
        yield from _iter_ast_nodes_with_local_scopes(child, local_scopes)


def _iter_ast_value_with_local_scopes(
    value: object,
    local_scopes: tuple[frozenset[str], ...],
) -> Iterable[tuple[ASTNode, tuple[frozenset[str], ...]]]:
    if isinstance(value, ASTNode):
        yield from _iter_ast_nodes_with_local_scopes(value, local_scopes)
    elif isinstance(value, Mapping):
        for item in value.values():
            yield from _iter_ast_value_with_local_scopes(item, local_scopes)
    elif isinstance(value, list | tuple | set | frozenset):
        for item in value:
            yield from _iter_ast_value_with_local_scopes(item, local_scopes)


def _extend_scopes(
    local_scopes: tuple[frozenset[str], ...],
    local_names: Iterable[str],
) -> tuple[frozenset[str], ...]:
    scope = frozenset(local_names)
    if not scope:
        return local_scopes
    return (*local_scopes, scope)


def _normalized_local_lookup_name(name: str) -> str:
    if name.startswith(("#", "@", "!")):
        return f"${name[1:]}"
    return name


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


def string_reference_range(node: ASTNode, source_text: str) -> Range:
    location = getattr(node, "location", None)
    if location is None:
        msg = "String reference node has no source location"
        raise ValueError(msg)
    full_range = location_to_range(location, source_text)
    if isinstance(node, StringIdentifier):
        suffix = node.name[1:] if node.name.startswith("$") else node.name
        start_character = _prefixed_reference_start_character(
            source_text,
            full_range.start.line,
            full_range.start.character,
        )
        return _same_line_utf16_range(
            source_text,
            full_range.start.line,
            start_character,
            start_character + 1 + len(suffix),
        )
    if isinstance(node, StringCount | StringOffset | StringLength):
        suffix = node.string_id[1:] if node.string_id.startswith("$") else node.string_id
        start_character = _prefixed_reference_start_character(
            source_text,
            full_range.start.line,
            full_range.start.character,
        )
        return _same_line_utf16_range(
            source_text,
            full_range.start.line,
            start_character,
            start_character + 1 + len(suffix),
        )
    return full_range


def _same_line_utf16_range(source_text: str, line_index: int, start: int, end: int) -> Range:
    lines = source_text.split("\n")
    if 0 <= line_index < len(lines):
        line = lines[line_index]
        start = utf8_col_to_utf16(line, start)
        end = utf8_col_to_utf16(line, end)
    return Range(
        start=Position(line=line_index, character=start),
        end=Position(line=line_index, character=end),
    )


def _prefixed_reference_start_character(
    source_text: str,
    line_index: int,
    character: int,
) -> int:
    lines = source_text.split("\n")
    if 0 <= line_index < len(lines):
        line = lines[line_index]
        source_character = utf16_col_to_utf8(line, character)
        if 0 < source_character <= len(line) and line[source_character - 1] in "$#@!":
            return source_character - 1
        return source_character
    return character
