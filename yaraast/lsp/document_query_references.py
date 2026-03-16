"""Reference and rename helpers for LSP document contexts."""

from __future__ import annotations

from typing import TYPE_CHECKING

from lsprotocol.types import Location, Position, TextEdit

from yaraast.lsp.document_query_reference_ast import (
    build_string_rename_edits_from_ast,
    collect_rule_reference_locations_from_ast,
    collect_string_reference_locations_from_ast,
)
from yaraast.lsp.document_query_reference_text import (
    iter_reference_occurrences,
    line_has_assignment,
    matches_resolved_symbol,
)
from yaraast.lsp.document_types import ReferenceRecord, RuleLinkRecord
from yaraast.lsp.structure import make_range

if TYPE_CHECKING:
    from yaraast.lsp.document_context import DocumentContext


def find_string_references(
    ctx: DocumentContext,
    identifier: str,
    *,
    include_declaration: bool = True,
) -> list[Location]:
    cache_key = f"string_references:{identifier}:{int(include_declaration)}"
    cached = ctx.get_cached(cache_key)
    if cached is not None:
        return cached
    ast_locations = collect_string_reference_locations_from_ast(
        ctx, identifier, include_declaration=include_declaration
    )
    if ast_locations is not None:
        ctx.set_cached(cache_key, ast_locations)
        return ast_locations
    base_name = identifier[1:] if identifier.startswith("$") else identifier
    variants = [f"${base_name}", f"#{base_name}", f"@{base_name}", f"!{base_name}"]
    locations: list[Location] = []
    definition = ctx.find_string_definition(variants[0])
    definition_range = definition.range if definition else None
    for line_num, col, variant, section_name in iter_reference_occurrences(
        ctx,
        variants,
        allowed_sections=("strings", "condition", "events", "match", "outcome", "options"),
    ):
        if not matches_resolved_symbol(
            ctx,
            Position(line=line_num, character=col),
            kind="string",
            normalized_name=variants[0],
        ):
            continue
        rng = make_range(line_num, col, col + len(variant))
        is_definition = (
            variant.startswith("$")
            and section_name == "strings"
            and line_has_assignment(ctx.lines[line_num], col + len(variant))
        )
        if is_definition and (not include_declaration or definition_range == rng):
            if include_declaration:
                locations.append(Location(uri=ctx.uri, range=rng))
            continue
        if section_name == "strings":
            continue
        locations.append(Location(uri=ctx.uri, range=rng))
    ctx.set_cached(cache_key, locations)
    return locations


def find_string_reference_records(
    ctx: DocumentContext,
    identifier: str,
    *,
    include_declaration: bool = True,
) -> list[ReferenceRecord]:
    cache_key = f"string_reference_records:{identifier}:{int(include_declaration)}"
    cached = ctx.get_cached(cache_key)
    if cached is not None:
        return cached
    definition = ctx.find_string_definition(identifier)
    records = [
        ReferenceRecord(
            location=location,
            role="declaration" if definition and definition.range == location.range else "read",
            symbol_kind="string",
        )
        for location in ctx.find_string_references(
            identifier,
            include_declaration=include_declaration,
        )
    ]
    ctx.set_cached(cache_key, records)
    return records


def build_string_rename_edits(
    ctx: DocumentContext, identifier: str, new_name: str
) -> list[TextEdit]:
    if not new_name.startswith("$"):
        new_name = f"${new_name}"
    ast_edits = build_string_rename_edits_from_ast(ctx, identifier, new_name)
    if ast_edits is not None:
        return ast_edits
    base_name = identifier[1:] if identifier.startswith("$") else identifier
    replacements = [
        (f"${base_name}", new_name),
        (f"#{base_name}", f"#{new_name[1:]}"),
        (f"@{base_name}", f"@{new_name[1:]}"),
        (f"!{base_name}", f"!{new_name[1:]}"),
    ]
    edits: list[TextEdit] = []
    for old, new in replacements:
        for line_num, col, variant, _section_name in iter_reference_occurrences(
            ctx,
            [old],
            allowed_sections=("strings", "condition", "events", "match", "outcome", "options"),
        ):
            if not matches_resolved_symbol(
                ctx,
                Position(line=line_num, character=col),
                kind="string",
                normalized_name=identifier if identifier.startswith("$") else f"${identifier}",
            ):
                continue
            edits.append(
                TextEdit(range=make_range(line_num, col, col + len(variant)), new_text=new)
            )
    return edits


def rename_rule_edits(ctx: DocumentContext, rule_name: str, new_name: str) -> list[TextEdit]:
    return [
        TextEdit(range=location.range, new_text=new_name)
        for location in ctx.rule_occurrences(rule_name)
    ]


def find_rule_definition(ctx: DocumentContext, rule_name: str) -> Location | None:
    cache_key = f"rule_definition:{rule_name}"
    cached = ctx.get_cached(cache_key)
    if cached is not None:
        return cached
    for symbol in ctx._symbols_of_kind("rule"):
        if symbol.name == rule_name:
            result = Location(uri=ctx.uri, range=symbol.range)
            ctx.set_cached(cache_key, result)
            return result
    return None


def rule_occurrences(ctx: DocumentContext, rule_name: str) -> list[Location]:
    cache_key = f"rule_occurrences:{rule_name}"
    cached = ctx.get_cached(cache_key)
    if cached is not None:
        return cached
    ast_locations = collect_rule_reference_locations_from_ast(ctx, rule_name)
    if ast_locations is not None:
        ctx.set_cached(cache_key, ast_locations)
        return ast_locations
    locations: list[Location] = []
    definition = ctx.find_rule_definition(rule_name)
    if definition is not None:
        locations.append(definition)
    for line_num, col, _variant, _section_name in iter_reference_occurrences(
        ctx,
        [rule_name],
        allowed_sections=("condition", "events", "match", "outcome", "options"),
    ):
        if not matches_resolved_symbol(
            ctx,
            Position(line=line_num, character=col),
            kind=("rule", "identifier"),
            normalized_name=rule_name,
        ):
            continue
        rng = make_range(line_num, col, col + len(rule_name))
        if definition is not None and definition.range == rng:
            continue
        locations.append(Location(uri=ctx.uri, range=rng))
    ctx.set_cached(cache_key, locations)
    return locations


def rule_reference_records(
    ctx: DocumentContext,
    rule_name: str,
    *,
    include_declaration: bool = True,
) -> list[ReferenceRecord]:
    cache_key = f"rule_reference_records:{rule_name}:{int(include_declaration)}"
    cached = ctx.get_cached(cache_key)
    if cached is not None:
        return cached
    definition = ctx.find_rule_definition(rule_name)
    records: list[ReferenceRecord] = []
    for location in ctx.rule_occurrences(rule_name):
        if not include_declaration and definition and definition.range == location.range:
            continue
        role = "declaration" if definition and definition.range == location.range else "use"
        records.append(ReferenceRecord(location=location, role=role, symbol_kind="rule"))
    ctx.set_cached(cache_key, records)
    return records


def get_local_rule_link_records(ctx: DocumentContext) -> list[RuleLinkRecord]:
    cache_key = "local_rule_link_records"
    cached = ctx.get_cached(cache_key)
    if cached is not None:
        return cached
    records: list[RuleLinkRecord] = []
    for rule_name in ctx.get_rule_names():
        definition = ctx.find_rule_definition(rule_name)
        if definition is None:
            continue
        for record in ctx.rule_reference_records(rule_name, include_declaration=False):
            records.append(
                RuleLinkRecord(
                    rule_name=rule_name,
                    location=record.location,
                    target_uri=definition.uri,
                )
            )
    ctx.set_cached(cache_key, records)
    return records
