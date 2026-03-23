"""Rule resolution and reference queries for the LSP runtime."""

from __future__ import annotations

import logging
from typing import TYPE_CHECKING

from lsprotocol.types import Location, Position, TextEdit

from yaraast.lsp.document_types import ReferenceRecord, ResolvedSymbol, RuleLinkRecord, uri_to_path

logger = logging.getLogger(__name__)

if TYPE_CHECKING:
    from yaraast.lsp.runtime import LspRuntime


def resolve_symbol(
    runtime: LspRuntime, uri: str, text: str, position: Position
) -> ResolvedSymbol | None:
    resolved = runtime.ensure_document(uri, text).resolve_symbol(position)
    if (
        resolved is not None
        and resolved.kind == "identifier"
        and find_rule_definition(runtime, resolved.normalized_name, uri) is not None
    ):
        return ResolvedSymbol(
            uri=resolved.uri,
            name=resolved.name,
            normalized_name=resolved.normalized_name,
            kind="rule",
            range=resolved.range,
        )
    return resolved


def find_rule_definition(
    runtime: LspRuntime,
    rule_name: str,
    current_uri: str | None = None,
) -> Location | None:
    cache_key = (runtime._workspace_generation, rule_name, current_uri)
    if cache_key in runtime._rule_definition_cache:
        return runtime._rule_definition_cache[cache_key]
    ordered_docs = runtime.iter_workspace_documents()
    if current_uri:
        ordered_docs.sort(key=lambda doc: doc.uri != current_uri)
    for doc in ordered_docs:
        location = doc.find_rule_definition(rule_name)
        if location is not None:
            runtime._rule_definition_cache[cache_key] = location
            return location
    runtime._rule_definition_cache[cache_key] = None
    return None


def find_rule_references(
    runtime: LspRuntime,
    rule_name: str,
    *,
    include_declaration: bool = True,
    current_uri: str | None = None,
) -> list[Location]:
    cache_key = (runtime._workspace_generation, rule_name, include_declaration, current_uri)
    cached = runtime._rule_references_cache.get(cache_key)
    if cached is not None:
        return cached
    refs: list[Location] = []
    definition = find_rule_definition(runtime, rule_name, current_uri)
    for doc in runtime.iter_workspace_documents():
        refs.extend(doc.rule_occurrences(rule_name))
    if not include_declaration and definition is not None:
        refs = [
            ref for ref in refs if not (ref.uri == definition.uri and ref.range == definition.range)
        ]
    runtime._rule_references_cache[cache_key] = refs
    return refs


def find_rule_reference_records(
    runtime: LspRuntime,
    rule_name: str,
    *,
    include_declaration: bool = True,
    current_uri: str | None = None,
) -> list[ReferenceRecord]:
    cache_key = (runtime._workspace_generation, rule_name, include_declaration, current_uri)
    cached = runtime._rule_reference_records_cache.get(cache_key)
    if cached is not None:
        return list(cached)
    records: list[ReferenceRecord] = []
    definition = find_rule_definition(runtime, rule_name, current_uri)
    for doc in runtime.iter_workspace_documents():
        for record in doc.rule_reference_records(
            rule_name, include_declaration=include_declaration
        ):
            if (
                not include_declaration
                and definition
                and (
                    record.location.uri == definition.uri
                    and record.location.range == definition.range
                )
            ):
                continue
            if (
                definition
                and record.location.uri == definition.uri
                and record.location.range == definition.range
            ):
                record = ReferenceRecord(record.location, "declaration", "rule")
            records.append(record)
    runtime._rule_reference_records_cache[cache_key] = records
    return records


def find_rule_reference_records_in_document(
    runtime: LspRuntime,
    rule_name: str,
    document_uri: str,
    *,
    include_declaration: bool = True,
    current_uri: str | None = None,
) -> list[ReferenceRecord]:
    doc = runtime.documents.get(document_uri)
    if doc is None:
        path = uri_to_path(document_uri)
        if path is None or not path.exists() or not path.is_file():
            return []
        try:
            doc = runtime.get_document(document_uri)
        except Exception:
            logger.debug("Operation failed in %s", __name__, exc_info=True)
            return []
    if doc is None:
        return []
    definition = find_rule_definition(runtime, rule_name, current_uri)
    records: list[ReferenceRecord] = []
    for record in doc.rule_reference_records(rule_name, include_declaration=True):
        if (
            not include_declaration
            and definition
            and (
                record.location.uri == definition.uri and record.location.range == definition.range
            )
        ):
            continue
        if (
            definition
            and record.location.uri == definition.uri
            and record.location.range == definition.range
        ):
            record = ReferenceRecord(record.location, "declaration", "rule")
        records.append(record)
    return records


def get_rule_link_records_for_document(
    runtime: LspRuntime, document_uri: str
) -> list[RuleLinkRecord]:
    doc = runtime.documents.get(document_uri)
    if doc is None:
        path = uri_to_path(document_uri)
        if path is None or not path.exists() or not path.is_file():
            return []
        try:
            doc = runtime.get_document(document_uri)
        except Exception:
            logger.debug("Operation failed in %s", __name__, exc_info=True)
            return []
    workspace_rule_names = {
        record.name for record in runtime.workspace_symbol_records() if record.kind == "rule"
    }
    cache_key = f"rule_link_records:{runtime._workspace_generation}:{document_uri}"
    cached = doc.get_cached(cache_key)
    if cached is not None:
        return cached
    links: list[RuleLinkRecord] = []
    for rule_name in workspace_rule_names:
        if not rule_name:
            continue
        definition = find_rule_definition(runtime, rule_name, document_uri)
        if definition is None:
            continue
        for record in find_rule_reference_records_in_document(
            runtime,
            rule_name,
            document_uri,
            current_uri=document_uri,
        ):
            if record.role == "declaration" or record.location.uri != document_uri:
                continue
            links.append(
                RuleLinkRecord(
                    rule_name=rule_name,
                    location=record.location,
                    target_uri=definition.uri,
                )
            )
    doc.set_cached(cache_key, links)
    return links


def rename_rule(runtime: LspRuntime, rule_name: str, new_name: str) -> dict[str, list[TextEdit]]:
    changes: dict[str, list[TextEdit]] = {}
    for doc in runtime.iter_workspace_documents():
        edits = doc.rename_rule_edits(rule_name, new_name)
        if edits:
            changes[doc.uri] = edits
    return changes
