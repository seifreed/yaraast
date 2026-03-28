"""Document models and parsing cache for LSP."""

from __future__ import annotations

import hashlib
from pathlib import Path
from typing import TYPE_CHECKING, Any

from lsprotocol.types import Location, Position, Range, TextEdit

import yaraast.lsp.document_queries as document_queries
from yaraast.dialects import YaraDialect

if TYPE_CHECKING:
    from yaraast.ast.base import YaraFile
    from yaraast.yaral.ast_nodes import YaraLFile

    ASTRoot = YaraFile | YaraLFile
from yaraast.lsp.document_rule_queries import (
    get_rule_info,
    get_rule_meta_items,
    get_rule_sections,
    get_rule_string_identifiers,
)
from yaraast.lsp.document_symbols import build_symbol_indexes, build_symbols
from yaraast.lsp.document_types import (
    LanguageMode,
    ReferenceRecord,
    ResolvedSymbol,
    RuleLinkRecord,
    SymbolRecord,
    uri_to_path,
)
from yaraast.unified_parser import UnifiedParser


class _SymbolIndex:
    """Internal helper managing symbol indexing for a DocumentContext."""

    def __init__(self) -> None:
        self._symbols: list[SymbolRecord] | None = None
        self._symbols_by_kind: dict[str, list[SymbolRecord]] | None = None
        self._symbol_lookup: dict[tuple[str, str, str | None], SymbolRecord] | None = None

    def invalidate(self) -> None:
        self._symbols = None
        self._symbols_by_kind = None
        self._symbol_lookup = None

    def get_symbols(self, doc: DocumentContext) -> list[SymbolRecord]:
        if self._symbols is not None:
            return self._symbols
        ast = doc.ast()
        if ast is None:
            self._symbols = []
            return self._symbols
        self._symbols = build_symbols(doc, ast, doc.lines)
        self._symbols_by_kind = None
        self._symbol_lookup = None
        return self._symbols

    def _ensure_indexes(self, doc: DocumentContext) -> None:
        if self._symbols_by_kind is not None and self._symbol_lookup is not None:
            return
        self._symbols_by_kind, self._symbol_lookup = build_symbol_indexes(self.get_symbols(doc))

    def symbols_of_kind(self, doc: DocumentContext, kind: str) -> list[SymbolRecord]:
        self._ensure_indexes(doc)
        assert self._symbols_by_kind is not None
        return self._symbols_by_kind.get(kind, [])

    def find_record(
        self,
        doc: DocumentContext,
        kind: str,
        name: str,
        container_name: str | None = None,
    ) -> SymbolRecord | None:
        self._ensure_indexes(doc)
        assert self._symbol_lookup is not None
        return self._symbol_lookup.get((kind, name, container_name))


class DocumentContext:
    """Parsed/cached representation of a single document."""

    def __init__(
        self,
        uri: str,
        text: str,
        version: int | None = None,
        *,
        is_open: bool = False,
        language_mode: LanguageMode = LanguageMode.AUTO,
    ) -> None:
        self.uri = uri
        self.text = text
        self.version = version
        self.is_open = is_open
        self.language_mode = language_mode
        self._ast: ASTRoot | None = None
        self._parse_error: Exception | None = None
        self._lines: list[str] | None = None
        self._symbol_index = _SymbolIndex()
        self._dialect: YaraDialect | None = None
        self._analysis_cache: dict[str, tuple[str, Any]] = {}

    def revision_key(self) -> str:
        digest = hashlib.sha1(self.text.encode("utf-8"), usedforsecurity=False).hexdigest()
        return f"{self.version if self.version is not None else 'noversion'}:{digest}"

    def get_cached(self, key: str) -> Any | None:
        cached = self._analysis_cache.get(key)
        if cached is None:
            return None
        revision, value = cached
        if revision != self.revision_key():
            self._analysis_cache.pop(key, None)
            return None
        return value

    def set_cached(self, key: str, value: Any) -> None:
        self._analysis_cache[key] = (self.revision_key(), value)

    @property
    def lines(self) -> list[str]:
        if self._lines is None:
            self._lines = self.text.split("\n")
        return self._lines

    @property
    def path(self) -> Path | None:
        return uri_to_path(self.uri)

    def update(self, text: str, version: int | None = None, *, is_open: bool | None = None) -> None:
        self.text = text
        self.version = version
        if is_open is not None:
            self.is_open = is_open
        self._ast = None
        self._parse_error = None
        self._lines = None
        self._symbol_index.invalidate()
        self._dialect = None
        self._analysis_cache = {}

    def set_language_mode(self, language_mode: LanguageMode) -> None:
        if self.language_mode == language_mode:
            return
        self.language_mode = language_mode
        self._ast = None
        self._parse_error = None
        self._symbol_index.invalidate()
        self._dialect = None
        self._analysis_cache = {}

    def ast(self) -> ASTRoot | None:
        if self._ast is not None or self._parse_error is not None:
            return self._ast
        try:
            dialect = self.language_mode.to_dialect(self.text)
            self._dialect = dialect
            self._ast = UnifiedParser(self.text, dialect=dialect).parse()
        except Exception as exc:
            self._parse_error = exc
            self._ast = None
        return self._ast

    def dialect(self) -> YaraDialect:
        if self._dialect is not None:
            return self._dialect
        self.ast()
        return self._dialect or self.language_mode.to_dialect(self.text)

    def parse_error(self) -> Exception | None:
        if self._ast is None and self._parse_error is None:
            self.ast()
        return self._parse_error

    def symbols(self) -> list[SymbolRecord]:
        return self._symbol_index.get_symbols(self)

    def _symbols_of_kind(self, kind: str) -> list[SymbolRecord]:
        return self._symbol_index.symbols_of_kind(self, kind)

    def find_string_definition(self, identifier: str) -> Location | None:
        for symbol in self._symbols_of_kind("string"):
            if symbol.name == identifier:
                return Location(uri=self.uri, range=symbol.range)
        return None

    def get_rule(self, rule_name: str) -> Any | None:
        ast = self.ast()
        if ast is None:
            return None
        for rule in self._iter_rules(ast):
            if getattr(rule, "name", None) == rule_name:
                return rule
        return None

    def get_import_modules(self) -> list[str]:
        return self._unique_symbol_names("import")

    def get_include_paths(self) -> list[str]:
        return self._unique_symbol_names("include")

    def get_rule_names(self) -> list[str]:
        return self._unique_symbol_names("rule")

    def _unique_symbol_names(self, kind: str) -> list[str]:
        result: list[str] = []
        seen: set[str] = set()
        for symbol in self._symbols_of_kind(kind):
            if symbol.name not in seen:
                seen.add(symbol.name)
                result.append(symbol.name)
        return result

    def find_symbol_record(
        self,
        kind: str,
        name: str,
        container_name: str | None = None,
    ) -> SymbolRecord | None:
        return self._symbol_index.find_record(self, kind, name, container_name)

    def get_module_info(self, module_name: str) -> dict[str, Any] | None:
        from yaraast.lsp.lsp_docs import MODULE_DOCS

        if module_name not in MODULE_DOCS:
            return None
        return {"name": module_name, "description": MODULE_DOCS[module_name]}

    def get_rule_info(self, rule_name: str) -> dict[str, Any] | None:
        return get_rule_info(self, rule_name)

    def get_rule_meta_items(self, rule_name: str) -> list[tuple[str, Any]]:
        return get_rule_meta_items(self, rule_name)

    def get_rule_string_identifiers(self, rule_name: str) -> list[str]:
        return get_rule_string_identifiers(self, rule_name)

    def get_rule_sections(self, rule_name: str) -> list[str]:
        return get_rule_sections(self, rule_name)

    def get_meta_value(self, key: str) -> Any | None:
        return document_queries.get_meta_value(self, key)

    def get_string_definition_node(self, identifier: str) -> tuple[Any, Any] | None:
        return document_queries.get_string_definition_node(self, identifier)

    def get_string_definition_info(self, identifier: str) -> dict[str, Any] | None:
        return document_queries.get_string_definition_info(self, identifier)

    def get_module_member_info(self, qualified_name: str) -> dict[str, Any] | None:
        return document_queries.get_module_member_info(self, qualified_name)

    def get_include_info(self, include_path: str) -> dict[str, Any]:
        return document_queries.get_include_info(self, include_path)

    def get_include_target_uri(self, include_path: str) -> str | None:
        return document_queries.get_include_target_uri(self, include_path)

    def get_dotted_symbol_at_position(self, position: Position) -> tuple[str, Range] | None:
        return document_queries.get_dotted_symbol_at_position(self, position)

    def find_string_references(
        self, identifier: str, *, include_declaration: bool = True
    ) -> list[Location]:
        return document_queries.find_string_references(
            self,
            identifier,
            include_declaration=include_declaration,
        )

    def find_string_reference_records(
        self,
        identifier: str,
        *,
        include_declaration: bool = True,
    ) -> list[ReferenceRecord]:
        return document_queries.find_string_reference_records(
            self,
            identifier,
            include_declaration=include_declaration,
        )

    def build_string_rename_edits(self, identifier: str, new_name: str) -> list[TextEdit]:
        return document_queries.build_string_rename_edits(self, identifier, new_name)

    def rename_rule_edits(self, rule_name: str, new_name: str) -> list[TextEdit]:
        return document_queries.rename_rule_edits(self, rule_name, new_name)

    def resolve_symbol(self, position: Position) -> ResolvedSymbol | None:
        return document_queries.resolve_symbol(self, position)

    def _iter_rules(self, ast: Any) -> list[Any]:
        return list(getattr(ast, "rules", []))

    def find_rule_definition(self, rule_name: str) -> Location | None:
        return document_queries.find_rule_definition(self, rule_name)

    def rule_occurrences(self, rule_name: str) -> list[Location]:
        return document_queries.rule_occurrences(self, rule_name)

    def rule_reference_records(
        self, rule_name: str, *, include_declaration: bool = True
    ) -> list[ReferenceRecord]:
        return document_queries.rule_reference_records(
            self,
            rule_name,
            include_declaration=include_declaration,
        )

    def get_local_rule_link_records(self) -> list[RuleLinkRecord]:
        return document_queries.get_local_rule_link_records(
            self,
        )
