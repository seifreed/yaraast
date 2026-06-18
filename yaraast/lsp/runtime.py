"""Runtime coordinator for the YARAAST language server."""

from __future__ import annotations

from collections import deque
import logging
from typing import Any

from lsprotocol.types import Location, Position, SymbolInformation, TextEdit

from yaraast.lsp.document_context import DocumentContext
from yaraast.lsp.document_types import (
    LanguageMode,
    ReferenceRecord,
    ResolvedSymbol,
    RuleLinkRecord,
    RuntimeConfig,
    SymbolRecord,
    path_to_uri,
    uri_to_path,
)
from yaraast.lsp.runtime_observability import (
    get_latency_metrics as runtime_get_latency_metrics,
    get_status as runtime_get_status,
    record_latency as runtime_record_latency,
    should_debounce as runtime_should_debounce,
)
from yaraast.lsp.runtime_rules import (
    find_rule_definition as runtime_find_rule_definition,
    find_rule_reference_records as runtime_find_rule_reference_records,
    find_rule_reference_records_in_document as runtime_find_rule_reference_records_in_document,
    find_rule_references as runtime_find_rule_references,
    get_rule_link_records_for_document as runtime_get_rule_link_records_for_document,
    rename_rule as runtime_rename_rule,
    resolve_symbol as runtime_resolve_symbol,
)
from yaraast.lsp.runtime_workspace import (
    workspace_symbol_records as runtime_workspace_symbol_records,
    workspace_symbols as runtime_workspace_symbols,
)
from yaraast.lsp.utils import path_exists, path_is_dir, path_is_file
from yaraast.lsp.workspace_index import WorkspaceIndex

logger = logging.getLogger(__name__)


def _parse_bool_setting(value: Any, default: bool) -> bool:
    if isinstance(value, bool):
        return value
    if isinstance(value, int) and not isinstance(value, bool):
        return value != 0
    if isinstance(value, str):
        normalized = value.strip().lower()
        if normalized in {"1", "true", "yes", "on"}:
            return True
        if normalized in {"0", "false", "no", "off"}:
            return False
    return default


def _parse_non_negative_int_setting(value: Any, default: int) -> int:
    if isinstance(value, bool):
        return default
    if isinstance(value, int):
        return max(0, value)
    if isinstance(value, str):
        try:
            return max(0, int(value.strip()))
        except ValueError:
            return default
    return default


def _parse_language_mode(value: object, default: LanguageMode) -> LanguageMode:
    if not isinstance(value, str):
        return default
    raw_mode = value.strip().lower()
    mapping = {
        "auto": LanguageMode.AUTO,
        "yara": LanguageMode.YARA,
        "yarax": LanguageMode.YARA_X,
        "yara-x": LanguageMode.YARA_X,
        "yaral": LanguageMode.YARA_L,
        "yara-l": LanguageMode.YARA_L,
    }
    return mapping.get(raw_mode, default)


def _require_document_uri(uri: str) -> str:
    if not isinstance(uri, str):
        msg = "Document URI must be a string"
        raise TypeError(msg)
    return uri


__all__ = [
    "CacheManager",
    "DocumentContext",
    "LanguageMode",
    "LspRuntime",
    "ReferenceRecord",
    "ResolvedSymbol",
    "RuleLinkRecord",
    "RuntimeConfig",
    "SymbolRecord",
    "path_to_uri",
    "uri_to_path",
]


class CacheManager:
    """Manages workspace caches with generation-based invalidation."""

    def __init__(self) -> None:
        self._generation = 0
        self._workspace_symbol_cache: dict[tuple[int, str], list[SymbolRecord]] = {}
        self._rule_definition_cache: dict[tuple[int, str, str | None], Location | None] = {}
        self._rule_references_cache: dict[tuple[int, str, bool, str | None], list[Location]] = {}
        self._rule_reference_records_cache: dict[
            tuple[int, str, bool, str | None], list[ReferenceRecord]
        ] = {}

    @property
    def generation(self) -> int:
        return self._generation

    def bump_generation(self) -> None:
        """Invalidate all caches by incrementing generation."""
        self._generation += 1
        self._workspace_symbol_cache = {}
        self._rule_definition_cache = {}
        self._rule_references_cache = {}
        self._rule_reference_records_cache = {}

    @property
    def workspace_symbol_cache(
        self,
    ) -> dict[tuple[int, str], list[SymbolRecord]]:
        return self._workspace_symbol_cache

    @property
    def rule_definition_cache(
        self,
    ) -> dict[tuple[int, str, str | None], Location | None]:
        return self._rule_definition_cache

    @property
    def rule_references_cache(
        self,
    ) -> dict[tuple[int, str, bool, str | None], list[Location]]:
        return self._rule_references_cache

    @property
    def rule_reference_records_cache(
        self,
    ) -> dict[tuple[int, str, bool, str | None], list[ReferenceRecord]]:
        return self._rule_reference_records_cache


class LspRuntime:
    """Owns document cache, parsing cache and workspace index."""

    def __init__(
        self,
        index: WorkspaceIndex | None = None,
        config: RuntimeConfig | None = None,
        cache: CacheManager | None = None,
    ) -> None:
        self.documents: dict[str, DocumentContext] = {}
        if index is not None and not isinstance(index, WorkspaceIndex):
            msg = "LSP runtime index must be a WorkspaceIndex"
            raise TypeError(msg)
        self.index = index or WorkspaceIndex()
        if config is not None and not isinstance(config, RuntimeConfig):
            msg = "LSP runtime config must be a RuntimeConfig"
            raise TypeError(msg)
        self.config = config or RuntimeConfig()
        if cache is not None and not isinstance(cache, CacheManager):
            msg = "LSP runtime cache must be a CacheManager"
            raise TypeError(msg)
        self.cache = cache or CacheManager()
        self._latency: dict[str, deque[float]] = {}
        self._task_timestamps: dict[tuple[str, str], float] = {}
        self._dirty_documents: set[str] = set()

    def _mark_dirty(self, uri: str) -> None:
        if self.config.cache_workspace:
            self._dirty_documents.add(uri)
        self.cache.bump_generation()

    def _sync_document_to_index(self, uri: str) -> None:
        if not self.config.cache_workspace:
            return
        ctx = self.documents.get(uri)
        if ctx is None:
            self.index.remove_document(uri)
            self._dirty_documents.discard(uri)
            self.cache.bump_generation()
            return
        self.index.update_document(ctx)
        self._dirty_documents.discard(uri)
        self.cache.bump_generation()

    def open_document(self, uri: str, text: str, version: int | None = None) -> DocumentContext:
        uri = _require_document_uri(uri)
        ctx = self.documents.get(uri)
        if ctx is None:
            ctx = DocumentContext(
                uri,
                text,
                version,
                is_open=True,
                language_mode=self.config.language_mode,
            )
            self.documents[uri] = ctx
        else:
            ctx.set_language_mode(self.config.language_mode)
            ctx.update(text, version, is_open=True)
        self._mark_dirty(uri)
        return ctx

    def update_document(self, uri: str, text: str, version: int | None = None) -> DocumentContext:
        uri = _require_document_uri(uri)
        return self.open_document(uri, text, version)

    def save_document(self, uri: str, text: str | None = None) -> DocumentContext | None:
        uri = _require_document_uri(uri)
        ctx = self.get_document(uri, load_workspace=False)
        if ctx is None:
            if text is None:
                return None
            return self.open_document(uri, text)
        if text is not None:
            ctx.update(text, ctx.version, is_open=True)
            self._mark_dirty(uri)
        self._sync_document_to_index(uri)
        return ctx

    def close_document(self, uri: str) -> None:
        uri = _require_document_uri(uri)
        ctx = self.documents.get(uri)
        if ctx is None:
            return
        if self.config.cache_workspace:
            ctx.is_open = False
            self._sync_document_to_index(uri)
        else:
            self.documents.pop(uri, None)
            self.cache.bump_generation()

    def get_document(self, uri: str, *, load_workspace: bool = True) -> DocumentContext | None:
        uri = _require_document_uri(uri)
        ctx = self.documents.get(uri)
        if ctx is not None:
            return ctx
        if not load_workspace:
            return None
        path = uri_to_path(uri)
        if path is None or not path_exists(path) or path_is_dir(path):
            return None
        try:
            text = path.read_text(encoding="utf-8")
        except Exception:
            logger.debug("Operation failed in %s", __name__, exc_info=True)
            return None
        ctx = DocumentContext(uri, text, is_open=False, language_mode=self.config.language_mode)
        if self.config.cache_workspace:
            self.documents[uri] = ctx
            self.index.update_document(ctx)
        self.cache.bump_generation()
        return ctx

    def ensure_document(self, uri: str, text: str) -> DocumentContext:
        uri = _require_document_uri(uri)
        ctx = self.documents.get(uri)
        if ctx is None:
            return self.open_document(uri, text)
        if ctx.text != text:
            ctx.update(text, ctx.version, is_open=ctx.is_open)
            self._mark_dirty(uri)
        return ctx

    def iter_workspace_documents(self) -> list[DocumentContext]:
        docs: dict[str, DocumentContext] = dict(self.documents)
        for path in self.index.iter_candidate_files():
            uri = path_to_uri(path)
            if uri not in docs:
                ctx = self.get_document(uri)
                if ctx is not None:
                    docs[uri] = ctx
        return list(docs.values())

    def set_workspace_folders(self, folders: list[str]) -> None:
        self.index.set_workspace_folders(folders)
        for uri, doc in list(self.documents.items()):
            if doc.is_open:
                continue
            if self.index._workspace_root_for_uri(uri) is not None:
                continue
            self.documents.pop(uri, None)
            self._dirty_documents.discard(uri)
        self.cache.bump_generation()
        if self.config.cache_workspace:
            for path in self.index.iter_candidate_files():
                self.get_document(path_to_uri(path))

    def update_config(self, settings: dict[str, Any] | None) -> None:
        if settings is None:
            return
        if not isinstance(settings, dict):
            msg = "LSP runtime settings must be a dictionary"
            raise TypeError(msg)
        if not settings:
            return
        if "YARA" in settings and isinstance(settings["YARA"], dict):
            settings = settings["YARA"]
        previous_mode = self.config.language_mode
        if "cacheWorkspace" in settings:
            self.config.cache_workspace = _parse_bool_setting(
                settings["cacheWorkspace"], self.config.cache_workspace
            )
        if "ruleNameValidation" in settings:
            rule_name_validation = settings["ruleNameValidation"]
            if rule_name_validation is None:
                self.config.rule_name_validation = None
            elif isinstance(rule_name_validation, str):
                self.config.rule_name_validation = rule_name_validation or None
        if "metadataValidation" in settings and isinstance(settings["metadataValidation"], list):
            self.config.metadata_validation = list(settings["metadataValidation"])
        if "codeFormatting" in settings and isinstance(settings["codeFormatting"], dict):
            self.config.code_formatting = dict(settings["codeFormatting"])
        if "dialectMode" in settings:
            self.config.language_mode = _parse_language_mode(
                settings["dialectMode"], self.config.language_mode
            )
        if previous_mode != self.config.language_mode:
            for doc in self.documents.values():
                doc.set_language_mode(self.config.language_mode)
                self._mark_dirty(doc.uri)
        if "diagnosticsDebounceMs" in settings:
            self.config.diagnostics_debounce_ms = _parse_non_negative_int_setting(
                settings["diagnosticsDebounceMs"], self.config.diagnostics_debounce_ms
            )
        if not self.config.cache_workspace:
            self.documents = {uri: doc for uri, doc in self.documents.items() if doc.is_open}
        self.cache.bump_generation()

    def handle_watched_files(self, changes: list[Any]) -> None:
        for change in changes:
            uri = getattr(change, "uri", None)
            if not uri:
                continue
            path = uri_to_path(uri)
            if path is None:
                continue
            if path_exists(path) and path_is_file(path):
                ctx = self.documents.get(uri)
                if ctx is not None and ctx.is_open:
                    self._sync_document_to_index(uri)
                    continue
                try:
                    text = path.read_text(encoding="utf-8")
                except Exception:
                    logger.debug("Operation failed in %s", __name__, exc_info=True)
                    self.documents.pop(uri, None)
                    continue
                if self.config.cache_workspace:
                    ctx = self.open_document(uri, text)
                    ctx.is_open = False
                    self._sync_document_to_index(uri)
                else:
                    self.documents.pop(uri, None)
                    self.cache.bump_generation()
            else:
                self.documents.pop(uri, None)
                self.index.remove_document(uri)
                self._dirty_documents.discard(uri)
                self.cache.bump_generation()

    def workspace_symbols(self, query: object) -> list[SymbolInformation]:
        return runtime_workspace_symbols(self, query)

    def workspace_symbol_records(self, query: object = "") -> list[SymbolRecord]:
        return runtime_workspace_symbol_records(self, query)

    def resolve_symbol(self, uri: str, text: str, position: Position) -> ResolvedSymbol | None:
        return runtime_resolve_symbol(self, uri, text, position)

    def find_rule_definition(
        self, rule_name: str, current_uri: str | None = None
    ) -> Location | None:
        return runtime_find_rule_definition(self, rule_name, current_uri)

    def find_rule_references(
        self,
        rule_name: str,
        *,
        include_declaration: bool = True,
        current_uri: str | None = None,
    ) -> list[Location]:
        return runtime_find_rule_references(
            self,
            rule_name,
            include_declaration=include_declaration,
            current_uri=current_uri,
        )

    def find_rule_reference_records(
        self,
        rule_name: str,
        *,
        include_declaration: bool = True,
        current_uri: str | None = None,
    ) -> list[ReferenceRecord]:
        return runtime_find_rule_reference_records(
            self,
            rule_name,
            include_declaration=include_declaration,
            current_uri=current_uri,
        )

    def find_rule_reference_records_in_document(
        self,
        rule_name: str,
        document_uri: str,
        *,
        include_declaration: bool = True,
        current_uri: str | None = None,
    ) -> list[ReferenceRecord]:
        return runtime_find_rule_reference_records_in_document(
            self,
            rule_name,
            document_uri,
            include_declaration=include_declaration,
            current_uri=current_uri,
        )

    def get_rule_link_records_for_document(self, document_uri: str) -> list[RuleLinkRecord]:
        return runtime_get_rule_link_records_for_document(self, document_uri)

    def rename_rule(self, rule_name: str, new_name: str) -> dict[str, list[TextEdit]]:
        return runtime_rename_rule(self, rule_name, new_name)

    def should_debounce(self, uri: str, task: str, *, debounce_ms: int | None = None) -> bool:
        return runtime_should_debounce(self, uri, task, debounce_ms=debounce_ms)

    def record_latency(self, operation: str, duration_ms: float) -> None:
        runtime_record_latency(self, operation, duration_ms)

    def get_latency_metrics(self) -> dict[str, dict[str, float]]:
        return runtime_get_latency_metrics(self)

    def get_status(self) -> dict[str, object]:
        return runtime_get_status(self)
