"""Persistent workspace symbol index for LSP."""

from __future__ import annotations

import json
import logging
from pathlib import Path

from lsprotocol.types import SymbolInformation

from yaraast.lsp.document_context import DocumentContext
from yaraast.lsp.document_types import (
    YARA_FILE_SUFFIXES,
    SymbolRecord,
    require_workspace_symbol_query,
    uri_to_path,
)
from yaraast.lsp.utils import path_exists, path_is_dir, path_is_file
from yaraast.shared.path_safety import path_is_symlink, path_is_within_directory

logger = logging.getLogger(__name__)


def _normalize_workspace_folders(folders: object) -> list[Path]:
    if not isinstance(folders, list) or not all(isinstance(folder, str) for folder in folders):
        msg = "Workspace folders must be a list of strings"
        raise TypeError(msg)
    if any(not folder.strip() for folder in folders):
        msg = "Workspace folder paths must not be empty"
        raise ValueError(msg)
    normalized = [Path(folder) for folder in folders]
    if any(path_is_symlink(folder) for folder in normalized):
        msg = "Workspace folder paths must not be a symlink"
        raise ValueError(msg)
    return normalized


def _normalize_excluded_uris(exclude_uris: object) -> set[str]:
    if exclude_uris is None:
        return set()
    if not isinstance(exclude_uris, set) or not all(isinstance(uri, str) for uri in exclude_uris):
        raise TypeError("Excluded workspace symbol URIs must be a set of strings")
    return exclude_uris


def _validated_persisted_symbols(value: object) -> dict[str, list[SymbolRecord]]:
    if not isinstance(value, dict):
        msg = "Workspace index persisted_symbols must be a dictionary"
        raise TypeError(msg)
    records: dict[str, list[SymbolRecord]] = {}
    for uri, symbols in value.items():
        if not isinstance(uri, str):
            msg = "Workspace index URI must be a string"
            raise TypeError(msg)
        if not isinstance(symbols, list):
            msg = "Workspace index symbols must be a list"
            raise TypeError(msg)
        for symbol in symbols:
            if not isinstance(symbol, SymbolRecord):
                msg = "Workspace index symbol must be a SymbolRecord"
                raise TypeError(msg)
        records[uri] = list(symbols)
    return records


class WorkspaceIndex:
    """Workspace-wide view built on top of cached documents."""

    def __init__(self) -> None:
        self.workspace_folders: list[Path] = []
        self.persisted_symbols: dict[str, list[SymbolRecord]] = {}

    def set_workspace_folders(self, folders: list[str]) -> None:
        self.workspace_folders = _normalize_workspace_folders(folders)
        self.load()

    def _cache_paths(self) -> list[Path]:
        cache_paths: list[Path] = []
        seen: set[Path] = set()
        for root in self.workspace_folders:
            cache_path = self._cache_path_for_root(root)
            if not self._cache_path_is_safe(root):
                continue
            if cache_path in seen:
                continue
            seen.add(cache_path)
            cache_paths.append(cache_path)
        return cache_paths

    def _cache_path_for_root(self, root: Path) -> Path:
        if path_is_file(root):
            root = root.parent
        return root / ".yaraast" / "lsp-workspace-index.json"

    def _cache_root_for_root(self, root: Path) -> Path:
        if path_is_file(root):
            return root.parent
        return root

    def _cache_path_is_safe(self, root: Path) -> bool:
        return path_is_within_directory(
            self._cache_path_for_root(root),
            self._cache_root_for_root(root),
        )

    def _workspace_root_for_uri(self, uri: str) -> Path | None:
        path = uri_to_path(uri)
        if path is None:
            return None
        return self._workspace_root_for_path(path)

    def _workspace_root_for_path(self, path: Path) -> Path | None:
        resolved_path = path.resolve()
        best_root: Path | None = None
        best_length = -1
        for root in self.workspace_folders:
            if not self._workspace_root_matches_path(resolved_path, root):
                continue
            resolved_root = root.resolve()
            root_length = len(str(resolved_root))
            if root_length > best_length:
                best_root = root
                best_length = root_length
        return best_root

    def _workspace_root_matches_path(self, path: Path, root: Path) -> bool:
        try:
            resolved_root = root.resolve()
        except OSError:
            return False
        if path_is_file(root):
            return path == resolved_root
        return path == resolved_root or path.is_relative_to(resolved_root)

    def _cache_payloads(self) -> dict[Path, dict[str, list[SymbolRecord]]]:
        payloads: dict[Path, dict[str, list[SymbolRecord]]] = {}
        for uri, symbols in self.persisted_symbols.items():
            root = self._workspace_root_for_uri(uri)
            if root is None:
                continue
            cache_path = self._cache_path_for_root(root)
            root_payload = payloads.setdefault(cache_path, {})
            root_payload[uri] = list(symbols)
        return payloads

    def load(self) -> None:
        self.persisted_symbols = {}
        for cache_path in self._cache_paths():
            if not path_exists(cache_path):
                continue
            try:
                payload = json.loads(cache_path.read_text(encoding="utf-8"))
            except Exception:
                logger.debug("Operation failed in %s", __name__, exc_info=True)
                continue
            if not isinstance(payload, dict):
                continue
            raw_symbols = payload.get("symbols", {})
            if not isinstance(raw_symbols, dict):
                continue
            for uri, symbols in raw_symbols.items():
                if not isinstance(uri, str) or not isinstance(symbols, list):
                    continue
                uri_path = uri_to_path(uri)
                if uri_path is not None and not path_exists(uri_path):
                    continue
                root = self._workspace_root_for_uri(uri)
                if root is not None and self._cache_path_for_root(root) != cache_path:
                    continue
                loaded_symbols = self._load_symbol_records(uri, symbols)
                if not loaded_symbols:
                    continue
                self.persisted_symbols.setdefault(uri, []).extend(loaded_symbols)

    def _load_symbol_records(self, uri: str, symbols: list[object]) -> list[SymbolRecord]:
        records: list[SymbolRecord] = []
        for symbol in symbols:
            if not isinstance(symbol, dict):
                continue
            try:
                record = SymbolRecord.from_dict(symbol)
            except Exception:
                logger.debug("Operation failed in %s", __name__, exc_info=True)
                continue
            if record.uri == uri:
                records.append(record)
        return records

    def save(self) -> None:
        persisted_symbols = _validated_persisted_symbols(self.persisted_symbols)
        payloads = self._cache_payloads()
        for cache_path in self._cache_paths():
            payload_symbols = payloads.get(cache_path, {})
            payload = {
                "symbols": {
                    uri: [symbol.to_dict() for symbol in symbols]
                    for uri, symbols in payload_symbols.items()
                    if uri in persisted_symbols
                }
            }
            try:
                cache_path.parent.mkdir(parents=True, exist_ok=True)
                cache_path.write_text(
                    json.dumps(payload, indent=2, sort_keys=True),
                    encoding="utf-8",
                )
            except OSError:
                logger.debug("Operation failed in %s", __name__, exc_info=True)

    def update_document(self, document: DocumentContext) -> None:
        if not isinstance(document, DocumentContext):
            msg = "Workspace index document must be a DocumentContext"
            raise TypeError(msg)
        self.persisted_symbols[document.uri] = list(document.symbols())
        self.save()

    def remove_document(self, uri: str) -> None:
        if not isinstance(uri, str):
            msg = "Workspace index URI must be a string"
            raise TypeError(msg)
        self.persisted_symbols.pop(uri, None)
        self.save()

    def search(self, query: object) -> list[SymbolInformation]:
        return [symbol.to_symbol_information() for symbol in self.search_records(query)]

    def search_records(
        self,
        query: object,
        *,
        exclude_uris: object = None,
    ) -> list[SymbolRecord]:
        query = require_workspace_symbol_query(query)
        query_lower = query.lower()
        excluded = _normalize_excluded_uris(exclude_uris)
        hidden_kinds = {"rule_block", "section_header"}
        result: list[SymbolRecord] = []
        for uri, symbols in self.persisted_symbols.items():
            if uri in excluded:
                continue
            uri_path = uri_to_path(uri)
            if (
                self.workspace_folders
                and uri_path is not None
                and path_exists(uri_path)
                and self._workspace_root_for_uri(uri) is None
            ):
                continue
            for symbol in symbols:
                if symbol.kind in hidden_kinds:
                    continue
                if query and query_lower not in symbol.name.lower():
                    continue
                result.append(symbol)
        return result

    def iter_candidate_files(self) -> list[Path]:
        files: set[Path] = set()
        for folder in self.workspace_folders:
            if not path_exists(folder):
                continue
            if path_is_file(folder) and folder.suffix.lower() in YARA_FILE_SUFFIXES:
                try:
                    files.add(folder.resolve())
                except OSError:
                    continue
                continue
            if not path_is_dir(folder):
                continue
            for suffix in YARA_FILE_SUFFIXES:
                try:
                    for path in folder.rglob(f"*{suffix}"):
                        if not path.is_file():
                            continue
                        try:
                            resolved_path = path.resolve()
                        except OSError:
                            continue
                        if path_is_within_directory(resolved_path, folder):
                            files.add(resolved_path)
                except OSError:
                    logger.debug("Operation failed in %s", __name__, exc_info=True)
        return sorted(files)
