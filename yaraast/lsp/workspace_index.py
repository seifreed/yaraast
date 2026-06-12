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
)

logger = logging.getLogger(__name__)


def _normalize_workspace_folders(folders: object) -> list[Path]:
    if not isinstance(folders, list) or not all(isinstance(folder, str) for folder in folders):
        msg = "Workspace folders must be a list of strings"
        raise TypeError(msg)
    if any(not folder.strip() for folder in folders):
        msg = "Workspace folder paths must not be empty"
        raise ValueError(msg)
    return [Path(folder) for folder in folders]


def _normalize_excluded_uris(exclude_uris: object) -> set[str]:
    if exclude_uris is None:
        return set()
    if not isinstance(exclude_uris, set) or not all(isinstance(uri, str) for uri in exclude_uris):
        raise TypeError("Excluded workspace symbol URIs must be a set of strings")
    return exclude_uris


class WorkspaceIndex:
    """Workspace-wide view built on top of cached documents."""

    def __init__(self) -> None:
        self.workspace_folders: list[Path] = []
        self.persisted_symbols: dict[str, list[SymbolRecord]] = {}

    def set_workspace_folders(self, folders: list[str]) -> None:
        self.workspace_folders = _normalize_workspace_folders(folders)
        self.load()

    def _cache_path(self) -> Path | None:
        if not self.workspace_folders:
            return None
        root = self.workspace_folders[0]
        if root.is_file():
            root = root.parent
        return root / ".yaraast" / "lsp-workspace-index.json"

    def load(self) -> None:
        cache_path = self._cache_path()
        self.persisted_symbols = {}
        if cache_path is None or not cache_path.exists():
            return
        try:
            payload = json.loads(cache_path.read_text(encoding="utf-8"))
        except Exception:
            logger.debug("Operation failed in %s", __name__, exc_info=True)
            return
        if not isinstance(payload, dict):
            return
        raw_symbols = payload.get("symbols", {})
        if not isinstance(raw_symbols, dict):
            return
        for uri, symbols in raw_symbols.items():
            if not isinstance(uri, str) or not isinstance(symbols, list):
                continue
            self.persisted_symbols[uri] = self._load_symbol_records(uri, symbols)

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
        cache_path = self._cache_path()
        if cache_path is None:
            return
        cache_path.parent.mkdir(parents=True, exist_ok=True)
        payload = {
            "symbols": {
                uri: [symbol.to_dict() for symbol in symbols]
                for uri, symbols in self.persisted_symbols.items()
            }
        }
        cache_path.write_text(json.dumps(payload, indent=2, sort_keys=True), encoding="utf-8")

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
        result: list[SymbolRecord] = []
        for uri, symbols in self.persisted_symbols.items():
            if uri in excluded:
                continue
            for symbol in symbols:
                if query and query_lower not in symbol.name.lower():
                    continue
                result.append(symbol)
        return result

    def iter_candidate_files(self) -> list[Path]:
        files: set[Path] = set()
        for folder in self.workspace_folders:
            if not folder.exists():
                continue
            if folder.is_file() and folder.suffix.lower() in YARA_FILE_SUFFIXES:
                files.add(folder)
                continue
            for suffix in YARA_FILE_SUFFIXES:
                files.update(folder.rglob(f"*{suffix}"))
        return sorted(files)
