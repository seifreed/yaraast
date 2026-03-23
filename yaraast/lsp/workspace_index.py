"""Persistent workspace symbol index for LSP."""

from __future__ import annotations

import json
import logging
from pathlib import Path

from lsprotocol.types import SymbolInformation

from yaraast.lsp.document_context import DocumentContext
from yaraast.lsp.document_types import SymbolRecord

logger = logging.getLogger(__name__)


class WorkspaceIndex:
    """Workspace-wide view built on top of cached documents."""

    def __init__(self) -> None:
        self.workspace_folders: list[Path] = []
        self.persisted_symbols: dict[str, list[SymbolRecord]] = {}

    def set_workspace_folders(self, folders: list[str]) -> None:
        self.workspace_folders = [Path(folder) for folder in folders if folder]
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
        raw_symbols = payload.get("symbols", {})
        if not isinstance(raw_symbols, dict):
            return
        for uri, symbols in raw_symbols.items():
            if not isinstance(uri, str) or not isinstance(symbols, list):
                continue
            self.persisted_symbols[uri] = [
                SymbolRecord.from_dict(symbol) for symbol in symbols if isinstance(symbol, dict)
            ]

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
        self.persisted_symbols[document.uri] = list(document.symbols())
        self.save()

    def remove_document(self, uri: str) -> None:
        self.persisted_symbols.pop(uri, None)
        self.save()

    def search(self, query: str) -> list[SymbolInformation]:
        return [symbol.to_symbol_information() for symbol in self.search_records(query)]

    def search_records(
        self,
        query: str,
        *,
        exclude_uris: set[str] | None = None,
    ) -> list[SymbolRecord]:
        query_lower = query.lower()
        excluded = exclude_uris or set()
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
            if folder.is_file() and folder.suffix in {".yar", ".yara"}:
                files.add(folder)
                continue
            files.update(folder.rglob("*.yar"))
            files.update(folder.rglob("*.yara"))
        return sorted(files)
