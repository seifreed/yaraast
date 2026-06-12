"""Workspace symbols provider for YARAAST LSP."""

from __future__ import annotations

import logging
from os import PathLike, fspath
from pathlib import Path

from lsprotocol.types import SymbolInformation

from yaraast.lsp.document_types import YARA_FILE_SUFFIXES
from yaraast.lsp.runtime import DocumentContext, LspRuntime, path_to_uri

logger = logging.getLogger(__name__)


def _path_access_error(path: Path) -> ValueError:
    msg = f"path could not be accessed: {path}"
    return ValueError(msg)


def _path_exists(path: Path) -> bool:
    try:
        return path.exists()
    except OSError as exc:
        raise _path_access_error(path) from exc


def _path_is_dir(path: Path) -> bool:
    try:
        return path.is_dir()
    except OSError as exc:
        raise _path_access_error(path) from exc


def _path_exists_and_not_dir(path: Path) -> bool:
    return _path_exists(path) and not _path_is_dir(path)


def _require_workspace_root(root_path: object) -> Path:
    if isinstance(root_path, bool | bytes) or not isinstance(root_path, str | PathLike):
        msg = "root_path must be a string or path-like object"
        raise TypeError(msg)
    raw_path = fspath(root_path)
    if not isinstance(raw_path, str):
        msg = "root_path must be a string or path-like object"
        raise TypeError(msg)
    if not raw_path.strip():
        msg = "root_path must not be empty"
        raise ValueError(msg)
    path = Path(raw_path)
    if _path_exists_and_not_dir(path):
        msg = "root_path must not be a file"
        raise ValueError(msg)
    return path


def _require_cache_file_path(file_path: object) -> str:
    if isinstance(file_path, bool | bytes) or not isinstance(file_path, str | PathLike):
        msg = "file_path must be a string or path-like object"
        raise TypeError(msg)
    raw_path = fspath(file_path)
    if not isinstance(raw_path, str):
        msg = "file_path must be a string or path-like object"
        raise TypeError(msg)
    if not raw_path.strip():
        msg = "file_path must not be empty"
        raise ValueError(msg)
    return raw_path


class WorkspaceSymbolsProvider:
    """Provide workspace-wide symbol search."""

    def __init__(self, runtime: LspRuntime | None = None) -> None:
        """Initialize workspace symbols provider."""
        self.runtime = runtime
        self.symbol_cache: dict[str, tuple[float, list[SymbolInformation]]] = {}
        self.workspace_root: Path | None = None

    def set_workspace_root(self, root_path: str | PathLike[str]) -> None:
        """Set the workspace root directory."""
        self.workspace_root = _require_workspace_root(root_path)

    def get_workspace_symbols(self, query: object) -> list[SymbolInformation]:
        """Search for symbols across the entire workspace."""
        if not isinstance(query, str):
            raise TypeError("Workspace symbol query must be a string")
        if self.runtime:
            return self.runtime.workspace_symbols(query)
        if not self.workspace_root or not _path_exists(self.workspace_root):
            return []

        symbols = []

        # Find all YARA files in workspace
        yara_files = [
            path
            for suffix in YARA_FILE_SUFFIXES
            for path in self.workspace_root.rglob(f"*{suffix}")
        ]

        for yara_file in yara_files:
            try:
                # Get symbols from this file
                file_symbols = self._get_symbols_from_file(yara_file)

                # Filter by query (case-insensitive substring match)
                if query:
                    query_lower = query.lower()
                    file_symbols = [sym for sym in file_symbols if query_lower in sym.name.lower()]

                symbols.extend(file_symbols)

            except Exception:
                logger.debug("Operation failed in %s", __name__, exc_info=True)
                # Skip files that fail to parse
                continue

        return symbols

    def _get_symbols_from_file(self, file_path: Path) -> list[SymbolInformation]:
        """Extract all symbols from a YARA file."""
        # Check cache first
        cache_key = str(file_path)
        mtime = file_path.stat().st_mtime

        if cache_key in self.symbol_cache:
            cached_mtime, cached_symbols = self.symbol_cache[cache_key]
            if cached_mtime == mtime:
                return list(cached_symbols)

        # Parse file and extract symbols
        symbols = []

        try:
            with open(file_path, encoding="utf-8") as f:
                content = f.read()

            file_uri = path_to_uri(file_path)
            doc = DocumentContext(file_uri, content)
            for record in doc.symbols():
                if record.kind not in {"rule", "string"}:
                    continue
                info = record.to_symbol_information()
                if record.kind == "rule":
                    info = SymbolInformation(
                        name=info.name,
                        kind=info.kind,
                        location=info.location,
                        container_name=file_path.name,
                    )
                elif record.kind == "string":
                    info = SymbolInformation(
                        name=info.name,
                        kind=info.kind,
                        location=info.location,
                        container_name=f"{file_path.name} :: {record.container_name}",
                    )
                symbols.append(info)

            # Cache results
            self.symbol_cache[cache_key] = (mtime, list(symbols))

        except Exception:
            logger.debug("Operation failed in %s", __name__, exc_info=True)
            # Return empty list if parsing fails
            pass

        return list(symbols)

    def clear_cache(self) -> None:
        """Clear the symbol cache."""
        if self.runtime:
            self.runtime.cache.workspace_symbol_cache.clear()
            return
        self.symbol_cache.clear()

    def invalidate_file(self, file_path: str | PathLike[str]) -> None:
        """Invalidate cache for a specific file."""
        cache_key = _require_cache_file_path(file_path)
        if self.runtime:
            self.runtime.cache.workspace_symbol_cache.clear()
            return
        if cache_key in self.symbol_cache:
            del self.symbol_cache[cache_key]
