"""Workspace symbols provider for YARAAST LSP."""

from __future__ import annotations

import logging
from pathlib import Path

from lsprotocol.types import SymbolInformation

from yaraast.lsp.runtime import DocumentContext, LspRuntime, path_to_uri

logger = logging.getLogger(__name__)


class WorkspaceSymbolsProvider:
    """Provide workspace-wide symbol search."""

    def __init__(self, runtime: LspRuntime | None = None) -> None:
        """Initialize workspace symbols provider."""
        self.runtime = runtime
        self.symbol_cache: dict[str, tuple[float, list[SymbolInformation]]] = {}
        self.workspace_root: Path | None = None

    def set_workspace_root(self, root_path: str) -> None:
        """Set the workspace root directory."""
        self.workspace_root = Path(root_path)

    def get_workspace_symbols(self, query: str) -> list[SymbolInformation]:
        """Search for symbols across the entire workspace."""
        if self.runtime:
            return self.runtime.workspace_symbols(query)
        if not self.workspace_root or not self.workspace_root.exists():
            return []

        symbols = []

        # Find all YARA files in workspace
        yara_files = list(self.workspace_root.rglob("*.yar")) + list(
            self.workspace_root.rglob("*.yara")
        )

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
                return cached_symbols

        # Parse file and extract symbols
        symbols = []

        try:
            with open(file_path) as f:
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
            self.symbol_cache[cache_key] = (mtime, symbols)

        except Exception:
            logger.debug("Operation failed in %s", __name__, exc_info=True)
            # Return empty list if parsing fails
            pass

        return symbols

    def clear_cache(self) -> None:
        """Clear the symbol cache."""
        if self.runtime:
            return
        self.symbol_cache.clear()

    def invalidate_file(self, file_path: str) -> None:
        """Invalidate cache for a specific file."""
        if self.runtime:
            return
        if file_path in self.symbol_cache:
            del self.symbol_cache[file_path]
