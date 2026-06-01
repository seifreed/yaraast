"""Helpers for classifying optional LSP dependency import failures."""

from __future__ import annotations

_OPTIONAL_LSP_IMPORT_NAMES = frozenset(
    {
        "lsprotocol",
        "lsprotocol.types",
        "pygls",
        "pygls.lsp",
        "pygls.lsp.server",
        "pygls.server",
    }
)


def is_missing_lsp_dependency(exc: ImportError) -> bool:
    """Return whether an ImportError means an optional LSP package is absent."""
    return (exc.name or "") in _OPTIONAL_LSP_IMPORT_NAMES
