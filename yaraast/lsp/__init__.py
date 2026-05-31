"""YARAAST Language Server Protocol implementation."""

from typing import Any

YaraLanguageServer: Any
_OPTIONAL_LSP_DEPENDENCY_ROOTS = ("pygls", "lsprotocol")


def _is_optional_lsp_dependency_error(exc: ImportError) -> bool:
    missing_name = exc.name or ""
    return any(
        missing_name == dependency or missing_name.startswith(f"{dependency}.")
        for dependency in _OPTIONAL_LSP_DEPENDENCY_ROOTS
    )


try:
    from yaraast.lsp.server import YaraLanguageServer
except ImportError as exc:
    if not _is_optional_lsp_dependency_error(exc):
        raise
    YaraLanguageServer = None

__all__ = ["YaraLanguageServer"]
