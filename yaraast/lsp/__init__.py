"""YARAAST Language Server Protocol implementation."""

from typing import Any

from yaraast.lsp.optional_dependencies import is_missing_lsp_dependency

YaraLanguageServer: Any


try:
    from yaraast.lsp.server import YaraLanguageServer
except ImportError as exc:
    if not is_missing_lsp_dependency(exc):
        raise
    YaraLanguageServer = None

__all__ = ["YaraLanguageServer"]
