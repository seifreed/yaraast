"""YARAAST Language Server Protocol implementation."""

from typing import Any

YaraLanguageServer: Any

try:
    from yaraast.lsp.server import YaraLanguageServer
except ImportError:
    YaraLanguageServer = None

__all__ = ["YaraLanguageServer"]
