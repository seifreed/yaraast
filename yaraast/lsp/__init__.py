"""YARAAST Language Server Protocol implementation."""

try:
    from yaraast.lsp.server import YaraLanguageServer
except Exception:
    YaraLanguageServer = None  # type: ignore[assignment]

__all__ = ["YaraLanguageServer"]
