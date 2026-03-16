"""Parser construction helpers for CLI modules."""

from __future__ import annotations

from yaraast import Parser


def create_parser() -> Parser:
    """Create a parser instance for CLI helpers."""
    return Parser()
