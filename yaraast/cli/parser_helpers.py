"""Parser construction helpers for CLI modules."""

from __future__ import annotations

from yaraast.parser.parser import Parser
from yaraast.parser.source import parse_yara_source


def create_parser() -> Parser:
    """Create a parser instance for CLI helpers."""
    return Parser()


__all__ = ["create_parser", "parse_yara_source"]
