"""Shared language services for LSP providers."""

from __future__ import annotations

from yaraast.parser.parser import Parser


def parse_source(text: str):
    """Parse source text for reuse across providers.

    Note: No caching — lru_cache previously cached None on parse failures,
    making error recovery impossible until cache eviction.
    """
    try:
        parser = Parser(text)
        return parser.parse()
    except Exception:
        return None
