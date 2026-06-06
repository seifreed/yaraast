"""Shared language services for LSP providers."""

from __future__ import annotations

import logging
from typing import Any

from yaraast.lsp.safe_handler import lsp_safe_handler
from yaraast.unified_parser import UnifiedParser

logger = logging.getLogger(__name__)


def parse_source(text: str) -> Any:
    """Parse source text for reuse across providers.

    Note: No caching — lru_cache previously cached None on parse failures,
    making error recovery impossible until cache eviction.
    """
    if not isinstance(text, str):
        msg = "LSP parse source text must be a string"
        raise TypeError(msg)
    return _parse_source_safe(text)


@lsp_safe_handler
def _parse_source_safe(text: str) -> Any:
    return UnifiedParser(text).parse()
