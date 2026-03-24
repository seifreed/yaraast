"""Shared language services for LSP providers."""

from __future__ import annotations

import logging

from yaraast.lsp.safe_handler import lsp_safe_handler
from yaraast.parser.parser import Parser

logger = logging.getLogger(__name__)


@lsp_safe_handler
def parse_source(text: str):
    """Parse source text for reuse across providers.

    Note: No caching — lru_cache previously cached None on parse failures,
    making error recovery impossible until cache eviction.
    """
    parser = Parser(text)
    return parser.parse()
