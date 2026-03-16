"""Semantic tokens provider for YARA Language Server."""

from __future__ import annotations

import time

from lsprotocol.types import Range, SemanticTokens, SemanticTokensLegend

from yaraast.lexer.lexer import Lexer
from yaraast.lexer.tokens import TokenType
from yaraast.lsp.runtime import LspRuntime
from yaraast.lsp.semantic_tokens_helpers import encode_tokens as helper_encode_tokens
from yaraast.lsp.semantic_tokens_helpers import (
    encode_tokens_in_range as helper_encode_tokens_in_range,
)
from yaraast.lsp.semantic_tokens_helpers import map_token_type as helper_map_token_type

# Define semantic token types and modifiers according to LSP spec
TOKEN_TYPES = [
    "namespace",  # 0
    "class",  # 1 - rules
    "enum",  # 2
    "interface",  # 3
    "struct",  # 4
    "typeParameter",  # 5
    "type",  # 6
    "parameter",  # 7
    "variable",  # 8 - string identifiers
    "property",  # 9 - meta keys
    "enumMember",  # 10
    "decorator",  # 11
    "event",  # 12
    "function",  # 13 - builtin functions
    "method",  # 14
    "macro",  # 15
    "label",  # 16
    "comment",  # 17
    "string",  # 18
    "keyword",  # 19
    "number",  # 20
    "regexp",  # 21
    "operator",  # 22
]

TOKEN_MODIFIERS = [
    "declaration",  # 0
    "definition",  # 1
    "readonly",  # 2
    "static",  # 3
    "deprecated",  # 4
    "abstract",  # 5
    "async",  # 6
    "modification",  # 7
    "documentation",  # 8
    "defaultLibrary",  # 9
]


class SemanticTokensProvider:
    """Provides semantic tokens for advanced syntax highlighting."""

    def __init__(self, runtime: LspRuntime | None = None) -> None:
        self.runtime = runtime

    @staticmethod
    def get_legend() -> SemanticTokensLegend:
        """Get the semantic tokens legend."""
        return SemanticTokensLegend(
            token_types=TOKEN_TYPES,
            token_modifiers=TOKEN_MODIFIERS,
        )

    def get_semantic_tokens(self, text: str, uri: str | None = None) -> SemanticTokens:
        """
        Get semantic tokens for the document.

        Args:
            text: The YARA source code

        Returns:
            SemanticTokens with token information
        """
        ctx = self.runtime.ensure_document(uri, text) if self.runtime and uri else None
        if ctx is not None:
            cached = ctx.get_cached("semantic_tokens:full")
            if cached is not None:
                return cached

        tokens_data = []
        started = time.perf_counter()

        try:
            lexer = Lexer(text)
            tokens = lexer.tokenize()
            tokens_data = helper_encode_tokens(tokens, self._map_token_type, TOKEN_TYPES)

        except Exception:
            # If tokenization fails, return empty tokens
            pass

        result = SemanticTokens(data=tokens_data)
        if ctx is not None:
            ctx.set_cached("semantic_tokens:full", result)
        if self.runtime is not None:
            self.runtime.record_latency(
                "semantic_tokens_full", (time.perf_counter() - started) * 1000.0
            )
        return result

    def get_semantic_tokens_range(
        self, text: str, range_: Range, uri: str | None = None
    ) -> SemanticTokens:
        """Get semantic tokens for a specific range."""
        ctx = self.runtime.ensure_document(uri, text) if self.runtime and uri else None
        cache_key = None
        if ctx is not None:
            cache_key = (
                f"semantic_tokens:range:{range_.start.line}:{range_.start.character}:"
                f"{range_.end.line}:{range_.end.character}"
            )
            cached = ctx.get_cached(cache_key)
            if cached is not None:
                return cached

        tokens_data = []
        started = time.perf_counter()

        try:
            lexer = Lexer(text)
            tokens = lexer.tokenize()
            tokens_data = helper_encode_tokens_in_range(
                tokens, range_, self._map_token_type, TOKEN_TYPES
            )

        except Exception:
            pass

        result = SemanticTokens(data=tokens_data)
        if ctx is not None and cache_key is not None:
            ctx.set_cached(cache_key, result)
        if self.runtime is not None:
            self.runtime.record_latency(
                "semantic_tokens_range", (time.perf_counter() - started) * 1000.0
            )
        return result

    def _map_token_type(self, token_type: TokenType) -> str | None:
        return helper_map_token_type(token_type)
