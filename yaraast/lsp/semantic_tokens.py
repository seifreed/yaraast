"""Semantic tokens provider for YARA Language Server."""

from __future__ import annotations

import logging
import time

from lsprotocol.types import Range, SemanticTokens, SemanticTokensLegend

from yaraast.lexer.lexer import Lexer
from yaraast.lexer.tokens import Token, TokenType
from yaraast.lsp.runtime import LspRuntime
from yaraast.lsp.semantic_tokens_helpers import (
    encode_tokens,
    encode_tokens_in_range,
    map_token_type,
)

logger = logging.getLogger(__name__)

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


def _copy_semantic_tokens(tokens: SemanticTokens) -> SemanticTokens:
    return SemanticTokens(data=list(tokens.data), result_id=tokens.result_id)


def _require_range(value: object) -> Range:
    if not isinstance(value, Range):
        msg = "range_ must be an LSP Range"
        raise TypeError(msg)
    return value


def _require_text(value: object) -> str:
    if not isinstance(value, str):
        msg = "Semantic token text must be a string"
        raise TypeError(msg)
    return value


def _require_uri(value: object) -> str | None:
    if value is not None and not isinstance(value, str):
        msg = "Semantic token URI must be a string or None"
        raise TypeError(msg)
    return value


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
        text = _require_text(text)
        uri = _require_uri(uri)
        ctx = self.runtime.ensure_document(uri, text) if self.runtime and uri else None
        if ctx is not None:
            cached = ctx.get_cached("semantic_tokens:full")
            if cached is not None:
                return _copy_semantic_tokens(cached)

        tokens_data = []
        started = time.perf_counter()
        tokenization_succeeded = False

        try:
            lexer: Lexer[list[Token]] = Lexer[list[Token]](text)
            tokens = lexer.tokenize()
            tokens_data = encode_tokens(tokens, self._map_token_type, TOKEN_TYPES, text)
            tokenization_succeeded = True

        except Exception:
            logger.debug("Operation failed in %s", __name__, exc_info=True)
            # If tokenization fails, return empty tokens

        result = SemanticTokens(data=tokens_data)
        if ctx is not None and tokenization_succeeded:
            ctx.set_cached("semantic_tokens:full", result)
        if self.runtime is not None:
            self.runtime.record_latency(
                "semantic_tokens_full", (time.perf_counter() - started) * 1000.0
            )
        return _copy_semantic_tokens(result)

    def get_semantic_tokens_range(
        self, text: str, range_: Range, uri: str | None = None
    ) -> SemanticTokens:
        """Get semantic tokens for a specific range."""
        text = _require_text(text)
        range_ = _require_range(range_)
        uri = _require_uri(uri)
        ctx = self.runtime.ensure_document(uri, text) if self.runtime and uri else None
        cache_key = None
        if ctx is not None:
            cache_key = (
                f"semantic_tokens:range:{range_.start.line}:{range_.start.character}:"
                f"{range_.end.line}:{range_.end.character}"
            )
            cached = ctx.get_cached(cache_key)
            if cached is not None:
                return _copy_semantic_tokens(cached)

        tokens_data = []
        started = time.perf_counter()
        tokenization_succeeded = False

        try:
            lexer: Lexer[list[Token]] = Lexer[list[Token]](text)
            tokens = lexer.tokenize()
            tokens_data = encode_tokens_in_range(
                tokens, range_, self._map_token_type, TOKEN_TYPES, text
            )
            tokenization_succeeded = True

        except Exception:
            logger.debug("Operation failed in %s", __name__, exc_info=True)

        result = SemanticTokens(data=tokens_data)
        if ctx is not None and cache_key is not None and tokenization_succeeded:
            ctx.set_cached(cache_key, result)
        if self.runtime is not None:
            self.runtime.record_latency(
                "semantic_tokens_range", (time.perf_counter() - started) * 1000.0
            )
        return _copy_semantic_tokens(result)

    def _map_token_type(self, token_type: TokenType) -> str | None:
        return map_token_type(token_type)
