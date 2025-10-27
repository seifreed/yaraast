"""Semantic tokens provider for YARA Language Server."""

from __future__ import annotations

from typing import TYPE_CHECKING

from lsprotocol.types import SemanticTokens, SemanticTokensLegend, SemanticTokensParams

from yaraast.lexer import Lexer, TokenType

if TYPE_CHECKING:
    pass


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

    @staticmethod
    def get_legend() -> SemanticTokensLegend:
        """Get the semantic tokens legend."""
        return SemanticTokensLegend(
            token_types=TOKEN_TYPES,
            token_modifiers=TOKEN_MODIFIERS,
        )

    def get_semantic_tokens(self, text: str) -> SemanticTokens:
        """
        Get semantic tokens for the document.

        Args:
            text: The YARA source code

        Returns:
            SemanticTokens with token information
        """
        tokens_data = []

        try:
            lexer = Lexer(text)
            tokens = lexer.tokenize()

            prev_line = 0
            prev_char = 0

            for token in tokens:
                if token.type == TokenType.EOF:
                    break

                token_type = self._map_token_type(token.type)
                if token_type is None:
                    continue

                # Calculate delta encoding
                delta_line = token.line - 1 - prev_line  # Convert to 0-based
                delta_char = token.column if delta_line > 0 else token.column - prev_char

                # Length of token
                length = len(str(token.value))

                # Token type index
                token_type_idx = TOKEN_TYPES.index(token_type)

                # Token modifiers (bitmask)
                modifiers = 0

                # Append: [deltaLine, deltaChar, length, tokenType, tokenModifiers]
                tokens_data.extend(
                    [
                        delta_line,
                        delta_char,
                        length,
                        token_type_idx,
                        modifiers,
                    ]
                )

                prev_line = token.line - 1
                prev_char = token.column

        except Exception:
            # If tokenization fails, return empty tokens
            pass

        return SemanticTokens(data=tokens_data)

    def _map_token_type(self, token_type: TokenType) -> str | None:
        """Map YARA token type to LSP semantic token type."""
        mapping = {
            # Keywords
            TokenType.RULE: "keyword",
            TokenType.PRIVATE: "keyword",
            TokenType.GLOBAL: "keyword",
            TokenType.META: "keyword",
            TokenType.STRINGS: "keyword",
            TokenType.CONDITION: "keyword",
            TokenType.IMPORT: "keyword",
            TokenType.INCLUDE: "keyword",
            TokenType.AND: "keyword",
            TokenType.OR: "keyword",
            TokenType.NOT: "keyword",
            TokenType.ALL: "keyword",
            TokenType.ANY: "keyword",
            TokenType.OF: "keyword",
            TokenType.THEM: "keyword",
            TokenType.FOR: "keyword",
            TokenType.IN: "keyword",
            TokenType.AT: "keyword",
            TokenType.FILESIZE: "keyword",
            TokenType.ENTRYPOINT: "keyword",
            TokenType.DEFINED: "keyword",
            # Literals
            TokenType.STRING: "string",
            TokenType.INTEGER: "number",
            TokenType.DOUBLE: "number",
            TokenType.REGEX: "regexp",
            TokenType.HEX_STRING: "string",
            TokenType.BOOLEAN_TRUE: "keyword",
            TokenType.BOOLEAN_FALSE: "keyword",
            # Identifiers
            TokenType.IDENTIFIER: "variable",
            TokenType.STRING_IDENTIFIER: "variable",
            TokenType.STRING_COUNT: "variable",
            TokenType.STRING_OFFSET: "variable",
            TokenType.STRING_LENGTH: "variable",
            # Operators
            TokenType.EQ: "operator",
            TokenType.NEQ: "operator",
            TokenType.LT: "operator",
            TokenType.LE: "operator",
            TokenType.GT: "operator",
            TokenType.GE: "operator",
            TokenType.PLUS: "operator",
            TokenType.MINUS: "operator",
            TokenType.MULTIPLY: "operator",
            TokenType.DIVIDE: "operator",
            TokenType.MODULO: "operator",
            TokenType.BITWISE_AND: "operator",
            TokenType.BITWISE_OR: "operator",
            TokenType.BITWISE_NOT: "operator",
            TokenType.XOR: "operator",
            TokenType.SHIFT_LEFT: "operator",
            TokenType.SHIFT_RIGHT: "operator",
            # Comments
            TokenType.COMMENT: "comment",
            # String modifiers
            TokenType.NOCASE: "property",
            TokenType.WIDE: "property",
            TokenType.ASCII: "property",
            TokenType.XOR_MOD: "property",
            TokenType.BASE64: "property",
            TokenType.BASE64WIDE: "property",
            TokenType.FULLWORD: "property",
        }

        return mapping.get(token_type)
