"""Lexer interface for dependency injection.

Copyright (c) Marc Rivero Lopez
Licensed under GPLv3
https://www.gnu.org/licenses/gpl-3.0.html
"""

from typing import Protocol

from yaraast.interfaces.token_interface import IToken


class ILexer(Protocol):
    """Protocol interface for YARA lexers.

    This interface enables dependency injection and allows mocking
    the lexer in tests. Any class that implements the tokenize method
    with the correct signature will satisfy this protocol.

    Example:
        class MockLexer:
            def tokenize(self, text: str) -> list[IToken]:
                ...

        # MockLexer implicitly satisfies ILexer
        parser = Parser(lexer=MockLexer())
    """

    def tokenize(self, text: str) -> list[IToken]:
        """Tokenize the input text and return list of tokens.

        Args:
            text: The YARA source code to tokenize.

        Returns:
            A list of token-like objects representing the tokenized input.
            The list should always end with an EOF token.
        """
        ...
