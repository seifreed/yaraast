"""YARA parser implementation.

Copyright (c) Marc Rivero López
Licensed under GPLv3
https://www.gnu.org/licenses/gpl-3.0.html
"""

from __future__ import annotations

from yaraast.ast.base import YaraFile
from yaraast.errors import ParseError
from yaraast.interfaces import ILexer, IToken
from yaraast.lexer import Lexer, TokenType

from ._expressions import ExpressionParsingMixin
from ._rules import RuleParsingMixin
from ._shared import ParserError
from ._strings import StringParsingMixin
from ._token_stream import TokenStreamMixin


class Parser(
    TokenStreamMixin,
    RuleParsingMixin,
    StringParsingMixin,
    ExpressionParsingMixin,
):
    """YARA parser for building AST from tokens.

    Supports three API styles:
    1. Original: Parser(text).parse()
    2. Reusable: Parser().parse(text)
    3. Dependency Injection: Parser(lexer=my_lexer).parse(text)

    The lexer parameter enables dependency injection for testing
    and adheres to the Dependency Inversion Principle.
    """

    def __init__(
        self,
        text: str | None = None,
        *,
        lexer: ILexer | None = None,
    ) -> None:
        """Initialize parser.

        Args:
            text: Optional YARA code to parse. If provided, parser is ready
                  to call parse(). If None, text must be passed to parse().
            lexer: Optional lexer instance implementing ILexer protocol.
                   If provided, this lexer will be used for tokenization.
                   If None, a default Lexer instance will be created.
                   This enables dependency injection for testing.
        """
        # Store the injected lexer or create a default one
        self._injected_lexer: ILexer | None = lexer
        self.lexer: Lexer | ILexer | None = None
        self.tokens: list[IToken] = []
        self.current = 0

        if text is not None:
            if self._injected_lexer is not None:
                self.lexer = self._injected_lexer
                self.tokens = self.lexer.tokenize(text)
            else:
                self.lexer = Lexer(text)
                self.tokens = self.lexer.tokenize()

    def parse(self, text: str | None = None) -> YaraFile:
        """Parse YARA file and return AST.

        Args:
            text: Optional YARA code to parse. If provided, will tokenize
                  this text. If None, uses text from constructor.

        Returns:
            YaraFile AST
        """
        # Support better_parser.py API: Parser().parse(text)
        if text is not None:
            if self._injected_lexer is not None:
                self.lexer = self._injected_lexer
                self.tokens = self.lexer.tokenize(text)
            else:
                self.lexer = Lexer(text)
                self.tokens = self.lexer.tokenize()
            self.current = 0

        # Ensure we have tokens to parse
        if not self.tokens:
            msg = "No text provided to parse"
            raise ParseError(msg)

        imports = []
        includes = []
        rules = []

        while not self._is_at_end():
            if self._match(TokenType.IMPORT):
                imports.append(self._parse_import())
            elif self._match(TokenType.INCLUDE):
                includes.append(self._parse_include())
            elif (
                self._check(TokenType.RULE)
                or self._check(TokenType.PRIVATE)
                or self._check(TokenType.GLOBAL)
            ):
                rules.append(self._parse_rule())
            else:
                msg = f"Unexpected token: {self._peek().value}"
                raise ParserError(
                    msg,
                    self._peek(),
                )

        yara_file = YaraFile(imports=imports, includes=includes, rules=rules)
        if imports or includes or rules:
            start_node = imports[0] if imports else includes[0] if includes else rules[0]
            end_node = rules[-1] if rules else includes[-1] if includes else imports[-1]
            self._set_node_location_from_nodes(yara_file, start_node, end_node)
        return yara_file
