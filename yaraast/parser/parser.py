"""YARA parser implementation.

Copyright (c) Marc Rivero López
Licensed under GPLv3
https://www.gnu.org/licenses/gpl-3.0.html
"""

from __future__ import annotations

from collections.abc import Sequence

from yaraast.ast.base import YaraFile
from yaraast.ast.extern import ExternImport
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
        self.tokens: Sequence[IToken] = []
        self.current = 0
        self._extern_rule_names: set[tuple[str | None, str]] = set()

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
        else:
            self.current = 0

        # Ensure we have tokens to parse
        if not self.tokens:
            msg = "No text provided to parse"
            raise ParseError(msg)

        imports = []
        includes = []
        rules = []
        extern_imports = []
        extern_rules = []
        namespaces = []
        pragmas = []
        top_level_nodes = []
        self._extern_rule_names = set()

        while not self._is_at_end():
            if self._check_file_pragma():
                pragma = self._parse_file_pragma()
                pragmas.append(pragma)
                top_level_nodes.append(pragma)
            elif self._match(TokenType.IMPORT):
                parsed_import = self._parse_import()
                if isinstance(parsed_import, ExternImport):
                    extern_imports.append(parsed_import)
                    self._register_extern_import(parsed_import)
                else:
                    imports.append(parsed_import)
                top_level_nodes.append(parsed_import)
            elif self._match(TokenType.INCLUDE):
                include = self._parse_include()
                includes.append(include)
                top_level_nodes.append(include)
            elif self._check_identifier_value("namespace"):
                namespace = self._parse_extern_namespace()
                namespaces.append(namespace)
                top_level_nodes.append(namespace)
            elif self._check_identifier_value("extern"):
                extern_rule = self._parse_extern_rule()
                extern_rules.append(extern_rule)
                self._register_extern_rule(extern_rule)
                top_level_nodes.append(extern_rule)
            elif (
                self._check(TokenType.RULE)
                or self._check(TokenType.PRIVATE)
                or self._check(TokenType.GLOBAL)
            ):
                rule = self._parse_rule()
                rules.append(rule)
                top_level_nodes.append(rule)
            else:
                msg = f"Unexpected token: {self._peek().value}"
                raise ParserError(
                    msg,
                    self._peek(),
                )

        yara_file = YaraFile(
            imports=imports,
            includes=includes,
            rules=rules,
            extern_rules=extern_rules,
            extern_imports=extern_imports,
            pragmas=pragmas,
            namespaces=namespaces,
        )
        if top_level_nodes:
            self._set_node_location_from_nodes(yara_file, top_level_nodes[0], top_level_nodes[-1])
        return yara_file
