"""Enhanced YARA-X parser with support for new syntax features."""

from __future__ import annotations

from typing import cast

from yaraast.ast.strings import HexToken
from yaraast.lexer.tokens import Token
from yaraast.parser._shared import ParserError
from yaraast.parser.hex_parser import HexParseError, HexStringParser
from yaraast.parser.parser import Parser as BaseParser
from yaraast.yarax.parser_collections import YaraXParserCollectionsMixin
from yaraast.yarax.parser_conditions import YaraXParserConditionsMixin
from yaraast.yarax.parser_expressions import YaraXParserExpressionsMixin
from yaraast.yarax.parser_helpers import YaraXParserHelpersMixin


class YaraXParser(
    YaraXParserConditionsMixin,
    YaraXParserCollectionsMixin,
    YaraXParserExpressionsMixin,
    YaraXParserHelpersMixin,
    BaseParser,
):
    """Enhanced parser for YARA-X with support for new syntax features."""

    _allow_string_identifier_non_logical_binary = True

    def __init__(self, text: str) -> None:
        """Initialize YARA-X parser.

        Args:
            text: YARA-X source code to parse
        """
        super().__init__(text)

    def _parse_hex_string(self, hex_content: str) -> list[HexToken]:
        """Parse YARA-X hex patterns without libyara placement-only restrictions."""
        try:
            hex_parser = HexStringParser(error_token=cast(Token, self._peek()))
            return hex_parser.parse(
                hex_content,
                validate_placement=False,
                allow_zero_jump=True,
                allow_empty_lower_bound=True,
            )
        except HexParseError as e:
            raise ParserError(str(e), self._peek()) from e
