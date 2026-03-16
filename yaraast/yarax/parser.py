"""Enhanced YARA-X parser with support for new syntax features."""

from __future__ import annotations

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

    def __init__(self, text: str) -> None:
        """Initialize YARA-X parser.

        Args:
            text: YARA-X source code to parse
        """
        super().__init__(text)
