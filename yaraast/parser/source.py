"""Source-level parser dispatch helpers."""

from __future__ import annotations

from yaraast.ast.base import YaraFile
from yaraast.dialects import YaraDialect, detect_dialect
from yaraast.parser.comment_aware_parser import CommentAwareParser
from yaraast.parser.parser import Parser
from yaraast.yarax.parser import YaraXParser


def parse_yara_source(content: str) -> YaraFile:
    """Parse standard YARA or YARA-X source."""
    if detect_dialect(content) == YaraDialect.YARA_X:
        return YaraXParser(content).parse()
    return Parser().parse(content)


def parse_yara_source_with_comments(content: str) -> YaraFile:
    """Parse standard YARA with comments or YARA-X source."""
    if detect_dialect(content) == YaraDialect.YARA_X:
        return YaraXParser(content).parse()
    return CommentAwareParser().parse(content)
