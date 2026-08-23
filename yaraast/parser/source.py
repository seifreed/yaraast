"""Source-level parser dispatch helpers."""

from __future__ import annotations

from typing import TYPE_CHECKING

from yaraast.ast.base import YaraFile
from yaraast.dialects import YaraDialect, detect_dialect
from yaraast.errors import ParseError
from yaraast.limits import DEFAULT_RESOURCE_LIMITS, CancellationToken, ResourceLimits
from yaraast.parser.comment_aware_parser import CommentAwareParser
from yaraast.parser.parser import Parser
from yaraast.yarax.parser import YaraXParser

if TYPE_CHECKING:
    from yaraast.yaral.ast_nodes import YaraLFile


def parse_source(
    content: str,
    *,
    resource_limits: ResourceLimits = DEFAULT_RESOURCE_LIMITS,
    cancellation_token: CancellationToken | None = None,
) -> YaraFile | YaraLFile:
    """Parse any supported dialect, routing on the detected YARA flavor.

    Returns a :class:`YaraFile` for classic YARA / YARA-X and a
    :class:`~yaraast.yaral.ast_nodes.YaraLFile` for YARA-L (Chronicle).
    """
    dialect = detect_dialect(content)
    if dialect == YaraDialect.YARA_X:
        return YaraXParser(
            content,
            resource_limits=resource_limits,
            cancellation_token=cancellation_token,
        ).parse()
    if dialect == YaraDialect.YARA_L:
        from yaraast.yaral.parser import YaraLParser

        return YaraLParser(
            content,
            resource_limits=resource_limits,
            cancellation_token=cancellation_token,
        ).parse()
    return Parser(
        resource_limits=resource_limits,
        cancellation_token=cancellation_token,
    ).parse(content)


def parse_yara_source(
    content: str,
    *,
    resource_limits: ResourceLimits = DEFAULT_RESOURCE_LIMITS,
    cancellation_token: CancellationToken | None = None,
) -> YaraFile:
    """Parse standard YARA or YARA-X source."""
    dialect = detect_dialect(content)
    if dialect == YaraDialect.YARA_L:
        msg = "YARA-L input is not supported by parse_yara_source; use parse_source instead"
        raise ParseError(msg)
    if dialect == YaraDialect.YARA_X:
        return YaraXParser(
            content,
            resource_limits=resource_limits,
            cancellation_token=cancellation_token,
        ).parse()
    return Parser(
        resource_limits=resource_limits,
        cancellation_token=cancellation_token,
    ).parse(content)


def parse_yara_source_with_comments(content: str) -> YaraFile:
    """Parse standard YARA with comments or YARA-X source."""
    dialect = detect_dialect(content)
    if dialect == YaraDialect.YARA_L:
        msg = (
            "YARA-L input is not supported by parse_yara_source_with_comments; "
            "use parse_source instead"
        )
        raise ParseError(msg)
    if dialect == YaraDialect.YARA_X:
        return YaraXParser(content).parse()
    return CommentAwareParser().parse(content)
