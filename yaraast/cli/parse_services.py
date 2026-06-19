"""Parsing services for CLI (logic without IO)."""

from __future__ import annotations

from collections.abc import Callable

from yaraast.dialects import YaraDialect
from yaraast.errors import YaraASTError
from yaraast.unified_parser import UnifiedParser

_DIALECTS = frozenset({"auto", "yara", "yara-l", "yara-x"})


def parse_content_by_dialect(
    content: str,
    dialect: object,
    show_status: bool,
    status_cb: Callable[[str], None] | None = None,
) -> tuple:
    lexer_errors = []
    parser_errors = []

    dialect = _require_dialect(dialect)
    if dialect == "auto":
        ast, lexer_errors, parser_errors = _parse_auto_detect_dialect(
            content,
            show_status,
            status_cb,
        )
    elif dialect == "yara-x":
        ast = _parse_yara_x_dialect(content, status_cb)
    elif dialect == "yara-l":
        ast = _parse_yara_l_dialect(content, status_cb)
    else:
        ast, lexer_errors, parser_errors = _parse_with_error_tolerant_parser(content)

    return ast, lexer_errors, parser_errors


def _require_dialect(dialect: object) -> str:
    if not isinstance(dialect, str):
        raise TypeError("dialect must be a string")
    if dialect not in _DIALECTS:
        valid = ", ".join(sorted(_DIALECTS))
        raise ValueError(f"dialect must be one of: {valid}")
    return dialect


def _parse_auto_detect_dialect(
    content: str,
    show_status: bool,
    status_cb: Callable[[str], None] | None,
) -> tuple:
    unified_parser = UnifiedParser(content)
    detected_dialect = unified_parser.get_dialect()
    if show_status and status_cb:
        status_cb(f"[green]Detected dialect: {detected_dialect.name}[/green]")

    if detected_dialect in {YaraDialect.YARA_L, YaraDialect.YARA_X}:
        ast = unified_parser.parse()
        return ast, [], []
    return _parse_with_error_tolerant_parser(content)


def _parse_yara_x_dialect(content: str, status_cb: Callable[[str], None] | None) -> object:
    if status_cb:
        status_cb("[green]Using YARA-X parser[/green]")
    return UnifiedParser(content, dialect=YaraDialect.YARA_X).parse()


def _parse_yara_l_dialect(content: str, status_cb: Callable[[str], None] | None) -> object:
    if status_cb:
        status_cb("[green]Using YARA-L parser[/green]")
    from yaraast.yaral.parser import YaraLParser

    parser = YaraLParser(content)
    return parser.parse()


def _parse_with_error_tolerant_parser(content: str) -> tuple:
    from yaraast.parser.error_tolerant_parser import ErrorTolerantParser
    from yaraast.parser.parser import Parser

    try:
        parser = Parser(content)
        ast = parser.parse()
        return ast, [], []
    except (YaraASTError, ValueError):
        result = ErrorTolerantParser().parse(content)
        return result.ast, [], result.errors
