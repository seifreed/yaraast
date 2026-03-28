"""Parsing services for CLI (logic without IO)."""

from __future__ import annotations

from collections.abc import Callable

from yaraast.dialects import YaraDialect
from yaraast.unified_parser import UnifiedParser


def parse_content_by_dialect(
    content: str,
    dialect: str,
    show_status: bool,
    status_cb: Callable[[str], None] | None = None,
) -> tuple:
    lexer_errors = []
    parser_errors = []

    if dialect == "auto":
        ast, lexer_errors, parser_errors = _parse_auto_detect_dialect(
            content,
            show_status,
            status_cb,
        )
    elif dialect == "yara-l":
        ast = _parse_yara_l_dialect(content, status_cb)
    else:
        ast, lexer_errors, parser_errors = _parse_standard_yara_dialect(content)

    return ast, lexer_errors, parser_errors


def _parse_auto_detect_dialect(
    content: str,
    show_status: bool,
    status_cb: Callable[[str], None] | None,
) -> tuple:
    unified_parser = UnifiedParser(content)
    detected_dialect = unified_parser.get_dialect()
    if show_status and status_cb:
        status_cb(f"[green]Detected dialect: {detected_dialect.name}[/green]")

    if detected_dialect == YaraDialect.YARA_L:
        ast = unified_parser.parse()
        return ast, [], []
    return _parse_with_error_tolerant_parser(content)


def _parse_yara_l_dialect(content: str, status_cb: Callable[[str], None] | None) -> object:
    if status_cb:
        status_cb("[green]Using YARA-L parser[/green]")
    from yaraast.yaral.parser import YaraLParser

    parser = YaraLParser(content)
    return parser.parse()


def _parse_standard_yara_dialect(content: str) -> tuple:
    return _parse_with_error_tolerant_parser(content)


def _parse_with_error_tolerant_parser(content: str) -> tuple:
    from yaraast.parser.error_tolerant_parser import ErrorTolerantParser
    from yaraast.parser.parser import Parser

    try:
        parser = Parser(content)
        ast = parser.parse()
        return ast, [], []
    except Exception:  # fallback to error-tolerant parser on any parse failure
        error_parser = ErrorTolerantParser()
        return error_parser.parse_with_errors(content)
