"""Small, stable public API for parsing and formatting YARA-family rules."""

from pathlib import Path
from typing import Literal

from yaraast.ast.base import YaraFile
from yaraast.codegen import CodeGenerator
from yaraast.dialects import YaraDialect
from yaraast.unified_parser import UnifiedParser
from yaraast.yaral.ast_nodes import YaraLFile
from yaraast.yaral.generator import YaraLGenerator
from yaraast.yarax.generator import YaraXGenerator

_DIALECTS: dict[str, YaraDialect | None] = {
    "auto": None,
    "yara": YaraDialect.YARA,
    "yara-x": YaraDialect.YARA_X,
    "yara-l": YaraDialect.YARA_L,
}


def _resolve_dialect(dialect: str) -> YaraDialect | None:
    try:
        return _DIALECTS[dialect]
    except (KeyError, TypeError) as exc:
        choices = ", ".join(_DIALECTS)
        raise ValueError(f"dialect must be one of: {choices}") from exc


def parse(
    source: str,
    *,
    dialect: Literal["auto", "yara", "yara-x", "yara-l"] = "auto",
) -> YaraFile | YaraLFile:
    """Parse YARA-family source text into its dialect-specific AST."""
    return UnifiedParser(source, _resolve_dialect(dialect)).parse()


def parse_file(
    path: str | Path,
    *,
    dialect: Literal["auto", "yara", "yara-x", "yara-l"] = "auto",
) -> YaraFile | YaraLFile:
    """Parse a UTF-8 YARA-family source file."""
    return UnifiedParser.parse_file(path, _resolve_dialect(dialect))


def format(
    source: str,
    *,
    dialect: Literal["auto", "yara", "yara-x", "yara-l"] = "auto",
) -> str:
    """Parse source and return canonical text for its dialect."""
    parser = UnifiedParser(source, _resolve_dialect(dialect))
    document = parser.parse()
    if parser.dialect is YaraDialect.YARA_L:
        if not isinstance(document, YaraLFile):
            msg = "YARA-L parser returned an incompatible document"
            raise TypeError(msg)
        return YaraLGenerator().generate(document)
    if not isinstance(document, YaraFile):
        msg = "YARA parser returned an incompatible document"
        raise TypeError(msg)
    if parser.dialect is YaraDialect.YARA_X:
        return YaraXGenerator().generate(document)
    return CodeGenerator().generate(document)
