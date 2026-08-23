"""Small, stable public API for YARA-family source and AST operations."""

from collections.abc import Sequence
from dataclasses import dataclass
from pathlib import Path
from typing import Literal

from yaraast.ast.base import YaraFile
from yaraast.codegen import CodeGenerator
from yaraast.dialects import YaraDialect
from yaraast.limits import DEFAULT_RESOURCE_LIMITS, CancellationToken, ResourceLimits
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

DialectName = Literal["auto", "yara", "yara-x", "yara-l"]
OutputDialectName = Literal["yara", "yara-x", "yara-l"]


@dataclass(frozen=True)
class SourceEdit:
    """One replacement over a half-open UTF-8 byte range."""

    start: int
    end: int
    replacement: str


def _resolve_dialect(dialect: str) -> YaraDialect | None:
    try:
        return _DIALECTS[dialect]
    except (KeyError, TypeError) as exc:
        choices = ", ".join(_DIALECTS)
        raise ValueError(f"dialect must be one of: {choices}") from exc


def parse(
    source: str,
    *,
    dialect: DialectName = "auto",
    resource_limits: ResourceLimits = DEFAULT_RESOURCE_LIMITS,
    cancellation_token: CancellationToken | None = None,
) -> YaraFile | YaraLFile:
    """Parse YARA-family source text into its dialect-specific AST."""
    return UnifiedParser(
        source,
        _resolve_dialect(dialect),
        resource_limits=resource_limits,
        cancellation_token=cancellation_token,
    ).parse()


def parse_file(
    path: str | Path,
    *,
    dialect: DialectName = "auto",
    resource_limits: ResourceLimits = DEFAULT_RESOURCE_LIMITS,
    cancellation_token: CancellationToken | None = None,
) -> YaraFile | YaraLFile:
    """Parse a UTF-8 YARA-family source file."""
    return UnifiedParser.parse_file(
        path,
        _resolve_dialect(dialect),
        resource_limits=resource_limits,
        cancellation_token=cancellation_token,
    )


def generate(
    document: YaraFile | YaraLFile,
    *,
    dialect: OutputDialectName = "yara",
) -> str:
    """Generate new source from an AST using an explicit output dialect."""
    resolved = _resolve_dialect(dialect)
    if resolved is None:
        msg = "generation dialect must be one of: yara, yara-x, yara-l"
        raise ValueError(msg)
    if resolved is YaraDialect.YARA_L:
        if not isinstance(document, YaraLFile):
            msg = "YARA-L generation requires a YaraLFile"
            raise TypeError(msg)
        return YaraLGenerator().generate(document)
    if not isinstance(document, YaraFile):
        msg = "YARA and YARA-X generation requires a YaraFile"
        raise TypeError(msg)
    if resolved is YaraDialect.YARA_X:
        return YaraXGenerator().generate(document)
    return CodeGenerator().generate(document)


def format_canonical(
    source: str,
    *,
    dialect: DialectName = "auto",
    resource_limits: ResourceLimits = DEFAULT_RESOURCE_LIMITS,
    cancellation_token: CancellationToken | None = None,
) -> str:
    """Parse source and return canonical text for its dialect."""
    parser = UnifiedParser(
        source,
        _resolve_dialect(dialect),
        resource_limits=resource_limits,
        cancellation_token=cancellation_token,
    )
    document = parser.parse()
    if parser.dialect is YaraDialect.YARA_L:
        return generate(document, dialect="yara-l")
    if parser.dialect is YaraDialect.YARA_X:
        return generate(document, dialect="yara-x")
    return generate(document, dialect="yara")


def rewrite_lossless(source: str, edits: Sequence[SourceEdit]) -> str:
    """Apply non-overlapping UTF-8 byte edits while preserving all other bytes."""
    if not isinstance(source, str):
        msg = "source must be a string"
        raise TypeError(msg)
    if isinstance(edits, str) or not isinstance(edits, Sequence):
        msg = "edits must be a sequence of SourceEdit values"
        raise TypeError(msg)

    source_bytes = source.encode("utf-8")
    validated = []
    for edit in edits:
        if not isinstance(edit, SourceEdit):
            msg = "edits must contain only SourceEdit values"
            raise TypeError(msg)
        if isinstance(edit.start, bool) or isinstance(edit.end, bool):
            msg = "edit offsets must be integers"
            raise TypeError(msg)
        if not isinstance(edit.start, int) or not isinstance(edit.end, int):
            msg = "edit offsets must be integers"
            raise TypeError(msg)
        if not isinstance(edit.replacement, str):
            msg = "edit replacement must be a string"
            raise TypeError(msg)
        if edit.start < 0 or edit.end < edit.start or edit.end > len(source_bytes):
            msg = "source edit range is outside the UTF-8 source bytes"
            raise ValueError(msg)
        validated.append(edit)

    output = bytearray()
    position = 0
    for edit in sorted(validated, key=lambda value: value.start):
        if edit.start < position:
            msg = "source edits must not overlap"
            raise ValueError(msg)
        output.extend(source_bytes[position : edit.start])
        output.extend(edit.replacement.encode("utf-8"))
        position = edit.end
    output.extend(source_bytes[position:])
    try:
        return output.decode("utf-8")
    except UnicodeDecodeError as exc:
        msg = "source edits must align to UTF-8 code point boundaries"
        raise ValueError(msg) from exc
