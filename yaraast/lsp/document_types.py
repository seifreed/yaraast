"""Shared LSP document models and path helpers."""

from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum
from pathlib import Path
from typing import Any
from urllib.parse import unquote, urlparse

from lsprotocol.types import Location, Position, Range, SymbolInformation, SymbolKind

from yaraast.config import DEFAULT_DIAGNOSTICS_DEBOUNCE_MS
from yaraast.dialects import YaraDialect, detect_dialect

YARA_FILE_SUFFIXES = frozenset({".yar", ".yara", ".yaral", ".yarax"})


def _required_symbol_string(data: dict[str, Any], key: str) -> str:
    value = data.get(key)
    if not isinstance(value, str) or not value:
        msg = f"SymbolRecord {key} must be a non-empty string"
        raise ValueError(msg)
    return value


def _required_position_int(data: dict[str, Any], key: str) -> int:
    value = data.get(key)
    if isinstance(value, int) and not isinstance(value, bool) and value >= 0:
        return value
    msg = f"SymbolRecord range {key} must be a non-negative integer"
    raise ValueError(msg)


def uri_to_path(uri: object) -> Path | None:
    if not isinstance(uri, str) or not uri:
        return None
    if uri.startswith("file://"):
        parsed = urlparse(uri)
        if parsed.netloc and parsed.netloc != "localhost":
            return None
        decoded = unquote(parsed.path)
        if not decoded:
            return None
        # On Windows, file:///C:/path yields /C:/path — strip leading slash
        if len(decoded) >= 3 and decoded[0] == "/" and decoded[2] == ":":
            decoded = decoded[1:]
        return Path(decoded)
    if "://" in uri:
        return None
    return Path(uri)


def path_to_uri(path: Path) -> str:
    return path.resolve().as_uri()


class LanguageMode(Enum):
    AUTO = "auto"
    YARA = "yara"
    YARA_X = "yarax"
    YARA_L = "yaral"

    def to_dialect(self, text: str) -> YaraDialect:
        if self is LanguageMode.YARA:
            return YaraDialect.YARA
        if self is LanguageMode.YARA_X:
            return YaraDialect.YARA_X
        if self is LanguageMode.YARA_L:
            return YaraDialect.YARA_L
        return detect_dialect(text)


@dataclass(slots=True)
class RuntimeConfig:
    cache_workspace: bool = True
    rule_name_validation: str | None = None
    metadata_validation: list[dict[str, Any]] = field(default_factory=list)
    code_formatting: dict[str, Any] = field(default_factory=dict)
    language_mode: LanguageMode = LanguageMode.AUTO
    diagnostics_debounce_ms: int = DEFAULT_DIAGNOSTICS_DEBOUNCE_MS


@dataclass(slots=True)
class SymbolRecord:
    name: str
    kind: str
    uri: str
    range: Range
    container_name: str | None = None

    def to_dict(self) -> dict[str, object]:
        return {
            "name": self.name,
            "kind": self.kind,
            "uri": self.uri,
            "range": {
                "start": {"line": self.range.start.line, "character": self.range.start.character},
                "end": {"line": self.range.end.line, "character": self.range.end.character},
            },
            "container_name": self.container_name,
        }

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> SymbolRecord:
        range_data = data.get("range", {})
        if not isinstance(range_data, dict):
            msg = "SymbolRecord range must be an object"
            raise ValueError(msg)
        start = range_data.get("start", {})
        end = range_data.get("end", {})
        if not isinstance(start, dict) or not isinstance(end, dict):
            msg = "SymbolRecord range endpoints must be objects"
            raise ValueError(msg)
        container_name = data.get("container_name")
        return cls(
            name=_required_symbol_string(data, "name"),
            kind=_required_symbol_string(data, "kind"),
            uri=_required_symbol_string(data, "uri"),
            range=Range(
                start=Position(
                    line=_required_position_int(start, "line"),
                    character=_required_position_int(start, "character"),
                ),
                end=Position(
                    line=_required_position_int(end, "line"),
                    character=_required_position_int(end, "character"),
                ),
            ),
            container_name=container_name if isinstance(container_name, str) else None,
        )

    def to_symbol_information(self) -> SymbolInformation:
        kind_map = {
            "import": SymbolKind.Namespace,
            "include": SymbolKind.File,
            "rule": SymbolKind.Class,
            "string": SymbolKind.Variable,
            "meta": SymbolKind.Property,
            "condition": SymbolKind.Function,
        }
        return SymbolInformation(
            name=self.name,
            kind=kind_map.get(self.kind, SymbolKind.Variable),
            location=Location(uri=self.uri, range=self.range),
            container_name=self.container_name,
        )


@dataclass(slots=True)
class ResolvedSymbol:
    uri: str
    name: str
    normalized_name: str
    kind: str
    range: Range


@dataclass(slots=True)
class ReferenceRecord:
    location: Location
    role: str
    symbol_kind: str


@dataclass(slots=True)
class RuleLinkRecord:
    rule_name: str
    location: Location
    target_uri: str


def copy_position(position: Position) -> Position:
    return Position(line=position.line, character=position.character)


def copy_location(location: Location) -> Location:
    return Location(uri=location.uri, range=copy_range(location.range))


def copy_range(range_: Range) -> Range:
    return Range(start=copy_position(range_.start), end=copy_position(range_.end))


def copy_reference_record(record: ReferenceRecord) -> ReferenceRecord:
    return ReferenceRecord(
        location=copy_location(record.location),
        role=record.role,
        symbol_kind=record.symbol_kind,
    )


def copy_rule_link_record(record: RuleLinkRecord) -> RuleLinkRecord:
    return RuleLinkRecord(
        rule_name=record.rule_name,
        location=copy_location(record.location),
        target_uri=record.target_uri,
    )


def copy_resolved_symbol(symbol: ResolvedSymbol) -> ResolvedSymbol:
    return ResolvedSymbol(
        uri=symbol.uri,
        name=symbol.name,
        normalized_name=symbol.normalized_name,
        kind=symbol.kind,
        range=copy_range(symbol.range),
    )


def require_workspace_symbol_query(query: object) -> str:
    if not isinstance(query, str):
        raise TypeError("Workspace symbol query must be a string")
    return query
