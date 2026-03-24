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


def uri_to_path(uri: str) -> Path | None:
    if uri.startswith("file://"):
        parsed = urlparse(uri)
        return Path(unquote(parsed.path))
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
        start = range_data.get("start", {})
        end = range_data.get("end", {})
        return cls(
            name=str(data.get("name", "")),
            kind=str(data.get("kind", "variable")),
            uri=str(data.get("uri", "")),
            range=Range(
                start=Position(
                    line=int(start.get("line", 0)),
                    character=int(start.get("character", 0)),
                ),
                end=Position(
                    line=int(end.get("line", 0)),
                    character=int(end.get("character", 0)),
                ),
            ),
            container_name=data.get("container_name"),
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
