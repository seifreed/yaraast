"""Result types for streaming parsing."""

from __future__ import annotations

from dataclasses import dataclass
from enum import Enum

from yaraast.ast.base import YaraFile


class ParseStatus(Enum):
    SUCCESS = "success"
    ERROR = "error"


@dataclass
class ParseResult:
    file_path: str
    rule_name: str | None
    status: ParseStatus
    error: str | None
    parse_time: float
    rule_count: int
    import_count: int
    ast: YaraFile | None = None
