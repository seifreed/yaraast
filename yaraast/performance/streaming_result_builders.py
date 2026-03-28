"""Helpers for building streaming parser result payloads."""

from __future__ import annotations

from pathlib import Path
import time
from typing import Any

from yaraast.ast.base import YaraFile
from yaraast.performance.streaming_results import ParseResult, ParseStatus


def default_streaming_stats() -> dict[str, Any]:
    """Return the default statistics structure for streaming parsing."""
    return {
        "rules_parsed": 0,
        "bytes_processed": 0,
        "parse_errors": 0,
        "peak_memory_mb": 0,
        "files_processed": 0,
        "files_successful": 0,
        "total_parse_time": 0,
    }


def build_rule_parse_result(file_path: Path, rule, parse_time: float) -> ParseResult:
    """Create a per-rule successful parse result."""
    ast = YaraFile(imports=[], includes=[], rules=[rule])
    return ParseResult(
        file_path=str(file_path),
        rule_name=rule.name if hasattr(rule, "name") else None,
        status=ParseStatus.SUCCESS,
        error=None,
        parse_time=parse_time,
        rule_count=1,
        import_count=0,
        ast=ast,
    )


def build_file_parse_result(file_path: Path, ast, parse_time: float) -> ParseResult:
    """Create a per-file successful parse result."""
    return ParseResult(
        file_path=str(file_path),
        rule_name=ast.rules[0].name if ast.rules else None,
        status=ParseStatus.SUCCESS,
        error=None,
        parse_time=parse_time,
        rule_count=len(ast.rules),
        import_count=len(ast.imports),
        ast=ast,
    )


def build_error_parse_result(file_path: Path, error: Exception | str) -> ParseResult:
    """Create a failed parse result."""
    return ParseResult(
        file_path=str(file_path),
        rule_name=None,
        status=ParseStatus.ERROR,
        error=str(error),
        parse_time=0,
        rule_count=0,
        import_count=0,
        ast=None,
    )


def timed_now() -> float:
    """Return current time for duration tracking."""
    return time.time()
