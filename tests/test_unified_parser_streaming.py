"""Real tests for UnifiedParser streaming behavior (no mocks)."""

from __future__ import annotations

from pathlib import Path

import pytest

from yaraast.dialects import YaraDialect
from yaraast.unified_parser import UnifiedParser


def _sample_with_preamble() -> str:
    return """
import "pe"
import "math" as m
include "common.yar"

rule r1 {
  condition:
    true
}
"""


def test_parse_file_traditional_real(tmp_path: Path) -> None:
    f = tmp_path / "sample.yar"
    f.write_text(_sample_with_preamble(), encoding="utf-8")

    ast = UnifiedParser.parse_file(f, streaming_threshold_mb=1024)
    assert len(ast.rules) == 1
    assert len(ast.imports) == 2
    assert len(ast.includes) == 1


def test_parse_file_force_streaming_real(tmp_path: Path) -> None:
    f = tmp_path / "sample_stream.yar"
    f.write_text(_sample_with_preamble(), encoding="utf-8")

    ast = UnifiedParser.parse_file(f, force_streaming=True)
    assert len(ast.rules) == 1
    assert len(ast.imports) == 2
    assert len(ast.includes) == 1
    assert {imp.module for imp in ast.imports} == {"pe", "math"}


def test_parse_file_auto_streaming_threshold_real(tmp_path: Path) -> None:
    f = tmp_path / "sample_auto_stream.yar"
    f.write_text(_sample_with_preamble(), encoding="utf-8")

    ast = UnifiedParser.parse_file(f, streaming_threshold_mb=0)
    assert len(ast.rules) == 1
    assert len(ast.imports) == 2


def test_extract_preamble_fast_real(tmp_path: Path) -> None:
    f = tmp_path / "pre.yar"
    f.write_text(
        """
// comment
import "pe"
/* block
comment */
import "elf" as e
include "a.yar"
rule x { condition: true }
""",
        encoding="utf-8",
    )

    imports, includes = UnifiedParser._extract_preamble_fast(f)
    assert len(imports) == 2
    assert imports[0].module == "pe"
    assert imports[1].module == "elf"
    assert imports[1].alias == "e"
    assert len(includes) == 1
    assert includes[0].path == "a.yar"


def test_parse_file_missing_raises_real(tmp_path: Path) -> None:
    missing = tmp_path / "missing.yar"
    with pytest.raises(FileNotFoundError):
        UnifiedParser.parse_file(missing)


def test_detect_file_dialect_real(tmp_path: Path) -> None:
    f = tmp_path / "dialect.yar"
    f.write_text(
        """
rule login_events {
  events:
    $e.metadata.event_type = "LOGIN"
  condition:
    $e
}
""",
        encoding="utf-8",
    )
    dialect = UnifiedParser.detect_file_dialect(str(f))
    assert dialect in {YaraDialect.YARA_L, YaraDialect.YARA}
