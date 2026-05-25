"""Real tests for UnifiedParser streaming behavior (no mocks)."""

from __future__ import annotations

from pathlib import Path

import pytest

from yaraast.ast.base import YaraFile
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


def _sample_with_extended_preamble() -> str:
    return """
#pragma optimize on
import "external.yar" (legacy.ExternalRule) as ext
namespace legacy
extern rule private legacy.ExternalRule

rule uses_external {
  condition:
    true
}
"""


def test_parse_file_traditional_real(tmp_path: Path) -> None:
    f = tmp_path / "sample.yar"
    f.write_text(_sample_with_preamble(), encoding="utf-8")

    ast = UnifiedParser.parse_file(f, streaming_threshold_mb=1024)
    assert isinstance(ast, YaraFile)
    assert len(ast.rules) == 1
    assert len(ast.imports) == 2
    assert len(ast.includes) == 1


def test_parse_file_force_streaming_real(tmp_path: Path) -> None:
    f = tmp_path / "sample_stream.yar"
    f.write_text(_sample_with_preamble(), encoding="utf-8")

    ast = UnifiedParser.parse_file(f, force_streaming=True)
    assert isinstance(ast, YaraFile)
    assert len(ast.rules) == 1
    assert len(ast.imports) == 2
    assert len(ast.includes) == 1
    assert {imp.module for imp in ast.imports} == {"pe", "math"}


def test_parse_file_force_streaming_preserves_extended_preamble(tmp_path: Path) -> None:
    f = tmp_path / "sample_stream_extended.yar"
    f.write_text(_sample_with_extended_preamble(), encoding="utf-8")

    ast = UnifiedParser.parse_file(f, dialect=YaraDialect.YARA, force_streaming=True)

    assert isinstance(ast, YaraFile)
    assert len(ast.rules) == 1
    assert ast.pragmas[0].name == "optimize"
    assert ast.extern_imports[0].module_path == "external.yar"
    assert ast.extern_imports[0].alias == "ext"
    assert ast.extern_imports[0].rules == ["legacy.ExternalRule"]
    assert ast.namespaces[0].name == "legacy"
    assert ast.namespaces[0].extern_rules[0].name == "ExternalRule"
    assert ast.namespaces[0].extern_rules[0].namespace == "legacy"
    assert ast.extern_rules == []


def test_parse_empty_file_force_streaming_real(tmp_path: Path) -> None:
    f = tmp_path / "empty.yar"
    f.write_text("", encoding="utf-8")

    ast = UnifiedParser.parse_file(f, force_streaming=True)

    assert isinstance(ast, YaraFile)
    assert ast.rules == []
    assert ast.imports == []
    assert ast.includes == []


def test_parse_file_auto_streaming_threshold_real(tmp_path: Path) -> None:
    f = tmp_path / "sample_auto_stream.yar"
    f.write_text(_sample_with_preamble(), encoding="utf-8")

    ast = UnifiedParser.parse_file(f, streaming_threshold_mb=0)
    assert isinstance(ast, YaraFile)
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


def test_extract_preamble_fast_stops_at_modified_rule(tmp_path: Path) -> None:
    f = tmp_path / "pre_modified.yar"
    f.write_text(
        """
import "pe"
private global rule x { condition: true }
include "late.yar"
""",
        encoding="utf-8",
    )

    imports, includes = UnifiedParser._extract_preamble_fast(f)
    assert [import_.module for import_ in imports] == ["pe"]
    assert includes == []


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
