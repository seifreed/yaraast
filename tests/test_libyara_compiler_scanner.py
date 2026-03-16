"""Real tests for libyara compiler/scanner (no mocks)."""

from __future__ import annotations

import pytest

from yaraast.libyara.compiler import YARA_AVAILABLE as COMPILER_AVAILABLE
from yaraast.libyara.compiler import LibyaraCompiler
from yaraast.libyara.scanner import LibyaraScanner


@pytest.mark.skipif(not COMPILER_AVAILABLE, reason="yara-python not available")
def test_libyara_compile_source_and_scan(tmp_path) -> None:
    compiler = LibyaraCompiler()
    scanner = LibyaraScanner()

    source = """
    rule test_rule {
        strings:
            $a = "abc"
        condition:
            $a
    }
    """
    result = compiler.compile_source(source)
    assert result.success is True
    assert result.compiled_rules is not None

    matched = scanner.scan_data(result.compiled_rules, b"xxabcxx")
    assert matched.success is True
    assert matched.matched is True
    assert "test_rule" in matched.matched_rules

    not_matched = scanner.scan_data(result.compiled_rules, b"zzz")
    assert not_matched.success is True
    assert not_matched.matched is False

    data_path = tmp_path / "data.bin"
    data_path.write_bytes(b"xxabcxx")
    file_result = scanner.scan_file(result.compiled_rules, data_path)
    assert file_result.success is True
    assert file_result.matched is True


@pytest.mark.skipif(not COMPILER_AVAILABLE, reason="yara-python not available")
def test_libyara_compile_file_missing(tmp_path) -> None:
    compiler = LibyaraCompiler()
    missing = tmp_path / "missing.yar"
    result = compiler.compile_file(missing)
    assert result.success is False
    assert result.errors
