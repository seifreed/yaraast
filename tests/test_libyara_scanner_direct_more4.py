from __future__ import annotations

import pytest

from yaraast.libyara.compiler import LibyaraCompiler
from yaraast.libyara.direct_compiler import YARA_AVAILABLE as DIRECT_YARA
from yaraast.libyara.direct_compiler import DirectASTCompiler, OptimizedMatcher
from yaraast.libyara.scanner import YARA_AVAILABLE as SCANNER_YARA
from yaraast.libyara.scanner import LibyaraScanner
from yaraast.parser import Parser


@pytest.mark.skipif(not DIRECT_YARA, reason="yara-python not available")
def test_direct_ast_compiler_invalid_ast_hits_error_result() -> None:
    compiler = DirectASTCompiler()

    result = compiler.compile_ast(None)  # type: ignore[arg-type]

    assert result.success is False
    assert result.errors
    assert "Direct compilation error" in result.errors[0]


@pytest.mark.skipif(not DIRECT_YARA, reason="yara-python not available")
def test_optimized_matcher_stats_zero_branch() -> None:
    compiler = LibyaraCompiler()
    ast = Parser().parse('rule a { strings: $x = "abc" condition: $x }')
    compiled = compiler.compile_ast(ast)
    assert compiled.success is True

    matcher = OptimizedMatcher(compiled.compiled_rules)
    stats = matcher.get_scan_stats()
    assert stats["average_scan_time"] == 0.0
    assert stats["success_rate"] == 0.0


@pytest.mark.skipif(not SCANNER_YARA, reason="yara-python not available")
def test_libyara_scanner_real_error_paths(tmp_path) -> None:
    compiler = LibyaraCompiler()
    scanner = LibyaraScanner()
    ast = Parser().parse('rule a { strings: $x = "abc" condition: $x }')
    compiled = compiler.compile_ast(ast)
    assert compiled.success is True

    directory = tmp_path / "adir"
    directory.mkdir()
    file_result = scanner.scan_file(compiled.compiled_rules, directory)
    assert file_result.success is False
    assert file_result.errors

    process_result = scanner.scan_process(compiled.compiled_rules, -1)
    assert process_result.success is False
    assert process_result.errors


@pytest.mark.skipif(not SCANNER_YARA, reason="yara-python not available")
def test_libyara_scanner_process_yara_error_path() -> None:
    compiler = LibyaraCompiler()
    scanner = LibyaraScanner()
    ast = Parser().parse('rule a { strings: $x = "abc" condition: $x }')
    compiled = compiler.compile_ast(ast)
    assert compiled.success is True

    result = scanner.scan_process(compiled.compiled_rules, 999999)
    assert result.success is False
    assert result.errors
    assert "Process scan error" in result.errors[0]
