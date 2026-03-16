"""Real tests for libyara DirectASTCompiler and OptimizedMatcher (no mocks)."""

from __future__ import annotations

import pytest

from yaraast.libyara.direct_compiler import YARA_AVAILABLE, DirectASTCompiler, OptimizedMatcher
from yaraast.parser import Parser


@pytest.mark.skipif(not YARA_AVAILABLE, reason="yara-python not available")
def test_direct_compiler_and_matcher(tmp_path) -> None:
    code = """
    rule direct_rule {
        strings:
            $a = "abc"
        condition:
            $a
    }
    """
    ast = Parser().parse(code)

    compiler = DirectASTCompiler(enable_optimization=True, debug_mode=True)
    result = compiler.compile_ast(ast)

    assert result.success is True
    assert result.optimized is True
    assert result.generated_source is not None
    assert result.ast_node_count > 0

    matcher = OptimizedMatcher(result.compiled_rules, ast=ast)
    scan = matcher.scan(b"xxabcxx")
    assert scan["success"] is True
    assert scan["matches"]
    stats = matcher.get_scan_stats()
    assert stats["total_scans"] >= 1
