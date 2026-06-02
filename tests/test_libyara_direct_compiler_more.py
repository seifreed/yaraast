"""Real tests for libyara DirectASTCompiler and OptimizedMatcher (no mocks)."""

from __future__ import annotations

from pathlib import Path
from typing import Any, cast

import pytest

from yaraast.libyara.direct_compiler import YARA_AVAILABLE, DirectASTCompiler, OptimizedMatcher
from yaraast.parser import Parser


@pytest.mark.skipif(not YARA_AVAILABLE, reason="yara-python not available")
def test_direct_compiler_and_matcher(tmp_path: Path) -> None:
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


@pytest.mark.skipif(not YARA_AVAILABLE, reason="yara-python not available")
def test_direct_compiler_compile_ast_uses_include_mapping() -> None:
    ast = Parser().parse("""
include "shared.yar"

rule main_rule {
    condition:
        shared_rule
}
""")

    compiler = DirectASTCompiler(enable_optimization=False)
    result = compiler.compile_ast(
        ast,
        includes={"shared.yar": "rule shared_rule { condition: true }\n"},
    )

    assert result.success is True
    assert result.compiled_rules is not None
    assert [match.rule for match in result.compiled_rules.match(data=b"")] == [
        "shared_rule",
        "main_rule",
    ]


@pytest.mark.skipif(not YARA_AVAILABLE, reason="yara-python not available")
def test_direct_compiler_compile_ast_uses_include_mapping_with_source_path(
    tmp_path: Path,
) -> None:
    ast = Parser().parse("""
include "virtual.yar"

rule main_rule {
    condition:
        virtual_rule
}
""")

    compiler = DirectASTCompiler(enable_optimization=False)
    result = compiler.compile_ast(
        ast,
        includes={"virtual.yar": "rule virtual_rule { condition: true }\n"},
        source_path=tmp_path / "main.yar",
    )

    assert result.success is True
    assert result.compiled_rules is not None
    assert [match.rule for match in result.compiled_rules.match(data=b"")] == [
        "virtual_rule",
        "main_rule",
    ]


@pytest.mark.skipif(not YARA_AVAILABLE, reason="yara-python not available")
def test_direct_compiler_compile_ast_rejects_invalid_source_path() -> None:
    ast = Parser().parse("rule main_rule { condition: true }")
    compiler = DirectASTCompiler(enable_optimization=False)

    empty_result = compiler.compile_ast(ast, source_path="")
    type_result = compiler.compile_ast(ast, source_path=cast(Any, False))

    assert empty_result.success is False
    assert empty_result.errors == ["Direct compilation error: source_path must not be empty"]
    assert type_result.success is False
    assert type_result.errors == [
        "Direct compilation error: source_path must be a string or path-like object",
    ]
