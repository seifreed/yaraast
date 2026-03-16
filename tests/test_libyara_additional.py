"""Additional tests for libyara helpers and compiler paths."""

from __future__ import annotations

import tempfile
from pathlib import Path

import pytest

try:
    import yara  # noqa: F401

    YARA_AVAILABLE = True
except ImportError:
    YARA_AVAILABLE = False

from yaraast.ast.expressions import IntegerLiteral
from yaraast.libyara.ast_optimizer import ASTOptimizer
from yaraast.parser import Parser

if YARA_AVAILABLE:
    from yaraast.libyara import DirectASTCompiler, LibyaraCompiler, LibyaraScanner


@pytest.mark.skipif(not YARA_AVAILABLE, reason="yara-python not available")
def test_compile_source_with_null_byte() -> None:
    compiler = LibyaraCompiler()
    source = "rule test { condition: true }\x00"
    result = compiler.compile_source(source)

    assert result.success is False
    assert result.errors


@pytest.mark.skipif(not YARA_AVAILABLE, reason="yara-python not available")
def test_compile_file_and_save_rules() -> None:
    rule_text = "rule test { condition: true }"
    with tempfile.NamedTemporaryFile(mode="w", delete=False, suffix=".yar") as f:
        f.write(rule_text)
        rule_path = Path(f.name)

    try:
        compiler = LibyaraCompiler()
        result = compiler.compile_file(rule_path)
        assert result.success is True
        assert result.compiled_rules is not None

        out_path = rule_path.with_suffix(".bin")
        assert compiler.save_compiled_rules(result.compiled_rules, out_path) is True
        assert out_path.exists()
    finally:
        rule_path.unlink(missing_ok=True)
        out_path = rule_path.with_suffix(".bin")
        out_path.unlink(missing_ok=True)


@pytest.mark.skipif(not YARA_AVAILABLE, reason="yara-python not available")
def test_save_compiled_rules_invalid() -> None:
    compiler = LibyaraCompiler()
    assert compiler.save_compiled_rules("not_rules", "out.yarc") is False


@pytest.mark.skipif(not YARA_AVAILABLE, reason="yara-python not available")
def test_direct_compiler_debug_mode_source() -> None:
    parser = Parser()
    ast = parser.parse("rule debug_rule { condition: true }")

    compiler = DirectASTCompiler(debug_mode=True, enable_optimization=False)
    result = compiler.compile_ast(ast)

    assert result.success is True
    assert result.generated_source is not None


@pytest.mark.skipif(not YARA_AVAILABLE, reason="yara-python not available")
def test_scanner_missing_file() -> None:
    rule_text = "rule test { condition: true }"
    compiler = LibyaraCompiler()
    compiled = compiler.compile_source(rule_text)

    scanner = LibyaraScanner()
    result = scanner.scan_file(compiled.compiled_rules, Path("missing-file.yar"))

    assert result.success is False
    assert result.errors


def test_ast_optimizer_fold_constants() -> None:
    optimizer = ASTOptimizer()
    folded = optimizer._fold_constants(IntegerLiteral(4), "+", IntegerLiteral(3))

    assert folded is not None
    assert folded.value == 7

    none_fold = optimizer._fold_constants(IntegerLiteral(1), "/", IntegerLiteral(0))
    assert none_fold is None


@pytest.mark.skipif(YARA_AVAILABLE, reason="yara-python available")
def test_libyara_unavailable_raises() -> None:
    from yaraast.libyara.compiler import LibyaraCompiler
    from yaraast.libyara.direct_compiler import DirectASTCompiler
    from yaraast.libyara.scanner import LibyaraScanner

    with pytest.raises(ImportError):
        LibyaraCompiler()
    with pytest.raises(ImportError):
        DirectASTCompiler()
    with pytest.raises(ImportError):
        LibyaraScanner()
