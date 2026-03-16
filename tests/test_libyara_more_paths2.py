"""Additional real coverage tests for libyara optimizer/scanner/direct compiler."""

from __future__ import annotations

import os
from pathlib import Path

import pytest

from yaraast.ast.base import YaraFile
from yaraast.ast.expressions import (
    BinaryExpression,
    BooleanLiteral,
    Identifier,
    IntegerLiteral,
    UnaryExpression,
)
from yaraast.ast.rules import Rule
from yaraast.libyara.ast_optimizer import ASTOptimizer
from yaraast.libyara.compiler import YARA_AVAILABLE as COMPILER_AVAILABLE
from yaraast.libyara.compiler import LibyaraCompiler
from yaraast.libyara.direct_compiler import YARA_AVAILABLE, DirectASTCompiler, OptimizedMatcher
from yaraast.libyara.scanner import YARA_AVAILABLE as SCANNER_AVAILABLE
from yaraast.libyara.scanner import LibyaraScanner
from yaraast.parser import Parser


def test_ast_optimizer_rule_and_constant_paths() -> None:
    optimizer = ASTOptimizer()
    rule = Rule(
        name="math_rule",
        condition=BinaryExpression(
            left=IntegerLiteral(value=8),
            operator="/",
            right=IntegerLiteral(value=2),
        ),
    )

    optimizer._optimize_rule(rule)

    assert optimizer.stats.rules_optimized == 1
    assert optimizer.stats.conditions_simplified == 1
    assert any(
        "Simplified condition in rule 'math_rule'" in item
        for item in optimizer.optimizations_applied
    )
    assert isinstance(rule.condition, IntegerLiteral)
    assert rule.condition.value == 4

    unary = UnaryExpression(
        operator="not",
        operand=BinaryExpression(
            left=IntegerLiteral(value=9),
            operator="-",
            right=IntegerLiteral(value=4),
        ),
    )
    optimized_unary = optimizer._optimize_condition(unary)
    assert isinstance(optimized_unary, UnaryExpression)
    assert isinstance(optimized_unary.operand, IntegerLiteral)
    assert optimized_unary.operand.value == 5

    non_folded = BinaryExpression(left=Identifier("x"), operator="+", right=IntegerLiteral(value=1))
    optimized_non_folded = optimizer._optimize_condition(non_folded)
    assert optimized_non_folded.left.name == "x"
    assert optimized_non_folded.right.value == 1

    assert optimizer._fold_constants(IntegerLiteral(7), "-", IntegerLiteral(3)).value == 4
    assert optimizer._fold_constants(IntegerLiteral(7), "*", IntegerLiteral(3)).value == 21
    assert optimizer._fold_constants(IntegerLiteral(7), "%", IntegerLiteral(3)).value == 1
    assert optimizer._fold_constants(IntegerLiteral(7), "/", IntegerLiteral(0)) is None
    assert optimizer._fold_constants(IntegerLiteral("bad"), "+", IntegerLiteral(1)) is None


@pytest.mark.skipif(
    not COMPILER_AVAILABLE or not SCANNER_AVAILABLE, reason="yara-python not available"
)
def test_libyara_scanner_file_process_and_error_paths(tmp_path: Path) -> None:
    compiler = LibyaraCompiler()
    scanner = LibyaraScanner(timeout=10)
    compilation = compiler.compile_source("rule always_true { condition: true }")
    assert compilation.success is True

    data_path = tmp_path / "sample.bin"
    data_path.write_bytes(b"sample")

    file_result = scanner.scan_file(compilation.compiled_rules, str(data_path))
    assert file_result.success is True
    assert file_result.data_size == len(b"sample")

    missing_result = scanner.scan_file(compilation.compiled_rules, tmp_path / "missing.bin")
    assert missing_result.success is False
    assert any("File not found:" in err for err in missing_result.errors)

    dir_result = scanner.scan_file(compilation.compiled_rules, tmp_path)
    assert dir_result.success is False
    assert dir_result.errors

    data_error = scanner.scan_data(object(), b"abc")
    assert data_error.success is False
    assert any("Unexpected error:" in err for err in data_error.errors)

    proc_ok = scanner.scan_process(compilation.compiled_rules, os.getpid())
    assert proc_ok.scan_time >= 0
    assert proc_ok.success in {True, False}

    proc_bad = scanner.scan_process(compilation.compiled_rules, -1)
    assert proc_bad.success is False
    assert proc_bad.errors


@pytest.mark.skipif(
    not COMPILER_AVAILABLE or not SCANNER_AVAILABLE, reason="yara-python not available"
)
def test_libyara_scanner_timeout_paths(tmp_path: Path) -> None:
    compiler = LibyaraCompiler()
    scanner = LibyaraScanner(timeout=1)
    compilation = compiler.compile_source("rule slow { strings: $a = /a.*b/ condition: $a }")
    assert compilation.success is True

    data_result = scanner.scan_data(compilation.compiled_rules, b"a" * 100000 + b"b")
    assert data_result.success is False
    assert data_result.errors == ["Scan timeout after 1 seconds"]

    file_path = tmp_path / "slow.bin"
    file_path.write_bytes(b"a" * 100000 + b"b")
    file_result = scanner.scan_file(compilation.compiled_rules, file_path)
    assert file_result.success is False
    assert file_result.errors == ["Scan timeout after 1 seconds"]


@pytest.mark.skipif(not YARA_AVAILABLE, reason="yara-python not available")
def test_direct_compiler_and_matcher_additional_paths(tmp_path: Path) -> None:
    source = """
    rule hint_rule {
        strings:
            $a = "abc"
        condition:
            $a
    }
    """
    ast = Parser().parse(source)
    compiler = DirectASTCompiler(enable_optimization=False)
    compiled = compiler.compile_ast(ast)
    assert compiled.success is True
    assert "rule hint_rule" in compiler.compile_to_yara(ast)

    stats = compiler.get_compilation_stats()
    assert stats["total_compilations"] >= 1
    compiler.reset_stats()
    assert compiler.get_compilation_stats()["total_compilations"] == 0

    compile_fail_ast = YaraFile(rules=[Rule(name="bad name", condition=BooleanLiteral(True))])
    compile_fail = compiler.compile_ast(compile_fail_ast)
    assert compile_fail.success is False
    assert compiler.get_compilation_stats()["failed_compilations"] == 1

    matcher = OptimizedMatcher(compiled.compiled_rules, ast=ast)
    initial = matcher.get_scan_stats()
    assert initial["average_scan_time"] == 0.0
    assert initial["success_rate"] == 0.0

    data_path = tmp_path / "match.txt"
    data_path.write_bytes(b"zzz")

    no_match = matcher.scan(str(data_path))
    assert no_match["success"] is True
    assert no_match["matches"] == []
    assert "No matches found - consider rule optimization" in no_match["optimization_hints"]

    bad_type = matcher.scan(["bad-data"])  # type: ignore[list-item]
    assert bad_type["success"] is False
    assert "Unsupported data type" in bad_type["error"]

    pid_scan = matcher.scan(os.getpid(), timeout=5)
    assert pid_scan["scan_time"] >= 0

    assert matcher._get_ast_context_for_rule("missing") is None
    assert OptimizedMatcher(compiled.compiled_rules)._get_ast_context_for_rule("hint_rule") is None
    assert matcher._estimate_condition_complexity(None) == 0


@pytest.mark.skipif(not YARA_AVAILABLE, reason="yara-python not available")
def test_direct_matcher_hints_for_complex_rule() -> None:
    many_strings = "\n".join(f'$s{i} = "a"' for i in range(21))
    all_refs = " and ".join(f"$s{i}" for i in range(21))
    ast = Parser().parse(
        f"""
        rule complex_rule {{
            strings:
                {many_strings}
            condition:
                (((((((((true and true) and true) and true) and true) and true) and true) and true) and true) and true) and ({all_refs})
        }}
        """
    )
    compiler = DirectASTCompiler(enable_optimization=False)
    result = compiler.compile_ast(ast)
    assert result.success is True

    matcher = OptimizedMatcher(result.compiled_rules, ast=ast)
    scan = matcher.scan(b"a")
    assert scan["success"] is True
    assert scan["matches"]
    assert any("complex condition" in hint for hint in scan["optimization_hints"])
    assert any("many strings" in hint for hint in scan["optimization_hints"])
    assert scan["rule_count"] == 1
    assert scan["ast_enhanced"] is True
    assert scan["matches"][0]["ast_context"] is not None
    assert scan["matches"][0]["ast_context"]["condition_complexity"] > 10
