"""Real tests for libyara AST optimizer (no mocks)."""

from __future__ import annotations

import pytest

from yaraast.libyara.ast_optimizer import ASTOptimizer
from yaraast.libyara.compiler import YARA_AVAILABLE as COMPILER_AVAILABLE
from yaraast.parser import Parser


@pytest.mark.skipif(not COMPILER_AVAILABLE, reason="yara-python not available")
def test_ast_optimizer_removes_unused_strings_and_simplifies() -> None:
    code = """
    rule opt_rule {
        strings:
            $a = "abc"
            $b = "def"
        condition:
            $a and (true and false)
    }
    """
    ast = Parser().parse(code)
    optimizer = ASTOptimizer()
    optimized = optimizer.optimize(ast)

    assert optimizer.stats.strings_optimized >= 1
    assert optimizer.stats.dead_code_removed >= 1
    assert optimizer.stats.conditions_simplified >= 1
    assert optimizer.optimizations_applied

    rule = optimized.rules[0]
    assert len(rule.strings) == 1
