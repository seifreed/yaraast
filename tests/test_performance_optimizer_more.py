"""More tests for performance optimizer (no mocks)."""

from __future__ import annotations

from pathlib import Path
from textwrap import dedent

from yaraast.parser import Parser
from yaraast.performance.optimizer import PerformanceOptimizer, optimize_yara_file


def _parse_yara(code: str):
    parser = Parser()
    return parser.parse(dedent(code))


def test_performance_optimizer_rule_and_file() -> None:
    code = """
    rule perf_opt {
        strings:
            $a = "abcd"
            $b = /ab+c/
            $c = { 6A 40 ?? }
        condition:
            $a or $b or $c
    }
    rule perf_opt2 {
        strings:
            $a = "a"
        condition:
            $a
    }
    """
    ast = _parse_yara(code)
    optimizer = PerformanceOptimizer()

    rule = ast.rules[0]
    optimized_rule = optimizer.optimize_rule(rule, strategy="balanced")
    assert optimized_rule is rule

    optimized_file = optimizer.optimize(ast, strategy="speed")
    assert optimized_file is ast

    stats = optimizer.get_statistics()
    assert stats["rules_optimized"] >= 1
    optimizer.reset_statistics()
    assert optimizer.get_statistics()["rules_optimized"] == 0


def test_optimize_yara_file(tmp_path: Path) -> None:
    code = """
    rule perf_opt_file {
        strings:
            $a = "abc"
        condition:
            $a
    }
    """
    path = tmp_path / "perf.yar"
    out = tmp_path / "perf_out.yar"
    path.write_text(dedent(code), encoding="utf-8")

    ast, stats = optimize_yara_file(str(path), output_path=str(out), strategy="memory")
    assert ast.rules
    assert out.exists()
    assert "rules_optimized" in stats
