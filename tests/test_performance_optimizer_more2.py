"""Additional real coverage for performance optimizer."""

from __future__ import annotations

from pathlib import Path

from click.testing import CliRunner

from yaraast.ast.base import YaraFile
from yaraast.ast.expressions import Identifier
from yaraast.ast.rules import Rule
from yaraast.ast.strings import HexByte, HexString, PlainString, RegexString
from yaraast.cli.commands.bench_cmd import bench
from yaraast.performance.optimizer import PerformanceOptimizer


def test_performance_optimizer_dispatch_and_complexity_paths() -> None:
    optimizer = PerformanceOptimizer()

    empty_rule = Rule(name="empty")
    optimized_rule = optimizer.optimize(empty_rule, strategy="speed")
    assert optimized_rule is empty_rule

    yara_file = YaraFile(
        rules=[Rule(name="a"), Rule(name="b", condition=Identifier(name="for loop and or"))]
    )
    optimized_file = optimizer.optimize(yara_file, strategy="memory")
    assert optimized_file is yara_file

    other = object()
    assert optimizer.optimize(other, strategy="balanced") is other

    assert optimizer._rule_complexity(Rule(name="bare")) == 0

    rich_rule = Rule(
        name="rich",
        strings=[
            RegexString(identifier="$re", regex="ab.*"),
            HexString(identifier="$hx", tokens=[HexByte(value=0x41), HexByte(value=0x42)]),
        ],
        condition=Identifier(name="for and or"),
    )
    assert optimizer._rule_complexity(rich_rule) > 0


def test_performance_optimizer_handles_unexpected_string_values() -> None:
    optimizer = PerformanceOptimizer()
    rule = Rule(
        name="weird",
        strings=[PlainString(identifier="$a", value=None)],  # runtime-malformed but real AST object
    )

    optimized = optimizer.optimize_rule(rule, strategy="speed")
    assert optimized is rule
    assert optimizer.get_statistics()["strings_optimized"] == 0

    memory_only_rule = Rule(name="mem_only", strings=[PlainString(identifier="$b", value="abc")])
    optimized_memory = optimizer.optimize_rule(memory_only_rule, strategy="memory")
    assert optimized_memory is memory_only_rule


def test_bench_command_skips_failed_operation_results(tmp_path: Path) -> None:
    runner = CliRunner()
    invalid_yara = tmp_path / "invalid.yar"
    invalid_yara.write_text("rule broken { condition: }")

    result = runner.invoke(
        bench,
        [str(invalid_yara), "--operations", "parse", "--iterations", "1"],
    )

    assert result.exit_code == 0
    assert "Parse" in result.output or "parse" in result.output
    assert "Benchmarking completed!" in result.output
