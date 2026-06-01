"""Additional real coverage for performance optimizer."""

from __future__ import annotations

from pathlib import Path
from typing import Any, cast

from click.testing import CliRunner
import pytest

from yaraast.ast.base import YaraFile
from yaraast.ast.expressions import Identifier
from yaraast.ast.rules import Rule
from yaraast.ast.strings import HexByte, HexString, PlainString, RegexString
from yaraast.cli.commands.bench_cmd import bench
from yaraast.performance.optimizer import PerformanceOptimizer


def _fresh_text(value: str) -> str:
    return ("_" + value)[1:]


def test_performance_optimizer_dispatch_and_complexity_paths() -> None:
    optimizer = PerformanceOptimizer()

    empty_rule = Rule(name="empty")
    optimized_rule = optimizer.optimize(empty_rule, strategy="speed")
    assert optimized_rule is not empty_rule
    assert optimized_rule == empty_rule

    yara_file = YaraFile(
        rules=[Rule(name="a"), Rule(name="b", condition=Identifier(name="for loop and or"))]
    )
    optimized_file = optimizer.optimize(yara_file, strategy="memory")
    assert optimized_file is not yara_file
    assert [rule.name for rule in optimized_file.rules] == ["a", "b"]
    assert optimizer.get_statistics()["rules_optimized"] == 3

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
        strings=[
            PlainString(identifier="$a", value=cast(Any, None)),
        ],  # runtime-malformed but real AST object
    )

    optimized = optimizer.optimize_rule(rule, strategy="speed")
    assert optimized is not rule
    assert optimized == rule
    assert optimizer.get_statistics()["strings_optimized"] == 0

    first_value = _fresh_text("abc")
    second_value = _fresh_text("abc")
    memory_only_rule = Rule(
        name="mem_only",
        strings=[
            PlainString(identifier="$a", value=first_value),
            PlainString(identifier="$b", value=second_value),
        ],
    )
    optimized_memory = optimizer.optimize_rule(memory_only_rule, strategy="memory")
    assert optimized_memory is not memory_only_rule
    first_string = optimized_memory.strings[0]
    second_string = optimized_memory.strings[1]
    assert isinstance(first_string, PlainString)
    assert isinstance(second_string, PlainString)
    assert first_string.value is second_string.value


@pytest.mark.parametrize("strategy", [None, 123])
def test_performance_optimizer_rejects_non_string_strategies(strategy: object) -> None:
    optimizer = PerformanceOptimizer()
    rule = Rule(name="sample")
    ast = YaraFile(rules=[rule])

    with pytest.raises(TypeError, match="optimization strategy must be a string"):
        optimizer.optimize_rule(rule, strategy=cast(Any, strategy))
    with pytest.raises(TypeError, match="optimization strategy must be a string"):
        optimizer.optimize_file(ast, strategy=cast(Any, strategy))
    with pytest.raises(TypeError, match="optimization strategy must be a string"):
        optimizer.optimize(object(), strategy=cast(Any, strategy))


def test_performance_optimizer_rejects_unknown_strategy() -> None:
    optimizer = PerformanceOptimizer()
    rule = Rule(name="sample")
    ast = YaraFile(rules=[rule])

    with pytest.raises(ValueError, match="optimization strategy must be one of"):
        optimizer.optimize_rule(rule, strategy="fast")
    with pytest.raises(ValueError, match="optimization strategy must be one of"):
        optimizer.optimize_file(ast, strategy="fast")
    with pytest.raises(ValueError, match="optimization strategy must be one of"):
        optimizer.optimize(object(), strategy="fast")


def test_bench_command_skips_failed_operation_results(tmp_path: Path) -> None:
    runner = CliRunner()
    invalid_yara = tmp_path / "invalid.yar"
    invalid_yara.write_text("rule broken { condition: }", encoding="utf-8")

    result = runner.invoke(
        bench,
        [str(invalid_yara), "--operations", "parse", "--iterations", "1"],
    )

    assert result.exit_code == 0
    assert "Parse" in result.output or "parse" in result.output
    assert "Benchmarking completed!" in result.output
