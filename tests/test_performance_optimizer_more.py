"""More tests for performance optimizer (no mocks)."""

from __future__ import annotations

from pathlib import Path
from textwrap import dedent
from typing import Any, cast

import pytest

from yaraast.ast.base import YaraFile
from yaraast.ast.strings import PlainString, RegexString
from yaraast.parser import Parser
from yaraast.performance.optimizer import PerformanceOptimizer, optimize_yara_file


def _parse_yara(code: str) -> YaraFile:
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
    assert optimized_rule is not rule
    assert isinstance(optimized_rule.strings[0], PlainString)
    assert optimized_rule.strings[0].identifier == "$a"
    assert isinstance(optimized_rule.strings[-1], RegexString)

    optimized_file = optimizer.optimize(ast, strategy="speed")
    assert optimized_file is not ast
    assert [string.identifier for string in ast.rules[0].strings] == ["$a", "$b", "$c"]

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
    assert stats["rules_optimized"] == 1


def test_optimize_yara_file_rejects_empty_output_path(tmp_path: Path) -> None:
    path = tmp_path / "perf.yar"
    path.write_text("rule perf { condition: true }", encoding="utf-8")

    with pytest.raises(ValueError, match="output_path must not be empty"):
        optimize_yara_file(str(path), output_path="")


def test_optimize_yara_file_rejects_directory_paths(tmp_path: Path) -> None:
    input_dir = tmp_path / "input_dir"
    input_dir.mkdir()
    output_dir = tmp_path / "output_dir"
    output_dir.mkdir()
    path = tmp_path / "perf.yar"
    path.write_text("rule perf { condition: true }", encoding="utf-8")

    with pytest.raises(ValueError, match="file_path must not be a directory"):
        optimize_yara_file(input_dir)
    with pytest.raises(ValueError, match="output_path must not be a directory"):
        optimize_yara_file(path, output_path=output_dir)


@pytest.mark.parametrize("value", [False, 0, object()])
def test_optimize_yara_file_rejects_invalid_path_types(value: Any, tmp_path: Path) -> None:
    path = tmp_path / "perf.yar"
    path.write_text("rule perf { condition: true }", encoding="utf-8")

    with pytest.raises(TypeError, match="file_path must be a file path"):
        optimize_yara_file(cast(Any, value))
    with pytest.raises(TypeError, match="output_path must be a file path"):
        optimize_yara_file(path, output_path=cast(Any, value))
