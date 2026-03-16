"""Extra real coverage for performance string analyzer and batch processor."""

from __future__ import annotations

from pathlib import Path
from textwrap import dedent

from yaraast.ast.conditions import Condition
from yaraast.ast.rules import Rule
from yaraast.ast.strings import HexByte, HexString, PlainString
from yaraast.parser import Parser
from yaraast.performance.batch_processor import BatchOperation, BatchProcessor
from yaraast.performance.string_analyzer import (
    StringPatternAnalyzer,
    _estimate_rule_cost,
    analyze_rule_performance,
)


def _parse_rule(code: str) -> Rule:
    return Parser().parse(dedent(code)).rules[0]


def test_string_pattern_analyzer_empty_and_prefix_tree_paths() -> None:
    analyzer = StringPatternAnalyzer()

    empty_rule = Rule(name="empty")
    assert analyzer.analyze_rule(empty_rule) == {
        "rule": "empty",
        "strings": 0,
        "analysis": None,
    }
    assert analyzer._analyze_lengths([]) == {
        "min": 0,
        "max": 0,
        "average": 0,
        "distribution": {},
    }

    strings = [
        "prefixAAA",
        "prefixAAB",
        "prefixAAC",
        "prefixAAD",
        "prefixAAE",
        "prefixAAF",
    ]
    prefixes = analyzer._find_common_prefixes(strings)
    optimizations = analyzer._find_optimizations(strings, {}, prefixes, {})
    assert any(opt["type"] == "prefix_tree" for opt in optimizations)


def test_string_rule_performance_and_cost_extra_paths() -> None:
    no_strings_rule = Rule(name="nostrings", condition=Condition())
    assert analyze_rule_performance(no_strings_rule) == []
    assert _estimate_rule_cost(no_strings_rule) == 0

    hex_rule = Rule(
        name="hex_cost",
        strings=[HexString(identifier="$h", tokens=[HexByte(value=0x41)])],
        condition=Condition(),
    )
    assert _estimate_rule_cost(hex_rule) == 2

    plain_long_rule = Rule(
        name="long_plain",
        strings=[PlainString(identifier="$a", value="abcdef")],
        condition=Condition(),
    )
    assert analyze_rule_performance(plain_long_rule) == []

    regex_rule = _parse_rule(
        """
        rule regex_cost {
            strings:
                $r = /ab+c/
            condition:
                $r
        }
        """
    )
    assert _estimate_rule_cost(regex_rule) >= 10


def test_string_pattern_analyzer_skips_rules_without_strings_in_file_analysis() -> None:
    code = """
    rule empty_one {
        condition:
            true
    }
    rule with_strings {
        strings:
            $a = "abc"
        condition:
            $a
    }
    rule empty_two {
        condition:
            true
    }
    """
    ast = Parser().parse(dedent(code))
    analysis = StringPatternAnalyzer().analyze_file(ast)

    assert len(analysis["per_rule"]) == 1
    assert analysis["per_rule"][0]["rule"] == "with_strings"
    assert analysis["cross_rule"]["total_unique"] == 1


def test_batch_processor_multiple_operations_and_progress(tmp_path: Path) -> None:
    code = """
    rule one {
        strings:
            $a = "abc"
        condition:
            $a
    }
    """
    path = tmp_path / "one.yar"
    path.write_text(dedent(code), encoding="utf-8")

    progress_calls: list[tuple[str, int, int]] = []

    def progress(stage: str, done: int, total: int) -> None:
        progress_calls.append((stage, done, total))

    processor = BatchProcessor(progress_callback=progress)
    out_dir = tmp_path / "out"

    results = processor.process_files(
        [path],
        [BatchOperation.HTML_TREE, BatchOperation.SERIALIZE],
        output_dir=out_dir,
    )

    assert BatchOperation.HTML_TREE in results
    assert BatchOperation.SERIALIZE in results
    assert results[BatchOperation.HTML_TREE].successful_count == 1
    assert results[BatchOperation.SERIALIZE].successful_count == 1
    assert any(call[0] == "Processing html_tree" for call in progress_calls)
    assert any(call[0] == "Processing serialize" for call in progress_calls)


def test_batch_processor_process_files_complexity_summary(tmp_path: Path) -> None:
    code = """
    rule one {
        strings:
            $a = "abc"
        condition:
            $a
    }
    """
    path = tmp_path / "complexity.yar"
    path.write_text(dedent(code), encoding="utf-8")

    result = BatchProcessor().process_files([path], BatchOperation.COMPLEXITY)

    assert result.successful_count == 1
    assert "one" in result.summary


def test_batch_processor_large_file_parse_and_unhandled_ops(tmp_path: Path) -> None:
    code = """
    rule a { condition: true }
    rule b { condition: true }
    """
    path = tmp_path / "many.yar"
    path.write_text(dedent(code), encoding="utf-8")

    processor = BatchProcessor()
    results = processor.process_large_file(
        path,
        operations=[BatchOperation.PARSE, BatchOperation.SERIALIZE],
        output_dir=tmp_path,
        split_rules=False,
    )

    assert results[BatchOperation.PARSE].successful_count == 1
    assert results[BatchOperation.SERIALIZE].successful_count == 0
    assert results[BatchOperation.SERIALIZE].failed_count == 0
