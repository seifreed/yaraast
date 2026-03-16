"""Tests for parallel analyzer (no mocks)."""

from __future__ import annotations

from pathlib import Path
from textwrap import dedent

from yaraast.parser import Parser
from yaraast.performance.parallel_analyzer import ParallelAnalyzer


def _parse_rules() -> list:
    code = """
    rule p1 { condition: true }
    rule p2 { condition: true }
    """
    parser = Parser()
    ast = parser.parse(dedent(code))
    return ast.rules


def test_parallel_analyzer_analyze_rules_and_file(tmp_path: Path) -> None:
    rules = _parse_rules()
    parser = Parser()
    ast = parser.parse("rule p1 { condition: true }")

    analyzer = ParallelAnalyzer(max_workers=1)
    results = analyzer.analyze_rules(rules, max_workers=1)
    assert len(results) == len(rules)

    file_result = analyzer.analyze_file(ast, max_workers=1)
    assert file_result["stats"]["total_rules"] == len(ast.rules)

    stats = analyzer.get_statistics()
    assert stats["rules_analyzed"] >= 1


def test_parallel_analyzer_batch_and_profile(tmp_path: Path) -> None:
    rules = _parse_rules()
    analyzer = ParallelAnalyzer(max_workers=1)

    profile = analyzer.profile_performance(rules, worker_counts=[1])
    assert profile["optimal_workers"] == 1

    # Custom function analysis (run with 1 worker for reliability)
    custom = analyzer.analyze_with_custom_function(rules, lambda r: {"rule": r.name}, max_workers=1)
    assert len(custom) == len(rules)


def test_parallel_analyzer_parse_files(tmp_path: Path) -> None:
    p1 = tmp_path / "a.yar"
    p2 = tmp_path / "b.yar"
    p1.write_text("rule a { condition: true }", encoding="utf-8")
    p2.write_text("rule b { condition: true }", encoding="utf-8")

    analyzer = ParallelAnalyzer(max_workers=1)
    jobs = analyzer.parse_files_parallel([str(p1), str(p2)], chunk_size=1)
    assert jobs
    assert all(job.is_completed for job in jobs)

    # parse_files uses ThreadPoolExecutor internally
    file_results = analyzer.batch_analyze_files([str(p1), str(p2)], max_workers=1)
    assert len(file_results) == 2
