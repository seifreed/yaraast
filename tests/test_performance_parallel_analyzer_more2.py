"""Additional real tests for ParallelAnalyzer."""

from __future__ import annotations

from pathlib import Path
from threading import Event
from typing import Any, cast

import pytest

from yaraast.ast.base import YaraFile
from yaraast.ast.rules import Rule
from yaraast.cli.performance_services import extract_successful_asts
from yaraast.metrics import dependency_graph_utils
from yaraast.parser import Parser, source as parser_source
from yaraast.performance.parallel_analyzer import ParallelAnalyzer


def _rule_code(name: str = "r") -> str:
    return f"""
    rule {name} {{
        strings:
            $a = "abc"
        condition:
            $a
    }}
    """


def _yarax_rule() -> str:
    return "rule x { condition: with xs = [1]: match xs { _ => true } }"


def _parsed_ast(name: str = "r") -> YaraFile:
    return Parser().parse(_rule_code(name))


def _worker_rule_name(rule: Rule, _parameters: dict[str, Any]) -> str:
    return rule.name


def _worker_fail_on_b(rule: Rule, _parameters: dict[str, Any]) -> str:
    if getattr(rule, "name", "") == "b":
        msg = "bad rule"
        raise ValueError(msg)
    return rule.name


def _custom_rule_name(rule: Rule) -> dict[str, str]:
    return {"rule": rule.name}


def _custom_fail_on_b(rule: Rule) -> dict[str, str]:
    if getattr(rule, "name", "") == "b":
        msg = "custom failure"
        raise ValueError(msg)
    return {"rule": rule.name}


def test_parallel_analyzer_direct_methods_and_stats(tmp_path: Path) -> None:
    ast = _parsed_ast("direct")
    rule = ast.rules[0]
    file_path = tmp_path / "direct.yar"
    file_path.write_text(_rule_code("direct"), encoding="utf-8")

    analyzer = ParallelAnalyzer(max_workers=1)

    single = analyzer._analyze_single_rule(rule)
    assert single["summary"]["total_rules"] == 1

    by_path = analyzer._analyze_file_path(str(file_path))
    assert by_path["file"] == str(file_path)
    assert by_path["stats"]["total_rules"] == 1

    stats = analyzer.get_statistics()
    assert stats["avg_time_per_rule"] >= 0
    assert stats["max_workers"] == 1

    analyzer.reset_statistics()
    reset = analyzer.get_statistics()
    assert reset["rules_analyzed"] == 0
    assert reset["errors"] == 0
    assert reset["total_time"] == 0.0
    assert reset["jobs_submitted"] == 0
    assert reset["jobs_completed"] == 0
    assert reset["jobs_failed"] == 0

    jobs_after_reset = analyzer.parse_files_parallel([str(file_path)], chunk_size=1)
    assert len(jobs_after_reset) == 1
    assert jobs_after_reset[0].status.value == "completed"
    reset_stats = analyzer.get_statistics()
    assert reset_stats["jobs_submitted"] == 1
    assert reset_stats["jobs_completed"] == 1
    assert reset_stats["jobs_failed"] == 0


def test_parallel_analyzer_accepts_yarax_files(tmp_path: Path) -> None:
    file_path = tmp_path / "x.yar"
    file_path.write_text(_yarax_rule(), encoding="utf-8")
    analyzer = ParallelAnalyzer(max_workers=1)

    by_path = analyzer._analyze_file_path(str(file_path))

    assert by_path["file"] == str(file_path)
    assert by_path["stats"]["total_rules"] == 1

    jobs = analyzer.parse_files_parallel([str(file_path)], chunk_size=1)

    assert len(jobs) == 1
    assert jobs[0].status.value == "completed"
    assert jobs[0].result[0].rules[0].name == "x"


def test_parallel_analyzer_batch_analyze_files_preserves_input_order(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    slow_path = tmp_path / "slow.yar"
    fast_path = tmp_path / "fast.yar"
    slow_path.write_text(_rule_code("slow"), encoding="utf-8")
    fast_path.write_text(_rule_code("fast"), encoding="utf-8")
    fast_finished = Event()
    analyzer = ParallelAnalyzer(max_workers=2)

    def delayed_analyze_file_path(file_path: str) -> dict[str, Any]:
        if file_path == str(slow_path):
            fast_finished.wait(timeout=1)
        result = {"file": file_path, "analysis": file_path}
        if file_path == str(fast_path):
            fast_finished.set()
        return result

    monkeypatch.setattr(analyzer, "_analyze_file_path", delayed_analyze_file_path)

    results = analyzer.batch_analyze_files([str(slow_path), str(fast_path)], max_workers=2)

    assert [result["file"] for result in results] == [str(slow_path), str(fast_path)]


def test_parallel_analyzer_rejects_invalid_worker_counts(tmp_path: Path) -> None:
    ast = _parsed_ast("workers")
    rules = ast.rules
    file_path = tmp_path / "workers.yar"
    file_path.write_text(_rule_code("workers"), encoding="utf-8")

    with pytest.raises(TypeError, match="max_workers must be an integer"):
        ParallelAnalyzer(max_workers=cast(Any, True))

    with pytest.raises(ValueError, match="max_workers must be at least 1"):
        ParallelAnalyzer(max_workers=0)

    analyzer = ParallelAnalyzer(max_workers=1)
    with pytest.raises(TypeError, match="max_workers must be an integer"):
        analyzer.analyze_rules(rules, max_workers=cast(Any, True))
    with pytest.raises(TypeError, match="max_workers must be an integer"):
        analyzer.batch_analyze_files([str(file_path)], max_workers=cast(Any, True))
    with pytest.raises(TypeError, match="max_workers must be an integer"):
        analyzer.analyze_with_custom_function(rules, _custom_rule_name, max_workers=cast(Any, True))
    with pytest.raises(TypeError, match="worker_counts must contain integers"):
        analyzer.profile_performance(rules, worker_counts=cast(Any, [True]))

    with pytest.raises(ValueError, match="max_workers must be at least 1"):
        analyzer.analyze_rules(rules, max_workers=0)
    with pytest.raises(ValueError, match="max_workers must be at least 1"):
        analyzer.batch_analyze_files([str(file_path)], max_workers=0)
    with pytest.raises(ValueError, match="max_workers must be at least 1"):
        analyzer.analyze_with_custom_function(rules, _custom_rule_name, max_workers=0)
    with pytest.raises(ValueError, match="worker_counts must contain values at least 1"):
        analyzer.profile_performance(rules, worker_counts=[0])


def test_parallel_analyzer_rejects_single_string_file_paths(tmp_path: Path) -> None:
    file_path = tmp_path / "single.yar"
    file_path.write_text(_rule_code("single"), encoding="utf-8")
    analyzer = ParallelAnalyzer(max_workers=1)

    with pytest.raises(TypeError, match="file_paths must be a sequence of paths"):
        analyzer.parse_files_parallel(cast(Any, str(file_path)), chunk_size=1)

    with pytest.raises(TypeError, match="file_paths must be a sequence of paths"):
        analyzer.batch_analyze_files(cast(Any, str(file_path)), max_workers=1)


def test_parallel_analyzer_batch_profile_and_optimal_workers(tmp_path: Path) -> None:
    analyzer = ParallelAnalyzer(max_workers=1)
    small_rules = Parser().parse(_rule_code("a") + _rule_code("b")).rules
    medium_rules = Parser().parse("\n".join(_rule_code(f"m{i}") for i in range(20))).rules
    large_rules = Parser().parse("\n".join(_rule_code(f"l{i}") for i in range(60))).rules
    huge_rules = Parser().parse("\n".join(_rule_code(f"h{i}") for i in range(210))).rules

    assert analyzer.optimize_worker_count(small_rules) == 1
    assert analyzer.optimize_worker_count(medium_rules) <= 4
    assert analyzer.optimize_worker_count(large_rules) <= 8
    assert analyzer.optimize_worker_count(huge_rules) >= 1

    profile = analyzer.profile_performance(small_rules)
    assert profile["rule_count"] == len(small_rules)
    assert profile["optimal_workers"] in profile["worker_performance"]

    limited_profile = analyzer.profile_performance(small_rules, worker_counts=[1, 10_000])
    assert 1 in limited_profile["worker_performance"]
    assert 10_000 not in limited_profile["worker_performance"]

    invalid_profile = analyzer.profile_performance(small_rules, worker_counts=[10_000])
    assert invalid_profile == {
        "worker_performance": {},
        "optimal_workers": None,
        "rule_count": len(small_rules),
    }

    empty_profile = analyzer.profile_performance(small_rules, worker_counts=[])
    assert empty_profile == {
        "worker_performance": {},
        "optimal_workers": None,
        "rule_count": len(small_rules),
    }

    analyzer.reset_statistics()
    empty_after_reset = analyzer.profile_performance(small_rules, worker_counts=[])
    assert empty_after_reset["worker_performance"] == {}
    assert analyzer.get_statistics()["rules_analyzed"] == 0

    analyzer.reset_statistics()
    jobs = analyzer.process_batch(small_rules, _worker_rule_name, job_type="names")
    assert [job.result for job in jobs] == ["a", "b"]
    stats = analyzer.get_statistics()
    assert stats["jobs_submitted"] == 2
    assert stats["jobs_completed"] == 2
    assert stats["jobs_failed"] == 0

    failing_jobs = analyzer.process_batch(small_rules, _worker_fail_on_b, job_type="names")
    assert failing_jobs[0].status.value == "completed"
    assert failing_jobs[1].status.value == "failed"
    failed_error = failing_jobs[1].error
    assert failed_error is not None
    assert "bad rule" in failed_error
    failing_stats = analyzer.get_statistics()
    assert failing_stats["jobs_submitted"] == 4
    assert failing_stats["jobs_completed"] == 3
    assert failing_stats["jobs_failed"] == 1


def test_parallel_analyzer_files_custom_and_graphs(tmp_path: Path) -> None:
    good_a = tmp_path / "a.yar"
    good_b = tmp_path / "b.yar"
    bad = tmp_path / "broken.yar"
    good_a.write_text(_rule_code("a"), encoding="utf-8")
    good_b.write_text(_rule_code("b"), encoding="utf-8")
    bad.write_text("rule broken { condition: ", encoding="utf-8")

    analyzer = ParallelAnalyzer(max_workers=1)

    file_results = analyzer.batch_analyze_files([str(good_a), str(bad)], max_workers=1)
    assert len(file_results) == 2
    assert any(result.get("analysis") is None for result in file_results)
    assert any(result.get("file") == str(good_a) for result in file_results)

    rules = Parser().parse(_rule_code("a") + _rule_code("b")).rules
    custom_ok = analyzer.analyze_with_custom_function(rules, _custom_rule_name, max_workers=1)
    assert len(custom_ok) == 2
    assert all("rule" in item for item in custom_ok)

    custom_fail = analyzer.analyze_with_custom_function(rules, _custom_fail_on_b, max_workers=1)
    assert len(custom_fail) == 2
    assert any(item.get("error") == "custom failure" for item in custom_fail)

    parse_jobs = analyzer.parse_files_parallel([str(good_a), str(bad)], chunk_size=1)
    assert len(parse_jobs) == 2
    assert parse_jobs[0].is_completed and parse_jobs[1].is_completed
    assert any(job.status.value == "failed" for job in parse_jobs)

    with pytest.raises(ValueError, match="chunk_size must be at least 1"):
        analyzer.parse_files_parallel([str(good_a)], chunk_size=0)

    with pytest.raises(TypeError, match="chunk_size must be an integer"):
        analyzer.parse_files_parallel([str(good_a)], chunk_size=cast(Any, True))

    with pytest.raises(TypeError, match="parameters must be a dictionary"):
        analyzer.process_batch(rules, _worker_rule_name, parameters=cast(Any, []))

    ast = _parsed_ast("graph_rule")
    graph_jobs = analyzer.generate_graphs_parallel([ast], tmp_path / "graphs", ["full", "rules"])
    assert len(graph_jobs) == 1
    assert graph_jobs[0].status.value == "completed"
    for output in graph_jobs[0].result:
        assert Path(output).exists()


@pytest.mark.parametrize("graph_types", ["full", b"full"])
def test_parallel_graph_export_rejects_scalar_graph_types(
    tmp_path: Path,
    graph_types: object,
) -> None:
    analyzer = ParallelAnalyzer(max_workers=1)
    ast = _parsed_ast("graph_rule")

    with pytest.raises(TypeError, match="graph_types must be a sequence of strings"):
        analyzer.generate_graphs_parallel(
            [ast],
            tmp_path / "graphs",
            cast(Any, graph_types),
        )


@pytest.mark.parametrize("graph_types", [[123], [None], [""]])
def test_parallel_graph_export_rejects_invalid_graph_type_entries(
    tmp_path: Path,
    graph_types: object,
) -> None:
    analyzer = ParallelAnalyzer(max_workers=1)
    ast = _parsed_ast("graph_rule")

    with pytest.raises(TypeError, match="graph_types must contain non-empty strings"):
        analyzer.generate_graphs_parallel(
            [ast],
            tmp_path / "graphs",
            cast(Any, graph_types),
        )


def test_parallel_parse_mixed_chunk_preserves_successful_files(tmp_path: Path) -> None:
    good_a = tmp_path / "a.yar"
    bad = tmp_path / "broken.yar"
    good_b = tmp_path / "b.yar"
    good_a.write_text(_rule_code("a"), encoding="utf-8")
    bad.write_text("rule broken { condition: ", encoding="utf-8")
    good_b.write_text(_rule_code("b"), encoding="utf-8")
    file_paths = [good_a, bad, good_b]

    analyzer = ParallelAnalyzer(max_workers=1)
    jobs = analyzer.parse_files_parallel([str(path) for path in file_paths], chunk_size=3)

    assert len(jobs) == 1
    assert jobs[0].status.value == "failed"
    assert jobs[0].result is not None
    assert [getattr(ast, "_parse_error", False) for ast in jobs[0].result] == [
        False,
        True,
        False,
    ]

    asts, file_names = extract_successful_asts(jobs, file_paths, chunk_size=3)
    assert [ast.rules[0].name for ast in asts] == ["a", "b"]
    assert file_names == [str(good_a), str(good_b)]


def test_parallel_parse_file_chunks_propagates_internal_parser_errors(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    file_path = tmp_path / "ok.yar"
    file_path.write_text(_rule_code("ok"), encoding="utf-8")
    analyzer = ParallelAnalyzer(max_workers=1)

    def broken_parse_yara_source(_content: str) -> YaraFile:
        raise AttributeError("parser state missing")

    monkeypatch.setattr(parser_source, "parse_yara_source", broken_parse_yara_source)

    with pytest.raises(AttributeError, match="parser state missing"):
        analyzer.parse_files_parallel([str(file_path)], chunk_size=1)


def test_parallel_graph_export_propagates_internal_export_errors(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    analyzer = ParallelAnalyzer(max_workers=1)
    ast = _parsed_ast("graph_rule")

    def broken_export_dependency_graph(*_args: object, **_kwargs: object) -> None:
        raise AttributeError("graph exporter state missing")

    monkeypatch.setattr(
        dependency_graph_utils,
        "export_dependency_graph",
        broken_export_dependency_graph,
    )

    with pytest.raises(AttributeError, match="graph exporter state missing"):
        analyzer.generate_graphs_parallel([ast], tmp_path / "graphs", ["full"])


def test_parallel_complexity_jobs_propagate_internal_analysis_errors(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    analyzer = ParallelAnalyzer(max_workers=1)
    ast = _parsed_ast("complexity_rule")

    def broken_analyze_file(*_args: object, **_kwargs: object) -> dict[str, object]:
        raise AttributeError("complexity analyzer state missing")

    monkeypatch.setattr(analyzer, "analyze_file", broken_analyze_file)

    with pytest.raises(AttributeError, match="complexity analyzer state missing"):
        analyzer.analyze_complexity_parallel([ast])


def test_parallel_analyzer_error_paths_without_mocks(tmp_path: Path) -> None:
    analyzer = ParallelAnalyzer(max_workers=1)

    bad_rules = [Parser().parse(_rule_code("ok")).rules[0], "not-a-rule"]
    results = analyzer.analyze_rules(cast(Any, bad_rules), max_workers=1)
    assert len(results) == 2
    assert any(item.get("analysis") is None for item in results if isinstance(item, dict))
    assert analyzer.get_statistics()["errors"] >= 1

    bad_graph_jobs = analyzer.generate_graphs_parallel(
        cast(Any, ["not-an-ast"]),
        tmp_path / "bad_graphs",
    )
    assert len(bad_graph_jobs) == 1
    assert bad_graph_jobs[0].status.value == "failed"
    assert bad_graph_jobs[0].error


def test_parallel_analyzer_context_manager_and_complexity_jobs() -> None:
    with ParallelAnalyzer(max_workers=1) as analyzer:
        ast = _parsed_ast("complex_ok")
        jobs = analyzer.analyze_complexity_parallel([ast])
        assert len(jobs) == 1
        assert jobs[0].status.value == "completed"
        assert jobs[0].result["stats"]["total_rules"] == 1
        assert "metrics" in jobs[0].result
        assert "quality_score" in jobs[0].result

        bad_jobs = analyzer.analyze_complexity_parallel(cast(Any, ["not-an-ast"]))
        assert len(bad_jobs) == 1
        assert bad_jobs[0].status.value == "failed"
        assert bad_jobs[0].error
