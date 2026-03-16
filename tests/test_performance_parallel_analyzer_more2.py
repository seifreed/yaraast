"""Additional real tests for ParallelAnalyzer."""

from __future__ import annotations

from pathlib import Path

from yaraast.parser import Parser
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


def _parsed_ast(name: str = "r"):
    return Parser().parse(_rule_code(name))


def _worker_rule_name(rule, _parameters):
    return rule.name


def _worker_fail_on_b(rule, _parameters):
    if getattr(rule, "name", "") == "b":
        msg = "bad rule"
        raise ValueError(msg)
    return rule.name


def _custom_rule_name(rule):
    return {"rule": rule.name}


def _custom_fail_on_b(rule):
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

    jobs = analyzer.process_batch(small_rules, _worker_rule_name, job_type="names")
    assert [job.result for job in jobs] == ["a", "b"]

    failing_jobs = analyzer.process_batch(small_rules, _worker_fail_on_b, job_type="names")
    assert failing_jobs[0].status.value == "completed"
    assert failing_jobs[1].status.value == "failed"
    assert "bad rule" in failing_jobs[1].error


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

    ast = _parsed_ast("graph_rule")
    graph_jobs = analyzer.generate_graphs_parallel([ast], tmp_path / "graphs", ["full", "rules"])
    assert len(graph_jobs) == 1
    assert graph_jobs[0].status.value == "completed"
    for output in graph_jobs[0].result:
        assert Path(output).exists()


def test_parallel_analyzer_error_paths_without_mocks(tmp_path: Path) -> None:
    analyzer = ParallelAnalyzer(max_workers=1)

    bad_rules = [Parser().parse(_rule_code("ok")).rules[0], "not-a-rule"]
    results = analyzer.analyze_rules(bad_rules, max_workers=1)  # type: ignore[arg-type]
    assert len(results) == 2
    assert any(item.get("analysis") is None for item in results if isinstance(item, dict))
    assert analyzer.get_statistics()["errors"] >= 1

    bad_graph_jobs = analyzer.generate_graphs_parallel(["not-an-ast"], tmp_path / "bad_graphs")  # type: ignore[list-item]
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

        bad_jobs = analyzer.analyze_complexity_parallel(["not-an-ast"])  # type: ignore[list-item]
        assert len(bad_jobs) == 1
        assert bad_jobs[0].status.value == "failed"
        assert bad_jobs[0].error
