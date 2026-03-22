"""Additional tests for performance service helpers."""

from __future__ import annotations

from pathlib import Path
from types import SimpleNamespace

from yaraast.cli import performance_services as ps
from yaraast.parser import Parser
from yaraast.performance.streaming_parser import StreamingParser


def _ast(name: str = "r"):
    return Parser().parse(f"rule {name} {{ condition: true }}")


def test_get_parse_iterator_collect_paths_and_stream_summary(tmp_path: Path) -> None:
    parser = StreamingParser()
    file_path = tmp_path / "one.yar"
    file_path.write_text("rule one { condition: true }\n", encoding="utf-8")

    split_iter = list(ps.get_parse_iterator(parser, file_path, True, "*.yar", False))
    assert split_iter and split_iter[0].rule_name == "one"

    parse_iter = list(ps.get_parse_iterator(parser, file_path, False, "*.yar", False))
    assert parse_iter and parse_iter[0].rule_name == "one"

    dir_iter = list(ps.get_parse_iterator(parser, tmp_path, False, "*.yar", False))
    assert dir_iter and dir_iter[0].rule_name == "one"

    missing = tmp_path / "missing"
    paths = ps.collect_file_paths((str(file_path), str(tmp_path), str(missing)))
    assert file_path in paths
    assert all(path.exists() for path in paths)

    summary = ps.summarize_stream_results(
        [
            SimpleNamespace(status=SimpleNamespace(value="success")),
            SimpleNamespace(status=SimpleNamespace(value="error")),
            SimpleNamespace(status=SimpleNamespace(value="other")),
        ]
    )
    assert len(summary["successful"]) == 1
    assert len(summary["failed"]) == 1


def test_extract_successful_asts_and_file_name_mapping_paths(tmp_path: Path) -> None:
    file_paths = [tmp_path / "a.yar"]
    ok_ast = _ast("ok")
    bad_ast = SimpleNamespace(_parse_error=True)
    job = SimpleNamespace(
        status=SimpleNamespace(value="completed"), result=[ok_ast, bad_ast, ok_ast]
    )
    skipped_job = SimpleNamespace(status=SimpleNamespace(value="failed"), result=[ok_ast])

    asts, names = ps.extract_successful_asts([job, skipped_job], file_paths, chunk_size=2)
    assert asts == [ok_ast, ok_ast]
    assert names == [str(file_paths[0])]

    assert ps._get_corresponding_file_name(1, 0, file_paths, 2) is None


def test_build_parallel_summary_and_plans_cover_remaining_branches() -> None:
    summary = ps.build_parallel_summary(
        [Path("a.yar")],
        [_ast("a")],
        {"avg_time_per_rule": 0.5, "jobs_completed": 1, "max_workers": 4},
        total_time=0,
    )
    assert summary["avg_job_time"] == 0.5
    assert summary["speedup"] == 1
    assert summary["workers_used"] == 4

    summary2 = ps.build_parallel_summary(
        [Path("a.yar")] * 6,
        [_ast("a")] * 6,
        {
            "avg_time_per_rule": 1.5,
            "jobs_completed": 6,
            "total_processing_time": 9.0,
            "max_workers": 4,
        },
        total_time=3.0,
    )
    assert summary2["speedup"] == 3.0  # 6 jobs * 1.5s avg = 9s sequential / 3s parallel

    summary3 = ps.build_parallel_summary(
        [Path("a.yar")],
        [],
        {"avg_time_per_rule": 0.0, "jobs_completed": 0, "max_workers": 2},
        total_time=5.0,
    )
    assert summary3["speedup"] == 1.0

    assert ps._build_strategy_messages(500) == [
        "Use batch processing with moderate parallelism",
        "Enable object pooling",
        "Monitor memory usage",
    ]
    assert ps._build_strategy_messages(5000) == [
        "Use streaming parser with small batches",
        "Enable aggressive memory management",
        "Consider distributed processing",
    ]
    assert ps._build_memory_plan(10, None, {"memory_limit_mb": 64}) is None
    assert ps._build_time_plan(10, None) is None


def test_run_parallel_analysis_and_build_output_data_more_paths(tmp_path: Path) -> None:
    file_path = tmp_path / "one.yar"
    file_path.write_text("rule one { condition: true }\n", encoding="utf-8")
    output_dir = tmp_path / "out"

    run_results, total_time = ps.run_parallel_analysis(
        [file_path],
        max_workers=1,
        chunk_size=1,
        analysis_type="all",
        output_dir=output_dir,
    )
    assert total_time >= 0
    assert len(run_results["successful_asts"]) == 1
    assert run_results["complexity_results"]
    assert run_results["dependency_graphs"]

    result_obj = SimpleNamespace(
        file_path=str(file_path),
        rule_name="one",
        status=SimpleNamespace(value="success"),
        error=None,
        parse_time=0.1,
        rule_count=1,
        import_count=0,
    )
    out = ps.build_stream_output_data([result_obj], [result_obj], [], 0.5, {"peak_memory_mb": 1})
    assert out["summary"]["success_rate"] == 100.0
    assert out["results"][0]["status"] == "success"
