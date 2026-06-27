"""Additional tests for performance service helpers."""

from __future__ import annotations

from pathlib import Path
from types import SimpleNamespace
from typing import Any, cast

import pytest

from yaraast.ast.base import YaraFile
from yaraast.cli import performance_services as ps
from yaraast.parser import Parser
from yaraast.performance.batch_processor import BatchOperation
from yaraast.performance.streaming_parser import StreamingParser


def _ast(name: str = "r") -> YaraFile:
    return Parser().parse(f"rule {name} {{ condition: true }}")


def test_get_parse_iterator_collect_paths_and_stream_summary(tmp_path: Path) -> None:
    parser = StreamingParser()
    file_path = tmp_path / "one.yar"
    yara_path = tmp_path / "two.yara"
    yarax_path = tmp_path / "native.yarax"
    file_path.write_text("rule one { condition: true }\n", encoding="utf-8")
    yara_path.write_text("rule two { condition: true }\n", encoding="utf-8")
    yarax_path.write_text("rule native { condition: true }\n", encoding="utf-8")

    split_iter = list(ps.get_parse_iterator(parser, file_path, True, "*.yar", False))
    assert split_iter and split_iter[0].rule_name == "one"

    parse_iter = list(ps.get_parse_iterator(parser, file_path, False, "*.yar", False))
    assert parse_iter and parse_iter[0].rule_name == "one"

    dir_iter = list(ps.get_parse_iterator(parser, tmp_path, False, None, False))
    dir_paths = {Path(result.file_path).name for result in dir_iter}
    assert {"one.yar", "two.yara"}.issubset(dir_paths)
    assert "native.yarax" not in dir_paths

    missing = tmp_path / "missing"
    paths = ps.collect_file_paths((str(file_path), str(tmp_path), str(missing)))
    assert file_path in paths
    assert yara_path in paths
    assert yarax_path not in paths
    assert paths.count(file_path) == 1
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


def test_collect_file_paths_deduplicates_relative_absolute_and_directory_paths(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    file_path = tmp_path / "one.yar"
    file_path.write_text("rule one { condition: true }\n", encoding="utf-8")

    monkeypatch.chdir(tmp_path)
    paths = ps.collect_file_paths(("one.yar", str(file_path), "."))
    resolved_paths = [path.resolve() for path in paths]

    assert resolved_paths.count(file_path.resolve()) == 1


@pytest.mark.parametrize("raw_path", [False, 0, object()])
def test_collect_file_paths_rejects_invalid_path_types(raw_path: Any) -> None:
    with pytest.raises(TypeError, match="input path must be a string or path-like object"):
        ps.collect_file_paths((cast(Any, raw_path),))


@pytest.mark.parametrize("raw_path", ["", "   ", "\t"])
def test_collect_file_paths_rejects_empty_path(raw_path: str) -> None:
    with pytest.raises(ValueError, match="input path must not be empty"):
        ps.collect_file_paths((raw_path,))


def test_collect_file_paths_rejects_null_byte_path() -> None:
    with pytest.raises(ValueError, match="input path must not contain null bytes"):
        ps.collect_file_paths(("\x00broken",))


def test_performance_services_reject_inaccessible_paths(tmp_path: Path) -> None:
    inaccessible = Path("a" * 5000)

    with pytest.raises(ValueError, match="path could not be accessed"):
        ps.collect_file_paths((inaccessible,))

    with pytest.raises(ValueError, match="path could not be accessed"):
        list(ps.get_parse_iterator(StreamingParser(), inaccessible, False, None, False))

    with pytest.raises(ValueError, match="path could not be accessed"):
        ps.run_batch_processing(
            inaccessible,
            tmp_path,
            [BatchOperation.PARSE],
            cast(Any, object()),
            None,
            False,
        )


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


def test_convert_operations_rejects_invalid_operations() -> None:
    assert [op.value for op in ps.convert_operations(["parse", "complexity"])] == [
        "parse",
        "complexity",
    ]

    for invalid_container in [None, 123, "parse", b"parse"]:
        with pytest.raises(TypeError, match="batch operations must be an iterable of strings"):
            ps.convert_operations(cast(Any, invalid_container))

    for invalid_operation in [None, 123]:
        with pytest.raises(TypeError, match="batch operation must be a string"):
            ps.convert_operations(["parse", invalid_operation])

    for unknown_operation in ["", "bad"]:
        with pytest.raises(
            ValueError,
            match=(
                "batch operation must be one of: "
                "complexity, dependency_graph, html_tree, parse, serialize, validate"
            ),
        ):
            ps.convert_operations(["parse", unknown_operation])


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

    plan_small = ps.build_optimization_plan(500, None, None)
    plan_large = ps.build_optimization_plan(5000, 128, 60)
    assert plan_small["strategy"] == [
        "Use batch processing with moderate parallelism",
        "Enable object pooling",
        "Monitor memory usage",
    ]
    assert plan_large["strategy"] == [
        "Use streaming parser with small batches",
        "Enable aggressive memory management",
        "Consider distributed processing",
    ]
    assert plan_small["memory_plan"] is None
    assert plan_small["time_plan"] is None
    assert plan_large["memory_plan"] is not None
    assert plan_large["time_plan"] is not None


def test_build_optimization_plan_rejects_invalid_numeric_inputs() -> None:
    with pytest.raises(TypeError, match="collection_size must be an integer"):
        ps.build_optimization_plan(cast(Any, True), None, None)

    with pytest.raises(TypeError, match="memory_mb must be an integer"):
        ps.build_optimization_plan(1, cast(Any, True), None)

    with pytest.raises(TypeError, match="target_time must be an integer"):
        ps.build_optimization_plan(1, None, cast(Any, True))

    with pytest.raises(ValueError, match="collection_size must be at least 0"):
        ps.build_optimization_plan(-1, None, None)

    with pytest.raises(ValueError, match="memory_mb must be at least 1"):
        ps.build_optimization_plan(1, 0, None)

    with pytest.raises(ValueError, match="target_time must be at least 1"):
        ps.build_optimization_plan(1, None, 0)


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


def test_run_parallel_analysis_rejects_invalid_timeout(tmp_path: Path) -> None:
    with pytest.raises(TypeError, match="timeout must be a number"):
        ps.run_parallel_analysis(
            [],
            max_workers=1,
            chunk_size=1,
            analysis_type="complexity",
            output_dir=tmp_path,
            timeout=cast(Any, True),
        )

    with pytest.raises(TypeError, match="chunk_size must be an integer"):
        ps.run_parallel_analysis(
            [],
            max_workers=1,
            chunk_size=cast(Any, True),
            analysis_type="complexity",
            output_dir=tmp_path,
        )

    with pytest.raises(ValueError, match="timeout must be greater than 0"):
        ps.run_parallel_analysis(
            [],
            max_workers=1,
            chunk_size=1,
            analysis_type="complexity",
            output_dir=tmp_path,
            timeout=0,
        )


def test_run_parallel_analysis_times_out_after_parse(tmp_path: Path) -> None:
    file_path = tmp_path / "one.yar"
    file_path.write_text("rule one { condition: true }\n", encoding="utf-8")

    with pytest.raises(TimeoutError, match="timed out after"):
        ps.run_parallel_analysis(
            [file_path],
            max_workers=1,
            chunk_size=1,
            analysis_type="complexity",
            output_dir=tmp_path / "out",
            timeout=0.000000001,
        )
