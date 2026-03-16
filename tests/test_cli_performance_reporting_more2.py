"""More tests for performance reporting helpers (no mocks)."""

from __future__ import annotations

from pathlib import Path
from types import SimpleNamespace

from yaraast.cli import performance_reporting as pr


def test_performance_reporting_operation_and_stream(capsys) -> None:
    result = SimpleNamespace(
        input_count=10,
        successful_count=8,
        failed_count=2,
        success_rate=80.0,
        total_time=1.23,
        output_files=["a", "b", "c", "d", "e", "f"],
        errors=["err1", "err2", "err3", "err4"],
    )
    operation = SimpleNamespace(value="parse")
    pr.display_operation_result(operation, result)
    out = capsys.readouterr().out
    assert "PARSE" in out
    assert "Output files: 6" in out
    assert "Errors: 4" in out

    rows = [
        SimpleNamespace(
            status=SimpleNamespace(value="success"),
            rule_count=2,
            import_count=1,
            parse_time=0.01,
            file_path="/tmp/a.yar",
            error=None,
        ),
        SimpleNamespace(
            status=SimpleNamespace(value="error"),
            rule_count=1,
            import_count=0,
            parse_time=0.02,
            file_path="/tmp/b.yar",
            error="bad",
        ),
    ]
    successful, failed = pr.display_stream_summary(rows, total_time=0.4)
    out2 = capsys.readouterr().out
    assert "Streaming Parse Results" in out2
    assert len(successful) == 1 and len(failed) == 1

    pr.display_stream_details(successful, failed, {"peak_memory_mb": 42.0})
    out3 = capsys.readouterr().out
    assert "Peak memory usage" in out3
    assert "Failed files" in out3

    many_failed = [SimpleNamespace(file_path=f"/tmp/f{i}.yar", error="x") for i in range(7)]
    pr.display_stream_details([], many_failed, {"peak_memory_mb": 0})
    out4 = capsys.readouterr().out
    assert "and 2 more" in out4


def test_performance_reporting_parallel_complexity_and_optimize(tmp_path: Path, capsys) -> None:
    pr.display_parallel_summary(
        {
            "files_processed": 5,
            "successful": 4,
            "jobs_submitted": 5,
            "jobs_completed": 5,
            "jobs_failed": 1,
            "avg_job_time": 0.01,
            "workers_used": 2,
            "speedup": 1.5,
        },
        total_time=0.9,
    )
    assert "Parallel Processing Summary" in capsys.readouterr().out

    pr.report_complexity_analysis([], tmp_path)
    assert not (tmp_path / "complexity_analysis.json").exists()

    pr.report_complexity_analysis(
        [{"quality_score": 60}, {"quality_score": 90}],
        tmp_path,
    )
    out = capsys.readouterr().out
    assert "Complexity analysis saved" in out
    assert "Average quality score" in out
    assert (tmp_path / "complexity_analysis.json").exists()

    plan_ok = {
        "recommendations": {
            "batch_size": 100,
            "gc_threshold": 700,
            "memory_limit_mb": 1024,
            "enable_pooling": True,
            "use_streaming": False,
        },
        "collection_size": 1000,
        "strategy": ["s1", "s2"],
        "memory_plan": {
            "available_mb": 2048,
            "sufficient": True,
            "estimated_mb": 100,
            "suggested_batch_size": 10,
        },
        "time_plan": {
            "target_time": 60,
            "estimated_time_parallel": 20,
            "needed_workers": 4,
            "max_workers": 4,
        },
        "examples": {
            "batch": {"batch_size": 100, "memory_limit_mb": 1024, "max_workers": 4},
            "stream": {"memory_limit_mb": 512},
        },
    }
    pr.display_optimize_report(plan_ok)
    out2 = capsys.readouterr().out
    assert "Optimization Recommendations" in out2
    assert "Memory sufficient" in out2
    assert "Target time achievable" in out2

    plan_warn = {
        "recommendations": {
            "batch_size": 10,
            "memory_limit_mb": 256,
            "enable_pooling": False,
            "use_streaming": True,
        },
        "collection_size": 10,
        "strategy": ["s"],
        "memory_plan": {
            "available_mb": 128,
            "sufficient": False,
            "estimated_mb": 300,
            "suggested_batch_size": 2,
        },
        "time_plan": {
            "target_time": 1,
            "estimated_time_parallel": 5,
            "needed_workers": 40,
            "max_workers": 2,
        },
        "examples": {
            "batch": {"batch_size": 10, "memory_limit_mb": 256, "max_workers": 2},
            "stream": {"memory_limit_mb": 128},
        },
    }
    pr.display_optimize_report(plan_warn)
    out3 = capsys.readouterr().out
    assert "Estimated memory need" in out3
    assert "Consider 32 workers" in out3
