"""Additional branch coverage for benchmark reporting helpers (no mocks)."""

from __future__ import annotations

import json
from pathlib import Path
from types import SimpleNamespace

from yaraast.cli import bench_reporting as br


def test_display_operation_result_and_none_case(capsys) -> None:
    ok = SimpleNamespace(success=True, execution_time=0.01, rules_count=3, ast_nodes=10)
    br.display_operation_result("parse", ok)
    out = capsys.readouterr().out
    assert "OK" in out
    assert "parse" in out

    fail = SimpleNamespace(success=False, error="boom")
    br.display_operation_result("parse", fail)
    out2 = capsys.readouterr().out
    assert "FAIL" in out2
    assert "boom" in out2

    # None should not crash or print operation lines.
    br.display_operation_result("parse", None)
    out3 = capsys.readouterr().out
    assert out3 == ""


def test_display_performance_comparison_paths(capsys) -> None:
    br.display_performance_comparison([{"file_name": "a", "results": {"codegen": object()}}])
    out = capsys.readouterr().out
    assert "Performance Comparison" in out
    assert "Parsing Performance" not in out

    slow = SimpleNamespace(execution_time=0.2, rules_count=2)
    fast = SimpleNamespace(execution_time=0.05, rules_count=5)
    br.display_performance_comparison(
        [
            {"file_name": "none.yar", "results": {"parse": None}},
            {"file_name": "slow.yar", "results": {"parse": slow}},
            {"file_name": "fast.yar", "results": {"parse": fast}},
        ],
    )
    out2 = capsys.readouterr().out
    assert "Parsing Performance" in out2
    assert "fast.yar" in out2
    assert "slow.yar" in out2


def test_save_benchmark_results_writes_json(tmp_path: Path, capsys) -> None:
    out_file = tmp_path / "bench.json"
    br.save_benchmark_results(
        output=str(out_file),
        iterations=3,
        operations="parse,codegen",
        all_results=[{"file_name": "a.yar", "results": {"parse": {"ok": True}}}],
        summary={"parse": {"avg_time": 0.1}},
    )
    text = out_file.read_text(encoding="utf-8")
    data = json.loads(text)
    assert data["iterations"] == 3
    assert data["operations"] == "parse,codegen"
    assert "timestamp" in data
    assert data["files"][0]["file_name"] == "a.yar"
    assert "saved to" in capsys.readouterr().out
