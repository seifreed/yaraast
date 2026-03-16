from __future__ import annotations

import importlib.util
import subprocess
import sys
from pathlib import Path

SCRIPT_PATH = Path(__file__).resolve().parents[1] / "scripts" / "benchmark_lsp_runtime.py"
SPEC = importlib.util.spec_from_file_location("benchmark_lsp_runtime", SCRIPT_PATH)
if SPEC is None or SPEC.loader is None:
    raise RuntimeError(f"Cannot load benchmark script at {SCRIPT_PATH}")
MODULE = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(MODULE)
run_benchmark = MODULE.run_benchmark
run_single_document_benchmark = MODULE.run_single_document_benchmark
run_regression_suite = MODULE.run_regression_suite


def test_lsp_runtime_benchmark_report_has_thresholds() -> None:
    report = run_benchmark(file_count=5, max_avg_ms=500.0)
    assert report["ok"] is True
    status = report["status"]
    assert "latency" in status
    assert "cache_stats" in status


def test_lsp_runtime_single_document_benchmark_report_has_thresholds() -> None:
    report = run_single_document_benchmark(rule_count=25, max_avg_ms=500.0)
    assert report["ok"] is True
    status = report["status"]
    assert "latency" in status
    assert "cache_stats" in status


def test_lsp_runtime_regression_suite_reports_named_scenarios() -> None:
    report = run_regression_suite()
    assert report["ok"] is True
    assert "single_document" in report
    assert "medium" in report
    assert "large" in report


def test_lsp_runtime_benchmark_script_can_write_results(tmp_path: Path) -> None:
    output = tmp_path / "runtime-benchmark.json"
    proc = subprocess.run(
        [sys.executable, str(SCRIPT_PATH), str(output)],
        cwd=Path(__file__).resolve().parents[1],
        capture_output=True,
        text=True,
        check=False,
    )
    assert proc.returncode == 0
    assert output.exists()
    text = output.read_text(encoding="utf-8")
    assert '"single_document"' in text
    assert '"medium"' in text
    assert '"large"' in text
    assert output.with_suffix(".md").exists()


def test_lsp_runtime_benchmark_script_can_write_history(tmp_path: Path) -> None:
    output = tmp_path / "runtime-benchmark.json"
    history_dir = tmp_path / "history"
    proc = subprocess.run(
        [sys.executable, str(SCRIPT_PATH), str(output), str(history_dir)],
        cwd=Path(__file__).resolve().parents[1],
        capture_output=True,
        text=True,
        check=False,
    )
    assert proc.returncode == 0
    history_files = list(history_dir.glob("lsp-runtime-*.json"))
    assert len(history_files) == 1
    summary_files = list(history_dir.glob("lsp-runtime-*.md"))
    assert len(summary_files) == 1
    index_path = history_dir / "README.md"
    assert index_path.exists()
    assert "| scenario | ok | threshold | failures |" in index_path.read_text(encoding="utf-8")
