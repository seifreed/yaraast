"""Regression tests for the parser runtime gate."""

from __future__ import annotations

import importlib.util
from pathlib import Path

SCRIPT_PATH = Path(__file__).resolve().parents[1] / "scripts" / "benchmark_parser_runtime.py"
SPEC = importlib.util.spec_from_file_location("benchmark_parser_runtime", SCRIPT_PATH)
if SPEC is None or SPEC.loader is None:
    raise RuntimeError(f"Cannot load benchmark script at {SCRIPT_PATH}")
MODULE = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(MODULE)


def test_parser_runtime_gate_reports_all_operations_and_thresholds() -> None:
    report = MODULE.run_regression_suite(rule_count=10, iterations=1)

    assert report["ok"] is True
    assert report["input"]["rules"] == 10
    assert set(report["operations"]) == {"parsing", "codegen", "roundtrip"}
    for operation in report["operations"].values():
        assert operation["ok"] is True
        assert operation["max_seconds"] > 0
        assert operation["rules_per_second"] > 0


def test_parser_runtime_gate_fails_when_an_operation_exceeds_its_limit() -> None:
    report = MODULE.run_regression_suite(
        rule_count=10,
        iterations=1,
        parsing_max_seconds=0.0,
    )

    assert report["ok"] is False
    assert report["operations"]["parsing"]["ok"] is False
