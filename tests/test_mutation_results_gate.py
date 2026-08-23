"""Regression tests for the mutation score gate."""

from __future__ import annotations

import importlib.util
from pathlib import Path

SCRIPT_PATH = Path(__file__).resolve().parents[1] / "scripts" / "check_mutation_results.py"
SPEC = importlib.util.spec_from_file_location("check_mutation_results", SCRIPT_PATH)
if SPEC is None or SPEC.loader is None:
    raise RuntimeError(f"Cannot load mutation gate at {SCRIPT_PATH}")
MODULE = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(MODULE)


def test_mutation_gate_enforces_score_and_complete_results() -> None:
    passed, score = MODULE.check_results({"total": 100, "killed": 80}, 75.0)
    below_score, _ = MODULE.check_results({"total": 100, "killed": 74}, 75.0)
    incomplete, _ = MODULE.check_results({"total": 100, "killed": 100, "timeout": 1}, 75.0)
    empty, _ = MODULE.check_results({}, 75.0)

    assert passed is True
    assert score == 80.0
    assert below_score is False
    assert incomplete is False
    assert empty is False
