"""Regression tests for required CI gates."""

from __future__ import annotations

from pathlib import Path


def _workflow(name: str) -> str:
    return (Path(".github/workflows") / name).read_text(encoding="utf-8")


def test_ci_runs_coverage_and_real_graphviz_without_hidden_test_ignores() -> None:
    workflow = _workflow("ci.yml")

    assert "coverage:" in workflow
    assert "python -m pytest tests/ --tb=short" in workflow
    assert "integration-visualization:" in workflow
    assert "sudo apt-get install --yes graphviz" in workflow
    assert "-m integration" in workflow
    assert "--ignore=" not in workflow


def test_release_runs_the_full_configured_test_gate() -> None:
    workflow = _workflow("release.yml")

    assert "sudo apt-get install --yes graphviz" in workflow
    assert "python -m pytest tests/ --tb=short" in workflow
    assert "--ignore=" not in workflow
