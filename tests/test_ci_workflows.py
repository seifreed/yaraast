"""Regression tests for required CI gates."""

from __future__ import annotations

from pathlib import Path


def _workflow(name: str) -> str:
    return (Path(".github/workflows") / name).read_text(encoding="utf-8")


def _assert_required_quality_gates(workflow: str) -> None:
    assert "run: ruff check ." in workflow
    assert "run: black --check ." in workflow
    assert "run: mypy ." in workflow
    assert "run: bandit -r yaraast" in workflow
    assert "--ignore-missing-imports" not in workflow


def test_ci_runs_coverage_and_real_graphviz_without_hidden_test_ignores() -> None:
    workflow = _workflow("ci.yml")

    _assert_required_quality_gates(workflow)
    assert "coverage:" in workflow
    assert "python -m pytest tests/ --tb=short" in workflow
    assert "integration-visualization:" in workflow
    assert "sudo apt-get install --yes graphviz" in workflow
    assert "-m integration" in workflow
    assert "--ignore=" not in workflow
    assert "pip-audit . --progress-spinner off" in workflow
    assert "tests/test_conformance_yarax.py" in workflow
    assert "tests/test_conformance_yaral.py" in workflow


def test_ci_audits_and_packages_the_vscode_extension() -> None:
    workflow = _workflow("ci.yml")

    assert "extension:" in workflow
    assert "npm ci" in workflow
    assert "npm audit --audit-level=low" in workflow
    assert "npx vsce package --out /tmp/yaraast.vsix" in workflow
    assert "python3 scripts/verify_vsix.py /tmp/yaraast.vsix" in workflow


def test_release_runs_the_full_configured_test_gate() -> None:
    workflow = _workflow("release.yml")

    _assert_required_quality_gates(workflow)
    assert "sudo apt-get install --yes graphviz" in workflow
    assert "python -m pytest tests/ --tb=short" in workflow
    assert "--ignore=" not in workflow
    assert "pip-audit . --progress-spinner off" in workflow
    assert "name: extension-vsix" in workflow
    assert "extension/*.vsix" in workflow
