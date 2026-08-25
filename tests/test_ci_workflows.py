"""Regression tests for required CI gates."""

from __future__ import annotations

from pathlib import Path


def _workflow(name: str) -> str:
    return (Path(".github/workflows") / name).read_text(encoding="utf-8")


def _assert_required_quality_gates(workflow: str) -> None:
    assert "run: ruff check ." in workflow
    assert "run: black --check ." in workflow
    assert "run: mypy ." in workflow
    assert (
        "mypy --strict --follow-imports=skip yaraast/limits.py yaraast/shared/path_safety.py"
        in workflow
    )
    assert "run: bandit -r yaraast" in workflow
    assert "--ignore-missing-imports" not in workflow


def test_workflows_use_node24_action_runtimes() -> None:
    workflows = "\n".join(_workflow(name) for name in ("ci.yml", "release.yml", "codeql.yml"))

    for action in (
        "actions/checkout@v6",
        "actions/setup-python@v6",
        "actions/setup-node@v6",
        "actions/cache@v5",
        "actions/upload-artifact@v6",
        "actions/download-artifact@v7",
    ):
        assert action in workflows

    for obsolete_action in (
        "actions/checkout@v4",
        "actions/setup-python@v5",
        "actions/setup-node@v4",
        "actions/cache@v4",
        "actions/upload-artifact@v4",
        "actions/download-artifact@v4",
    ):
        assert obsolete_action not in workflows


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
    assert "tests/test_conformance_invalid.py" in workflow
    assert "performance:" in workflow
    assert (
        "python scripts/benchmark_parser_runtime.py benchmark-results/parser.json --samples 5"
        in workflow
    )
    assert "python scripts/benchmark_lsp_runtime.py benchmark-results/lsp.json" in workflow
    assert "name: benchmark-results" in workflow
    assert "fuzz:" in workflow
    assert 'pip install -e ".[fuzz]"' in workflow
    assert "python -m fuzz.run_parser_fuzz fuzz/corpus/parser" in workflow
    assert "python -m fuzz.run_roundtrip_fuzz fuzz/corpus/roundtrip" in workflow
    assert "-atheris_runs=10000 -max_len=65536 -timeout=5" in workflow
    assert "macos-15-intel" in workflow
    assert "EXPECTED_ARCH: ${{ matrix.arch }}" in workflow
    assert "mutation:" in workflow
    assert 'pip install -e ".[dev,mutation,serialization]"' in workflow
    assert "mutmut run --max-children 4" in workflow
    assert "mutmut export-cicd-stats" in workflow
    assert "--minimum-score 75" in workflow


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
    assert "release-guard:" in workflow
    assert 'git merge-base --is-ancestor "$RELEASE_SHA" origin/main' in workflow
    assert "gpg --batch --import .github/release-signing-key.asc" in workflow
    assert "awk -F: '$1 == \"fpr\" { print $10; exit }'" in workflow
    assert "96F84462629EAEB5C79EE345BD4420606460365C" in workflow
    assert 'git verify-tag "$RELEASE_TAG"' in workflow
    assert "check-runs?per_page=100" in workflow
    assert 'run["conclusion"] == "success"' in workflow
    assert "needs: release-guard" in workflow
    assert "sudo apt-get install --yes graphviz" in workflow
    assert "python -m pytest tests/ --tb=short" in workflow
    assert "--ignore=" not in workflow
    assert "pip-audit . --progress-spinner off" in workflow
    assert "name: extension-vsix" in workflow
    assert "extension/*.vsix" in workflow
    assert "permissions:\n  contents: read" in workflow
    assert (
        'pip install -e ".[dev,conformance,lsp,visualization,serialization,performance]"'
        in workflow
    )
    assert "python -m twine check dist/*" in workflow
    assert ".sdist-venv/bin/pip check" in workflow
    assert '"yaraast/types/modules/vt.json"' in workflow
    assert '"yaraast/serialization/yara_ast.proto"' in workflow
    assert '"yaraast/serialization/yara_ast_pb2.pyi"' in workflow
    assert "import tarfile" in workflow
    assert "from importlib.resources import files" in workflow
    assert 'ModuleLoader().get_module("vt")' in workflow
    assert '"$GITHUB_WORKSPACE/.release-venv/bin/python" - <<' in workflow
    assert "draft: true" in workflow
    assert "needs: github-release" in workflow
    assert "finalize-release:" in workflow
