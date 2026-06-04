"""Regression coverage for runnable examples."""

from __future__ import annotations

from pathlib import Path
import subprocess
import sys


def test_custom_visitor_example_runs() -> None:
    repo_root = Path(__file__).resolve().parents[1]

    result = subprocess.run(
        [sys.executable, "examples/custom_visitor.py"],
        cwd=repo_root,
        check=True,
        capture_output=True,
        text=True,
    )

    assert "total_rules: 2" in result.stdout
    assert "private_rules: 1" in result.stdout
    assert "global_rules: 1" in result.stdout
    assert "meta_keys: author, severity, version" in result.stdout
    assert '$a = "test"' in result.stdout


def test_core_examples_run() -> None:
    repo_root = Path(__file__).resolve().parents[1]

    for example in (
        "builder_demo.py",
        "complete_features.py",
        "parse_file.py",
        "transform_ast.py",
    ):
        result = subprocess.run(
            [sys.executable, f"examples/{example}"],
            cwd=repo_root,
            check=True,
            capture_output=True,
            text=True,
        )

        assert result.stdout
