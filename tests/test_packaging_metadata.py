"""Packaging metadata regression tests."""

from __future__ import annotations

from pathlib import Path
import tomllib


def test_project_license_uses_spdx_string_metadata() -> None:
    pyproject = tomllib.loads(Path("pyproject.toml").read_text(encoding="utf-8"))
    project = pyproject["project"]

    assert project["license"] == "MIT"
    assert "License :: OSI Approved :: MIT License" not in project["classifiers"]


def test_runtime_dependencies_are_direct_project_requirements() -> None:
    pyproject = tomllib.loads(Path("pyproject.toml").read_text(encoding="utf-8"))

    assert pyproject["project"]["dependencies"] == [
        "click>=8.4.2",
        "rich>=13.0.0",
        "attrs>=23.0.0",
        "PyYAML>=6.0.0",
    ]


def test_conformance_engines_are_reproducibly_pinned() -> None:
    pyproject = tomllib.loads(Path("pyproject.toml").read_text(encoding="utf-8"))
    optional_dependencies = pyproject["project"]["optional-dependencies"]

    assert optional_dependencies["libyara"] == ["yara-python==4.5.4"]
    assert optional_dependencies["conformance"] == [
        "yara-python==4.5.4",
        "yara-x==1.19.0",
    ]
