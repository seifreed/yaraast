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


def test_mypy_has_protobuf_stubs_for_generated_messages() -> None:
    pyproject = tomllib.loads(Path("pyproject.toml").read_text(encoding="utf-8"))

    assert "types-protobuf>=7.34.1" in pyproject["project"]["optional-dependencies"]["dev"]


def test_release_version_has_a_dated_changelog_entry() -> None:
    pyproject = tomllib.loads(Path("pyproject.toml").read_text(encoding="utf-8"))
    project_version = pyproject["project"]["version"]
    changelog = Path("CHANGELOG.md").read_text(encoding="utf-8")

    assert project_version == "2.0.1"
    assert f"## {project_version} - 2026-08-23" in changelog
