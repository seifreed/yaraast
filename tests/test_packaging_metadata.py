"""Packaging metadata regression tests."""

from __future__ import annotations

from pathlib import Path
import tomllib


def _dependency_by_name(dependencies: list[str], package_name: str) -> str:
    prefix = f"{package_name.lower()}>="
    for dependency in dependencies:
        if dependency.lower().startswith(prefix):
            return dependency
    raise AssertionError(f"{package_name} dependency floor is missing")


def test_project_license_uses_spdx_string_metadata() -> None:
    pyproject = tomllib.loads(Path("pyproject.toml").read_text(encoding="utf-8"))
    project = pyproject["project"]

    assert project["license"] == "MIT"
    assert "License :: OSI Approved :: MIT License" not in project["classifiers"]


def test_security_dependency_floors_cover_known_vulnerable_versions() -> None:
    pyproject = tomllib.loads(Path("pyproject.toml").read_text(encoding="utf-8"))
    project = pyproject["project"]
    dependencies = project["dependencies"]
    dev_dependencies = project["optional-dependencies"]["dev"]

    assert _dependency_by_name(dependencies, "cryptography") == "cryptography>=48.0.0"
    assert _dependency_by_name(dependencies, "idna") == "idna>=3.18"
    assert _dependency_by_name(dependencies, "Pygments") == "Pygments>=2.20.0"
    assert _dependency_by_name(dependencies, "urllib3") == "urllib3>=2.7.0"
    assert _dependency_by_name(dev_dependencies, "pytest") == "pytest>=9.0.3"
