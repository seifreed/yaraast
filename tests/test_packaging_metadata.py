"""Packaging metadata regression tests."""

from __future__ import annotations

from pathlib import Path
import tomllib


def test_project_license_uses_spdx_string_metadata() -> None:
    pyproject = tomllib.loads(Path("pyproject.toml").read_text(encoding="utf-8"))
    project = pyproject["project"]

    assert project["license"] == "MIT"
    assert "License :: OSI Approved :: MIT License" not in project["classifiers"]
