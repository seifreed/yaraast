from __future__ import annotations

from pathlib import Path
import re
import tomllib


def test_supported_python_versions_are_declared_and_tested() -> None:
    project = tomllib.loads(Path("pyproject.toml").read_text(encoding="utf-8"))["project"]
    assert project["requires-python"] == ">=3.11"
    classifiers = set(project["classifiers"])
    workflow = Path(".github/workflows/ci.yml").read_text(encoding="utf-8")
    tested_versions = set(re.findall(r'python-version: "(3\.\d+)"', workflow))

    for version in ("3.11", "3.12", "3.13", "3.14"):
        assert f"Programming Language :: Python :: {version}" in classifiers
        assert version in tested_versions


def test_pep561_marker_is_at_package_root() -> None:
    assert Path("yaraast/py.typed").is_file()
    assert not Path("yaraast/parser/py.typed").exists()
