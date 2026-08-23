"""Repository portability regression tests."""

from __future__ import annotations

from pathlib import Path

import pytest


@pytest.mark.parametrize(
    "path",
    [
        "CHANGELOG.md",
        "CODE_OF_CONDUCT.md",
        "CONTRIBUTING.md",
        "MIGRATING.md",
        "SECURITY.md",
        ".github/ISSUE_TEMPLATE/bug.yml",
        ".github/ISSUE_TEMPLATE/feature.yml",
    ],
)
def test_public_governance_file_exists(path: str) -> None:
    assert Path(path).is_file()


def test_documentation_does_not_publish_developer_home_paths() -> None:
    paths = [Path("README.md"), *Path("docs").rglob("*.md"), *Path("docs").rglob("*.json")]

    for path in paths:
        text = path.read_text(encoding="utf-8")
        assert "/Users/" not in text, f"developer path leaked in {path}"


def test_runtime_cache_directories_are_ignored() -> None:
    patterns = Path(".gitignore").read_text(encoding="utf-8").splitlines()

    assert ".yaraast/" in patterns
