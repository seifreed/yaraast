"""Repository portability regression tests."""

from __future__ import annotations

from pathlib import Path


def test_documentation_does_not_publish_developer_home_paths() -> None:
    paths = [Path("README.md"), *Path("docs").rglob("*.md"), *Path("docs").rglob("*.json")]

    for path in paths:
        text = path.read_text(encoding="utf-8")
        assert "/Users/" not in text, f"developer path leaked in {path}"


def test_runtime_cache_directories_are_ignored() -> None:
    patterns = Path(".gitignore").read_text(encoding="utf-8").splitlines()

    assert ".yaraast/" in patterns
