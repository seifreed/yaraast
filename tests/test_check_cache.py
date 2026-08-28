"""Regression tests for check caching and incremental file selection."""

from __future__ import annotations

from pathlib import Path

from yaraast.check import affected_files, check_path
from yaraast.check_cache import CheckCache
from yaraast.diagnostics import Diagnostic, DiagnosticResult, Severity
from yaraast.project_config import ProjectConfig


def test_check_cache_round_trips_diagnostics(tmp_path: Path) -> None:
    cache = CheckCache(tmp_path)
    diagnostic = Diagnostic("YARA103", Severity.WARNING, "policy", "unused", "a.yar", 1, 1, 1, 1)
    result = DiagnosticResult((diagnostic,))
    cache.put("a.yar", "key", result)
    cache.save()

    assert CheckCache(tmp_path).get("a.yar", "key") == result


def test_check_path_uses_ignored_cache_directory(tmp_path: Path) -> None:
    (tmp_path / "sample.yar").write_text("rule sample { condition: true }\n", encoding="utf-8")

    check_path(tmp_path, ProjectConfig(tmp_path))

    assert (tmp_path / ".yaraast" / "check-cache.json").is_file()


def test_affected_files_includes_transitive_dependents(tmp_path: Path) -> None:
    leaf = tmp_path / "leaf.yar"
    middle = tmp_path / "middle.yar"
    top = tmp_path / "top.yar"
    leaf.write_text("rule leaf { condition: true }\n", encoding="utf-8")
    middle.write_text('include "leaf.yar"\nrule middle { condition: true }\n', encoding="utf-8")
    top.write_text('include "middle.yar"\nrule top { condition: true }\n', encoding="utf-8")

    selected = affected_files((leaf, middle, top), {"leaf.yar"})

    assert selected == (leaf, middle, top)
