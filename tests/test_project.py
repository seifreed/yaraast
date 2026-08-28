"""Regression tests for the high-level Project API."""

from __future__ import annotations

from pathlib import Path

from yaraast.project import Project


def test_project_load_check_and_test_use_local_repository(tmp_path: Path) -> None:
    (tmp_path / "rules").mkdir()
    (tmp_path / "rules/sample.yar").write_text(
        'rule sample { strings: $a = "hello" condition: $a }\n', encoding="utf-8"
    )
    (tmp_path / "tests/sample").mkdir(parents=True)
    (tmp_path / "tests/sample/positives").mkdir()
    (tmp_path / "tests/sample/positives/a.bin").write_bytes(b"hello")
    (tmp_path / "tests/sample/test.yml").write_text(
        """
schema: yaraast-test/v1
rule_id: sample
engines: [missing]
positive:
  - path: positives/a.bin
    expected: [sample]
""",
        encoding="utf-8",
    )

    project = Project.load(tmp_path)

    assert project.check(compile_targets=False).diagnostics == ()
    assert project.test(engines=("missing",)).coverage() == {
        "rules": 1,
        "positive": 1,
        "negative": 0,
    }
