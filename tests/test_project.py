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


def test_project_edit_previews_and_applies_lossless_changes(tmp_path: Path) -> None:
    rules = tmp_path / "rules"
    rules.mkdir()
    path = rules / "sample.yar"
    path.write_text("// keep\nrule old_name { condition: true }\n", encoding="utf-8")

    session = Project.load(tmp_path).edit().rename_rule("old_name", "new_name")

    preview = session.preview()
    assert preview[0][0] == path
    assert "// keep" in preview[0][1].updated
    session.apply()
    assert "rule new_name" in path.read_text(encoding="utf-8")
