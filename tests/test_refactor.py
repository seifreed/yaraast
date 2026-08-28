"""Regression tests for lossless refactoring."""

from __future__ import annotations

from pathlib import Path

from yaraast.refactor import rename_rule, rename_string, write_refactor


def test_rename_rule_preserves_comments_and_string_literals() -> None:
    source = (
        '// old_rule\nrule old_rule { condition: true }\n'
        'rule consumer { condition: old_rule }\n'
        'rule literal { strings: $a = "old_rule" condition: $a }\n'
    )

    result = rename_rule(source, "old_rule", "new_rule")

    assert result.updated.count("new_rule") == 2
    assert '"old_rule"' in result.updated
    assert "// old_rule" in result.updated


def test_rename_string_reparses_and_writes_atomically(tmp_path: Path) -> None:
    path = tmp_path / "rule.yar"
    source = 'rule sample { strings: $a = "hello" condition: $a }\n'
    path.write_text(source, encoding="utf-8")

    result = rename_string(source, "$a", "$payload")
    write_refactor(path, result)

    assert "$payload" in path.read_text(encoding="utf-8")
    assert "$a" not in path.read_text(encoding="utf-8")
