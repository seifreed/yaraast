"""Regression tests for lossless refactoring."""

from __future__ import annotations

from pathlib import Path

from yaraast.refactor import (
    migrate_source,
    normalize_metadata,
    remove_unused_strings,
    rename_rule,
    rename_string,
    sort_imports,
    write_refactor,
)


def test_rename_rule_preserves_comments_and_string_literals() -> None:
    source = (
        "// old_rule\nrule old_rule { condition: true }\n"
        "rule consumer { condition: old_rule }\n"
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


def test_remove_unused_strings_preserves_other_source() -> None:
    source = (
        'rule sample {\n strings:\n  $used = "used"\n  $unused = "unused"\n'
        " condition: $used\n}\n"
    )

    result = remove_unused_strings(source)

    assert "$unused" not in result.updated
    assert "$used" in result.updated


def test_sort_imports_and_normalize_metadata() -> None:
    source = (
        'import "pe"\nimport "hash"\nrule sample {\n meta:\n  z = "last"\n'
        '  a = "first"\n condition: true\n}\n'
    )

    imports = sort_imports(source)
    metadata = normalize_metadata(imports.updated)

    assert metadata.updated.index('import "hash"') < metadata.updated.index('import "pe"')
    assert metadata.updated.index('  a = "first"') < metadata.updated.index('  z = "last"')


def test_migrate_source_reparses_target_dialect() -> None:
    result = migrate_source("rule sample { condition: true }\n", "yara", "yara-x")

    assert result.changed
    assert "rule sample" in result.updated
