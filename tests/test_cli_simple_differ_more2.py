"""Additional tests for simple differ utilities (no mocks)."""

from __future__ import annotations

from pathlib import Path

from yaraast.ast.base import YaraFile
from yaraast.cli.simple_differ import (
    SimpleASTDiffer,
    SimpleDiffer,
    diff_ast,
    diff_lines,
)
from yaraast.parser import Parser
from yaraast.yarax.parser import YaraXParser


class _QueuedParser(Parser):
    def __init__(self, asts: list[YaraFile]) -> None:
        super().__init__()
        self.asts = asts

    def parse(self, text: str | None = None) -> YaraFile:
        return self.asts.pop(0)


def _duplicate_named_ast(source: str, duplicate_name: str) -> YaraFile:
    ast = Parser().parse(source)
    for rule in ast.rules:
        rule.name = duplicate_name
    return ast


def test_simple_differ_line_changes() -> None:
    differ = SimpleDiffer()
    result = differ.diff("rule a { condition: true }", "rule a { condition: false }")

    assert result.has_changes is True
    summary = result.summary
    assert summary["modified"] >= 1
    assert summary["total_changes"] == summary["added"] + summary["removed"] + summary["modified"]


def test_simple_ast_differ_files(tmp_path: Path) -> None:
    file1 = tmp_path / "a.yar"
    file2 = tmp_path / "b.yar"

    file1.write_text("rule r1 { condition: true }", encoding="utf-8")
    file2.write_text("rule r2 { condition: true }", encoding="utf-8")

    differ = SimpleASTDiffer()
    result = differ.diff_files(file1, file2)

    assert result.has_changes is True
    assert result.added_rules == ["r2"]
    assert result.removed_rules == ["r1"]


def test_simple_ast_differ_modified_rule(tmp_path: Path) -> None:
    file1 = tmp_path / "a.yar"
    file2 = tmp_path / "b.yar"

    file1.write_text("rule r1 { condition: true }", encoding="utf-8")
    file2.write_text("rule r1 { condition: false }", encoding="utf-8")

    differ = SimpleASTDiffer()
    result = differ.diff_files(file1, file2)

    assert result.modified_rules == ["r1"]


def test_simple_ast_differ_diff_files_detects_changed_duplicate_rule_occurrence(
    tmp_path: Path,
) -> None:
    file1 = tmp_path / "old.yar"
    file2 = tmp_path / "new.yar"

    file1.write_text("old", encoding="utf-8")
    file2.write_text("new", encoding="utf-8")
    old_ast = _duplicate_named_ast(
        "rule dup_first { condition: true }\nrule dup_second { condition: 1 }\n",
        "dup",
    )
    new_ast = _duplicate_named_ast(
        "rule dup_first { condition: false }\nrule dup_second { condition: 1 }\n",
        "dup",
    )

    result = SimpleASTDiffer(parser=_QueuedParser([old_ast, new_ast])).diff_files(file1, file2)

    assert result.has_changes is True
    assert result.modified_rules == ["dup#1"]
    assert result.logical_changes == ["Rule modified: dup#1"]
    assert result.change_summary["modified_rules"] == 1


def test_simple_ast_differ_diff_files_preserves_duplicate_rule_adds_and_removals(
    tmp_path: Path,
) -> None:
    file1 = tmp_path / "old.yar"
    file2 = tmp_path / "new.yar"

    file1.write_text("old", encoding="utf-8")
    file2.write_text("new", encoding="utf-8")
    old_ast = Parser().parse(
        "\n".join(
            [
                "rule adddup { condition: true }",
                "rule remdup_first { condition: true }",
                "rule remdup_second { condition: false }",
            ]
        )
    )
    old_ast.rules[1].name = "remdup"
    old_ast.rules[2].name = "remdup"
    new_ast = Parser().parse(
        "\n".join(
            [
                "rule adddup_first { condition: true }",
                "rule adddup_second { condition: false }",
                "rule remdup { condition: true }",
            ]
        )
    )
    new_ast.rules[0].name = "adddup"
    new_ast.rules[1].name = "adddup"

    result = SimpleASTDiffer(parser=_QueuedParser([old_ast, new_ast])).diff_files(file1, file2)

    assert result.added_rules == ["adddup#2"]
    assert result.removed_rules == ["remdup#2"]
    assert result.modified_rules == []
    assert result.logical_changes == ["Rule added: adddup#2", "Rule removed: remdup#2"]


def test_simple_ast_differ_diff_files_ignores_rule_location_changes(
    tmp_path: Path,
) -> None:
    file1 = tmp_path / "old.yar"
    file2 = tmp_path / "new.yar"

    file1.write_text(
        "\n".join(
            [
                "rule shifted { condition: true }",
                "rule stable { condition: false }",
            ]
        ),
        encoding="utf-8",
    )
    file2.write_text(
        "\n".join(
            [
                "rule added { condition: true }",
                "rule shifted { condition: true }",
                "rule stable { condition: false }",
            ]
        ),
        encoding="utf-8",
    )

    result = SimpleASTDiffer().diff_files(file1, file2)

    assert result.added_rules == ["added"]
    assert result.modified_rules == []
    assert result.logical_changes == ["Rule added: added"]


def test_simple_ast_differ_modified_rules_are_sorted(tmp_path: Path) -> None:
    file1 = tmp_path / "old.yar"
    file2 = tmp_path / "new.yar"
    names = [
        "zeta",
        "alpha",
        "mu",
        "beta",
        "theta",
        "delta",
        "omega",
        "kappa",
        "eta",
        "gamma",
    ]

    file1.write_text(
        "\n".join(f"rule {name} {{ condition: true }}" for name in names),
        encoding="utf-8",
    )
    file2.write_text(
        "\n".join(f"rule {name} {{ condition: false }}" for name in names),
        encoding="utf-8",
    )

    result = SimpleASTDiffer().diff_files(file1, file2)

    assert result.modified_rules == sorted(names)
    assert [change.removeprefix("Rule modified: ") for change in result.logical_changes] == sorted(
        names
    )


def test_simple_ast_differ_handles_yarax_files(tmp_path: Path) -> None:
    file1 = tmp_path / "old.yar"
    file2 = tmp_path / "new.yar"
    file1.write_text(
        "rule x { condition: with xs = [1]: match xs { _ => true } }",
        encoding="utf-8",
    )
    file2.write_text(
        "rule x { condition: with xs = [1]: match xs { _ => false } }",
        encoding="utf-8",
    )

    result = SimpleASTDiffer().diff_files(file1, file2)

    assert result.modified_rules == ["x"]
    assert result.has_changes is True


def test_diff_ast_handles_yarax_ast() -> None:
    ast1 = YaraXParser("rule x { condition: with xs = [1]: match xs { _ => true } }").parse()
    ast2 = YaraXParser("rule x { condition: with xs = [1]: match xs { _ => false } }").parse()

    result = diff_ast(ast1, ast2)

    assert result.has_changes is True
    assert result.summary["modified"] > 0


def test_diff_ast_and_helpers() -> None:
    parser = Parser()
    ast1 = parser.parse("rule r1 { condition: true }")
    ast2 = parser.parse("rule r1 { condition: true }")
    ast3 = parser.parse("rule r1 { condition: false }")

    same = diff_ast(ast1, ast2)
    changed = diff_ast(ast1, ast3)

    assert same.has_changes is False
    assert changed.has_changes is True

    lines = diff_lines(["a", "b"], ["a", "c"])
    assert any(line.content.startswith("~") for line in lines)

    token_result = SimpleDiffer().diff("a b c", "a c d")
    assert token_result.has_changes is True
    assert token_result.summary["modified"] >= 1
