from __future__ import annotations

from pathlib import Path

from yaraast.ast.base import YaraFile
from yaraast.ast.expressions import (
    BinaryExpression,
    BooleanLiteral,
    Identifier,
    StringCount,
    UnaryExpression,
)
from yaraast.ast.modifiers import MetaEntry
from yaraast.ast.rules import Rule
from yaraast.ast.strings import HexByte, HexString, PlainString, RegexString
from yaraast.cli.diff_tools import ASTDiffer, ASTStructuralAnalyzer
from yaraast.parser import Parser


def test_ast_structural_analyzer_collects_signatures_and_empty_condition() -> None:
    ast = YaraFile(
        imports=[],
        includes=[],
        rules=[
            Rule(
                name="r1",
                modifiers=["private"],
                tags=[],
                meta={"a": 1},
                strings=[
                    PlainString("$a", value="abc"),
                    RegexString("$r", regex="ab.*"),
                    HexString("$h", tokens=[HexByte(0x4D), HexByte(0x5A)]),
                ],
                condition=BinaryExpression(Identifier("$a"), "and", BooleanLiteral(True)),
            ),
            Rule(name="r2", condition=None),
        ],
    )

    analyzer = ASTStructuralAnalyzer()
    analysis = analyzer.analyze(ast)
    assert analysis["total_rules"] == 2
    assert "file" in analysis["structural_hash"]
    assert "r1" in analysis["rule_signatures"]
    assert "$a" in analysis["string_signatures"]
    assert "$r" in analysis["string_signatures"]
    assert "$h" in analysis["string_signatures"]
    assert "r1.condition" in analysis["condition_signatures"]

    assert analyzer._get_condition_structure(None) == {"type": "empty"}
    cond = analyzer._get_condition_structure(
        BinaryExpression(Identifier("x"), "or", BooleanLiteral(False))
    )
    assert cond["type"] == "BinaryExpression"
    assert cond["operator"] == "or"
    assert cond["left"]["type"] == "Identifier"
    assert cond["right"]["type"] == "BooleanLiteral"


def test_ast_differ_diff_asts_detects_structural_logical_and_condition_changes() -> None:
    ast1 = Parser().parse(
        """
import "pe"

rule same {
    strings:
        $a = "abc"
    condition:
        $a
}
"""
    )
    ast2 = Parser().parse(
        """
rule same {
    strings:
        $a = "xyz"
        $b = "new"
    condition:
        true
}

rule added {
    condition:
        true
}
"""
    )

    result = ASTDiffer().diff_asts(ast1, ast2)
    assert result.has_changes is True
    assert "added" in result.added_rules
    assert "same" in result.modified_rules
    assert any("File structure changed" in c for c in result.structural_changes)
    assert any("Added strings" in c for c in result.logical_changes)
    assert any("Condition logic changed in rule 'same'" in c for c in result.logical_changes)
    assert result.change_summary["added_rules"] == 1


def test_ast_differ_diff_files_error_and_style_detection_paths(tmp_path: Path) -> None:
    differ = ASTDiffer()

    bad1 = tmp_path / "bad1.yar"
    bad2 = tmp_path / "bad2.yar"
    bad1.write_text("rule broken")
    bad2.write_text("rule also_broken")
    error_result = differ.diff_files(bad1, bad2)
    assert error_result.has_changes is False
    assert any("Error comparing files:" in c for c in error_result.logical_changes)

    same1 = tmp_path / "same1.yar"
    same2 = tmp_path / "same2.yar"
    same1.write_text("rule s { condition: true }")
    same2.write_text("rule s { condition: true }")
    same_result = differ.diff_files(same1, same2)
    assert same_result.has_changes is False
    assert same_result.change_summary["style_changes"] == 0

    ast = Parser().parse("rule s { condition: true }")
    style_result = differ._detect_style_changes(ast, ast, differ.diff_asts(ast, ast))
    assert style_result.style_only_changes == []


def test_ast_differ_removed_strings_modified_strings_and_unary_condition() -> None:
    ast1 = YaraFile(
        imports=[],
        includes=[],
        rules=[
            Rule(
                name="r",
                strings=[
                    PlainString("$a", value="abc"),
                    PlainString("$gone", value="remove"),
                ],
                condition=UnaryExpression("not", Identifier("$a")),
            )
        ],
    )
    ast2 = YaraFile(
        imports=[],
        includes=[],
        rules=[
            Rule(
                name="r",
                strings=[PlainString("$a", value="xyz")],
                condition=UnaryExpression("not", Identifier("$a")),
            )
        ],
    )

    analyzer = ASTStructuralAnalyzer()
    cond = analyzer._get_condition_structure(UnaryExpression("not", Identifier("$a")))
    assert cond["type"] == "UnaryExpression"
    assert cond["operator"] == "not"
    assert cond["operand"]["type"] == "Identifier"

    result = ASTDiffer().diff_asts(ast1, ast2)
    assert any("Removed strings: $gone" in change for change in result.logical_changes)
    assert any("String '$a' content modified" in change for change in result.logical_changes)


def test_ast_structural_analyzer_meta_list_and_regex_content_changes() -> None:
    ast1 = YaraFile(
        rules=[
            Rule(
                name="rx",
                meta=[MetaEntry.from_key_value("author", "one")],
                strings=[RegexString("$r", regex="ab.*")],
                condition=StringCount("$r"),
            )
        ]
    )
    ast2 = YaraFile(
        rules=[
            Rule(
                name="rx",
                meta=[MetaEntry.from_key_value("author", "one")],
                strings=[RegexString("$r", regex="cd.*")],
                condition=StringCount("$r"),
            )
        ]
    )

    analyzer = ASTStructuralAnalyzer()
    analysis = analyzer.analyze(ast1)
    assert "rx" in analysis["rule_signatures"]
    assert "$r" in analysis["string_signatures"]

    cond = analyzer._get_condition_structure(StringCount("$r"))
    assert cond["type"] == "StringCount"
    assert cond["children"] == []

    result = ASTDiffer().diff_asts(ast1, ast2)
    assert any("String '$r' content modified" in change for change in result.logical_changes)


def test_ast_differ_detects_style_only_changes_from_original_text(tmp_path: Path) -> None:
    file1 = tmp_path / "style1.yar"
    file2 = tmp_path / "style2.yar"
    file1.write_text(
        'rule s {\n    strings:\n        $a = "abc"\n    condition:\n        $a\n}',
    )
    file2.write_text('rule  s  {\n  strings:\n      $a   =   "abc"\n    condition:\n\t$a\n}')

    result = ASTDiffer().diff_files(file1, file2)
    assert result.has_changes is False
    assert result.style_only_changes
    assert any(
        "whitespace/indentation" in change or "spacing/formatting" in change
        for change in result.style_only_changes
    )
