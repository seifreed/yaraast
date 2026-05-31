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


def _yarax_rule(value: str) -> str:
    return f"rule x {{ condition: with xs = [1]: match xs {{ _ => {value} }} }}"


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
    assert "r1:$a" in analysis["string_signatures"]
    assert "r1:$r" in analysis["string_signatures"]
    assert "r1:$h" in analysis["string_signatures"]
    assert "r1.condition" in analysis["condition_signatures"]

    assert analyzer._get_condition_structure(None) == {"type": "empty"}
    cond = analyzer._get_condition_structure(
        BinaryExpression(Identifier("x"), "or", BooleanLiteral(False))
    )
    assert cond["type"] == "BinaryExpression"
    assert cond["operator"] == "or"
    assert cond["left"]["type"] == "Identifier"
    assert cond["right"]["type"] == "BooleanLiteral"


def test_ast_diff_distinguishes_byte_literal_from_matching_repr_text() -> None:
    old_ast = YaraFile(
        rules=[
            Rule(
                name="literal_collision",
                strings=[PlainString("$a", value=b"abc")],
                condition=BooleanLiteral(True),
            )
        ]
    )
    new_ast = YaraFile(
        rules=[
            Rule(
                name="literal_collision",
                strings=[PlainString("$a", value="b'abc'")],
                condition=BooleanLiteral(True),
            )
        ]
    )

    result = ASTDiffer().diff_asts(old_ast, new_ast)

    assert result.has_changes
    assert "String 'literal_collision:$a' content modified" in result.logical_changes


def test_ast_differ_diff_asts_detects_structural_logical_and_condition_changes() -> None:
    ast1 = Parser().parse("""
import "pe"

rule same {
    strings:
        $a = "abc"
    condition:
        $a
}
""")
    ast2 = Parser().parse("""
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
""")

    result = ASTDiffer().diff_asts(ast1, ast2)
    assert result.has_changes is True
    assert "added" in result.added_rules
    assert "same" in result.modified_rules
    assert any("File structure changed" in c for c in result.structural_changes)
    assert any("Added strings" in c for c in result.logical_changes)
    assert any("Condition logic changed in rule 'same'" in c for c in result.logical_changes)
    assert result.change_summary["added_rules"] == 1


def test_ast_differ_detects_changed_duplicate_rule_occurrence() -> None:
    ast1 = YaraFile(
        rules=[
            Rule("duplicate", condition=BooleanLiteral(True)),
            Rule("duplicate", condition=BooleanLiteral(False)),
        ],
    )
    ast2 = YaraFile(
        rules=[
            Rule("duplicate", condition=UnaryExpression("not", BooleanLiteral(True))),
            Rule("duplicate", condition=BooleanLiteral(False)),
        ],
    )

    result = ASTDiffer().diff_asts(ast1, ast2)

    assert result.has_changes is True
    assert any("Condition logic changed in rule 'duplicate#1'" in c for c in result.logical_changes)


def test_ast_differ_detects_changed_duplicate_string_occurrence() -> None:
    ast1 = YaraFile(
        rules=[
            Rule(
                "strings",
                strings=[
                    PlainString("$a", value="first"),
                    PlainString("$a", value="second"),
                ],
                condition=BooleanLiteral(True),
            ),
        ],
    )
    ast2 = YaraFile(
        rules=[
            Rule(
                "strings",
                strings=[
                    PlainString("$a", value="changed"),
                    PlainString("$a", value="second"),
                ],
                condition=BooleanLiteral(True),
            ),
        ],
    )

    result = ASTDiffer().diff_asts(ast1, ast2)

    assert result.has_changes is True
    assert "String 'strings:$a#1' content modified" in result.logical_changes


def test_ast_differ_public_change_lists_are_stably_sorted() -> None:
    ast1 = Parser().parse("""
rule z_removed { condition: true }
rule a_removed { condition: true }
rule m_removed { condition: true }

rule z_changed { condition: true }
rule a_changed { condition: true }
rule m_changed { condition: true }

rule string_changes {
    strings:
        $z = "z"
        $a = "a"
        $m = "m"
    condition:
        any of them
}
""")
    ast2 = Parser().parse("""
rule z_added { condition: true }
rule a_added { condition: true }
rule m_added { condition: true }

rule z_changed { condition: false }
rule a_changed { condition: false }
rule m_changed { condition: false }

rule string_changes {
    strings:
        $y = "y"
        $b = "b"
        $n = "n"
    condition:
        any of them
}
""")

    result = ASTDiffer().diff_asts(ast1, ast2)

    assert result.added_rules == ["a_added", "m_added", "z_added"]
    assert result.removed_rules == ["a_removed", "m_removed", "z_removed"]
    assert result.modified_rules == ["string_changes"]
    assert "Added strings: string_changes:$b, string_changes:$n, string_changes:$y" in (
        result.logical_changes
    )
    assert "Removed strings: string_changes:$a, string_changes:$m, string_changes:$z" in (
        result.logical_changes
    )
    assert [
        change for change in result.logical_changes if change.startswith("Condition logic changed")
    ] == [
        "Condition logic changed in rule 'a_changed'",
        "Condition logic changed in rule 'm_changed'",
        "Condition logic changed in rule 'z_changed'",
    ]


def test_ast_differ_diff_files_error_and_style_detection_paths(tmp_path: Path) -> None:
    differ = ASTDiffer()

    bad1 = tmp_path / "bad1.yar"
    bad2 = tmp_path / "bad2.yar"
    bad1.write_text("rule broken", encoding="utf-8")
    bad2.write_text("rule also_broken", encoding="utf-8")
    error_result = differ.diff_files(bad1, bad2)
    assert error_result.has_changes is True
    assert any("Error comparing files:" in c for c in error_result.logical_changes)

    same1 = tmp_path / "same1.yar"
    same2 = tmp_path / "same2.yar"
    same1.write_text("rule s { condition: true }", encoding="utf-8")
    same2.write_text("rule s { condition: true }", encoding="utf-8")
    same_result = differ.diff_files(same1, same2)
    assert same_result.has_changes is False
    assert same_result.change_summary["style_changes"] == 0

    ast = Parser().parse("rule s { condition: true }")
    style_result = differ._detect_style_changes(ast, ast, differ.diff_asts(ast, ast))
    assert style_result.style_only_changes == []


def test_ast_differ_diff_files_accepts_yarax(tmp_path: Path) -> None:
    file1 = tmp_path / "old.yar"
    file2 = tmp_path / "new.yar"
    file1.write_text(_yarax_rule("true"), encoding="utf-8")
    file2.write_text(_yarax_rule("false"), encoding="utf-8")

    result = ASTDiffer().diff_files(file1, file2)

    assert result.has_changes is True
    assert "x" not in result.added_rules
    assert any("Condition logic changed in rule 'x'" in c for c in result.logical_changes)


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
    assert any("Removed strings: r:$gone" in change for change in result.logical_changes)
    assert any("String 'r:$a' content modified" in change for change in result.logical_changes)


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
    assert "rx:$r" in analysis["string_signatures"]

    cond = analyzer._get_condition_structure(StringCount("$r"))
    assert cond["type"] == "StringCount"
    assert cond["children"] == []

    result = ASTDiffer().diff_asts(ast1, ast2)
    assert any("String 'rx:$r' content modified" in change for change in result.logical_changes)


def test_ast_differ_detects_hex_token_content_changes() -> None:
    ast1 = YaraFile(
        rules=[
            Rule(
                name="hex_rule",
                strings=[HexString("$h", tokens=[HexByte(0x41), HexByte(0x42)])],
                condition=BooleanLiteral(True),
            )
        ]
    )
    ast2 = YaraFile(
        rules=[
            Rule(
                name="hex_rule",
                strings=[HexString("$h", tokens=[HexByte(0x41), HexByte(0x43)])],
                condition=BooleanLiteral(True),
            )
        ]
    )

    result = ASTDiffer().diff_asts(ast1, ast2)

    assert result.has_changes is True
    assert any(
        "String 'hex_rule:$h' content modified" in change for change in result.logical_changes
    )


def test_ast_differ_detects_meta_value_changes() -> None:
    ast1 = YaraFile(
        rules=[
            Rule(
                name="meta_rule",
                meta=[MetaEntry.from_key_value("version", "one")],
                condition=BooleanLiteral(True),
            )
        ]
    )
    ast2 = YaraFile(
        rules=[
            Rule(
                name="meta_rule",
                meta=[MetaEntry.from_key_value("version", "two")],
                condition=BooleanLiteral(True),
            )
        ]
    )

    result = ASTDiffer().diff_asts(ast1, ast2)

    assert result.has_changes is True
    assert "meta_rule" in result.modified_rules


def test_ast_differ_detects_style_only_changes_from_original_text(tmp_path: Path) -> None:
    file1 = tmp_path / "style1.yar"
    file2 = tmp_path / "style2.yar"
    file1.write_text(
        'rule s {\n    strings:\n        $a = "abc"\n    condition:\n        $a\n}',
        encoding="utf-8",
    )
    file2.write_text(
        'rule  s  {\n  strings:\n      $a   =   "abc"\n    condition:\n\t$a\n}', encoding="utf-8"
    )

    result = ASTDiffer().diff_files(file1, file2)
    assert result.has_changes is True
    assert result.style_only_changes
    assert any(
        "whitespace/indentation" in change or "spacing/formatting" in change
        for change in result.style_only_changes
    )
