"""Additional real tests for OptimizationAnalyzer."""

from __future__ import annotations

from yaraast.analysis.optimization import OptimizationAnalyzer, OptimizationReport
from yaraast.ast.conditions import OfExpression
from yaraast.ast.expressions import BinaryExpression, Identifier, IntegerLiteral, StringIdentifier
from yaraast.ast.rules import Rule
from yaraast.ast.strings import HexByte, HexString, PlainString, RegexString
from yaraast.parser import Parser


def _parse(source: str):
    return Parser().parse(source)


def test_optimization_report_format_and_high_impact_count() -> None:
    report = OptimizationReport()
    report.add_suggestion("r1", "opt", "desc", "high")
    report.add_suggestion("r2", "opt", "desc", "medium")
    report.add_suggestion("r3", "opt", "desc", "weird")

    assert report.high_impact_count == 1
    assert report.suggestions[0].format().startswith("● [opt] r1:")
    assert report.suggestions[2].format().startswith("• [opt] r3:")


def test_optimization_analyzer_rule_without_condition_and_non_hex_plain_string() -> None:
    ast = _parse(
        """
        rule no_condition {
            strings:
                $a = "printable text"
        }
        """
    )

    report = OptimizationAnalyzer().analyze(ast)

    assert report.statistics["total_suggestions"] == 0


def test_optimization_analyzer_adds_string_hex_and_overlap_suggestions() -> None:
    ast = _parse(
        """
        rule mixed_strings {
            strings:
                $np = "\\x01\\x02A\\x03"
                $short = "abc"
                $long = "xxabcxx"
            condition:
                $short
        }
        """
    )

    report = OptimizationAnalyzer().analyze(ast)
    descriptions = [s.description for s in report.suggestions]

    assert any("hex pattern may be clearer" in d for d in descriptions)
    assert any("contained in" in d for d in descriptions)


def test_optimization_analyzer_hex_paths_condition_refs_and_specificity() -> None:
    hex_rule = Rule(
        name="hex_rule",
        strings=[
            HexString(identifier="$a", tokens=[HexByte(0x10), HexByte(0x11), HexByte(0x12)]),
            HexString(identifier="$b", tokens=[HexByte(0x10), HexByte(0x11), HexByte(0x99)]),
        ],
        condition=BinaryExpression(
            BinaryExpression(StringIdentifier("$s"), "and", StringIdentifier("$s")),
            "and",
            BinaryExpression(StringIdentifier("$s"), "and", StringIdentifier("$s")),
        ),
    )
    many_rule = Rule(
        name="many_rule",
        strings=[PlainString(identifier=f"$s{i}", value=f"v{i}") for i in range(11)],
        condition=OfExpression(quantifier=Identifier("any"), string_set=Identifier("them")),
    )

    report = OptimizationAnalyzer().analyze(
        __import__("yaraast.ast.base", fromlist=["YaraFile"]).YaraFile(
            imports=[],
            includes=[],
            rules=[hex_rule, many_rule],
        )
    )
    descriptions = [s.description for s in report.suggestions]

    assert any("referenced 4 times" in d for d in descriptions)
    assert any("'any of them' with many strings" in d for d in descriptions)
    assert not any("common prefix" in d for d in descriptions)


def test_optimization_analyzer_handles_regex_strings_and_mixed_hex_groups() -> None:
    mixed_rule = Rule(
        name="mixed_rule",
        strings=[
            RegexString(identifier="$re", regex="abc.*"),
            HexString(
                identifier="$a1",
                tokens=[HexByte(0xAA), HexByte(0xBB), HexByte(0xCC), HexByte(0xDD), HexByte(0x01)],
            ),
            HexString(
                identifier="$a2",
                tokens=[HexByte(0xAA), HexByte(0xBB), HexByte(0xCC), HexByte(0xDD), HexByte(0x02)],
            ),
            HexString(
                identifier="$b1",
                tokens=[HexByte(0x10), HexByte(0x11), HexByte(0x12), HexByte(0x13), HexByte(0x01)],
            ),
            HexString(
                identifier="$b2",
                tokens=[HexByte(0x10), HexByte(0x11), HexByte(0x12), HexByte(0x13), HexByte(0x02)],
            ),
            HexString(
                identifier="$b3",
                tokens=[HexByte(0x10), HexByte(0x11), HexByte(0x12), HexByte(0x13), HexByte(0x03)],
            ),
        ],
        condition=StringIdentifier("$re"),
    )

    report = OptimizationAnalyzer().analyze(
        __import__("yaraast.ast.base", fromlist=["YaraFile"]).YaraFile(
            imports=[],
            includes=[],
            rules=[mixed_rule],
        )
    )

    assert any("common prefix" in s.description for s in report.suggestions)


def test_optimization_analyzer_binary_without_current_rule_and_inverse_overlap() -> None:
    analyzer = OptimizationAnalyzer()
    analyzer.visit_binary_expression(
        BinaryExpression(
            BinaryExpression(IntegerLiteral(1), ">", IntegerLiteral(0)),
            "and",
            BinaryExpression(IntegerLiteral(1), ">", IntegerLiteral(2)),
        )
    )
    assert analyzer.report.suggestions == []

    ast = _parse(
        """
        rule inverse_overlap {
            strings:
                $big = "alphabet"
                $small = "alpha"
            condition:
                $big
        }
        """
    )
    report = OptimizationAnalyzer().analyze(ast)
    assert any("'$small' is contained in '$big'" in s.description for s in report.suggestions)


def test_optimization_analyzer_cross_rule_duplication_and_similarity() -> None:
    ast = _parse(
        """
        rule dup1 {
            strings:
                $a = "same"
            condition:
                $a
        }

        rule dup2 {
            strings:
                $a = "same"
            condition:
                $a
        }

        rule dup3 {
            strings:
                $a = "same"
            condition:
                $a
        }

        rule sim1 {
            strings:
                $a = "one"
            condition:
                $a
        }

        rule sim2 {
            strings:
                $a = "two"
            condition:
                $a
        }

        rule sim3 {
            strings:
                $a = "three"
            condition:
                $a
        }

        rule sim4 {
            strings:
                $a = "four"
            condition:
                $a
        }
        """
    )

    report = OptimizationAnalyzer().analyze(ast)
    descriptions = [s.description for s in report.suggestions]

    assert any("Same plain pattern used in 3 rules" in d for d in descriptions)
    assert any("rules have similar structure" in d for d in descriptions)
