from __future__ import annotations

from yaraast.ast.base import Location, YaraFile
from yaraast.ast.conditions import OfExpression
from yaraast.ast.expressions import (
    BinaryExpression,
    BooleanLiteral,
    Identifier,
    IntegerLiteral,
    SetExpression,
)
from yaraast.ast.modifiers import StringModifier, StringModifierType
from yaraast.ast.rules import Rule
from yaraast.ast.strings import HexByte, HexJump, HexString, PlainString, RegexString
from yaraast.yarax.compatibility_checker import CompatibilityIssue, YaraXCompatibilityChecker
from yaraast.yarax.feature_flags import YaraXFeatures
from yaraast.yarax.parser import YaraXParser


def test_compatibility_issue_string_and_rule_meta_paths() -> None:
    issue = CompatibilityIssue("error", Location(2, 3), "kind", "broken")
    assert str(issue) == "[ERROR] 2:3: broken"

    checker = YaraXCompatibilityChecker(YaraXFeatures.yarax_strict())
    yara_file = YaraFile(
        rules=[
            Rule(name="dict_meta", meta={"author": "x"}, condition=BooleanLiteral(True)),
            Rule(
                name="list_meta",
                meta=[PlainString(identifier="$m", value="meta")],
                condition=BooleanLiteral(True),
            ),
        ],
    )
    assert checker.check(yara_file) == []


def test_checker_covers_plain_regex_hex_and_quantifier_helpers() -> None:
    checker = YaraXCompatibilityChecker(YaraXFeatures.yarax_strict())

    plain = PlainString(
        identifier="$a",
        value="-bad-",
        modifiers=[
            StringModifier(StringModifierType.XOR),
            StringModifier(StringModifierType.FULLWORD),
        ],
    )
    checker.visit_plain_string(plain)
    assert any(i.issue_type == "xor_fullword_boundary" for i in checker.issues)

    checker.issues.clear()
    checker.visit_plain_string(
        PlainString(
            identifier="$single",
            value="a",
            modifiers=[
                StringModifier(StringModifierType.XOR),
                StringModifier(StringModifierType.FULLWORD),
            ],
        )
    )
    assert not any(i.issue_type == "xor_fullword_boundary" for i in checker.issues)

    checker.issues.clear()
    checker.visit_plain_string(PlainString(identifier="$b", value=b"aa", modifiers=["base64"]))
    assert any(i.issue_type == "base64_too_short" for i in checker.issues)

    checker.issues.clear()
    checker.visit_plain_string(
        PlainString(
            identifier="$xb",
            value=b"-bad-",
            modifiers=[
                StringModifier(StringModifierType.XOR),
                StringModifier(StringModifierType.FULLWORD),
            ],
        )
    )
    assert any(i.issue_type == "xor_fullword_boundary" for i in checker.issues)

    regex = RegexString(identifier="$r", regex=r"\g", modifiers=[])
    checker.visit_regex_string(regex)
    assert any(i.issue_type == "invalid_escape" for i in checker.issues)

    assert checker._is_valid_quantifier("a{2}", 1) is True
    assert checker._is_valid_quantifier("a{2,}", 1) is True
    assert checker._is_valid_quantifier("a{2", 1) is False
    assert checker._is_valid_quantifier("a{2,x}", 1) is False
    assert checker._skip_digits("ab", 1) is False
    assert checker._get_position_after_digits("123x", 0) == 3

    checker.visit_hex_string(HexString(identifier="$h", tokens=[HexByte(0x41), HexJump(1, 2)]))
    checker.visit_hex_jump(HexJump(2, 4))
    checker_no_hex = YaraXCompatibilityChecker(YaraXFeatures.yara_compatible())
    checker_no_hex.visit_hex_jump(HexJump(3, 5))


def test_checker_reports_yarax_features_with_identifier_and_of_expression() -> None:
    checker = YaraXCompatibilityChecker(YaraXFeatures.yara_compatible())
    checker.current_rule = "demo"
    checker.visit_identifier(Identifier(name="with"))
    assert any(i.issue_type == "unsupported_feature" for i in checker.issues)

    checker.features.allow_tuple_of_expressions = True
    of_expr = OfExpression(
        quantifier=IntegerLiteral(1),
        string_set=SetExpression(
            elements=[BinaryExpression(BooleanLiteral(True), "and", BooleanLiteral(False))],
        ),
    )
    checker.visit_of_expression(of_expr)
    checker.visit_of_expression(OfExpression(quantifier="any", string_set=["$a", "$b"]))
    report = checker.get_report()

    assert "yarax_feature" in report["issues_by_type"]
    assert any(
        "boolean expressions in 'of' statement" in item for item in report["yarax_features_used"]
    )
    assert report["migration_difficulty"] == "moderate"


def test_checker_reports_parsed_yarax_nodes_for_yara_compatibility() -> None:
    ast = YaraXParser(
        """
rule native_yarax {
    condition:
        with xs = [1, ...arr],
             f = lambda x: x,
             ac = [x for x in [1, 2] if x],
             dc = {k: v for k, v in data if v}:
            match xs[0] { 1 => true, _ => false }
}
""",
    ).parse()

    strict_issues = YaraXCompatibilityChecker(YaraXFeatures.yarax_strict()).check(ast)
    assert not any(issue.issue_type == "yarax_feature" for issue in strict_issues)

    checker = YaraXCompatibilityChecker(YaraXFeatures.yara_compatible())
    issues = checker.check(ast)
    features = {
        issue.message.split(": ", 1)[1] for issue in issues if issue.issue_type == "yarax_feature"
    }

    assert {
        "array comprehensions",
        "dict comprehensions",
        "lambda expressions",
        "list expressions",
        "pattern matching",
        "spread operators",
        "with statements",
    }.issubset(features)
    assert all(issue.severity == "error" for issue in issues if issue.issue_type == "yarax_feature")
    assert "with statements" in checker.get_report()["yarax_features_used"]
    assert checker.get_report()["yarax_features_used"] == [
        "with statements",
        "list expressions",
        "spread operators",
        "lambda expressions",
        "array comprehensions",
        "dict comprehensions",
        "pattern matching",
    ]


def test_checker_reports_nested_collection_only_yarax_features() -> None:
    ast = YaraXParser(
        """
rule collection_features {
    condition:
        [true][0] and {"a": true}["a"] and "abc"[0:1] == "a" and (1, 2)[0] == 1
}
""",
    ).parse()

    checker = YaraXCompatibilityChecker(YaraXFeatures.yara_compatible())
    issues = checker.check(ast)
    features = {
        issue.message.split(": ", 1)[1] for issue in issues if issue.issue_type == "yarax_feature"
    }

    assert {
        "dict expressions",
        "list expressions",
        "slice expressions",
        "tuple expressions",
        "tuple indexing",
    }.issubset(features)


def test_checker_assesses_migration_difficulty_levels() -> None:
    checker = YaraXCompatibilityChecker(YaraXFeatures.yarax_strict())
    assert checker.get_report()["migration_difficulty"] == "trivial"

    checker.issues = [CompatibilityIssue("warning", None, "warn", "warning")]
    assert checker.get_report()["migration_difficulty"] == "easy"

    checker.issues = [CompatibilityIssue("error", None, "err", "error") for _ in range(6)]
    assert checker.get_report()["migration_difficulty"] == "difficult"
