from __future__ import annotations

from typing import Any, cast

import pytest

from yaraast.ast.base import YaraFile
from yaraast.ast.conditions import OfExpression
from yaraast.ast.expressions import (
    BinaryExpression,
    BooleanLiteral,
    Identifier,
    IntegerLiteral,
    StringIdentifier,
)
from yaraast.ast.extern import ExternImport, ExternNamespace, ExternRule
from yaraast.ast.meta import Meta
from yaraast.ast.modifiers import StringModifier, StringModifierType
from yaraast.ast.pragmas import IncludeOncePragma
from yaraast.ast.rules import Import, Rule, Tag
from yaraast.ast.strings import PlainString, RegexString
from yaraast.codegen.formatting import BraceStyle, FormattingConfig, StringStyle
from yaraast.codegen.generator import CodeGenerator
from yaraast.codegen.options import GeneratorOptions
from yaraast.yarax.ast_nodes import SliceExpression


def test_advanced_generator_brace_styles_and_section_layout() -> None:
    rule = Rule(name="r", condition=BooleanLiteral(True))
    yara_file = YaraFile(imports=[Import("pe")], rules=[rule])

    same = CodeGenerator(
        options=GeneratorOptions(advanced=FormattingConfig(brace_style=BraceStyle.SAME_LINE))
    ).generate(yara_file)
    assert 'import "pe"' in same
    assert "rule r {" in same

    new_line = CodeGenerator(
        options=GeneratorOptions(advanced=FormattingConfig(brace_style=BraceStyle.NEW_LINE))
    ).generate(
        yara_file,
    )
    assert "rule r\n{" in new_line or "rule r\r\n{" in new_line

    kandr = CodeGenerator(
        options=GeneratorOptions(advanced=FormattingConfig(brace_style=BraceStyle.K_AND_R))
    ).generate(yara_file)
    assert "rule r {" in kandr


def test_advanced_generator_yara_file_preserves_top_level_extensions() -> None:
    yara_file = YaraFile(
        pragmas=[IncludeOncePragma()],
        imports=[Import("pe")],
        extern_imports=[ExternImport("external.yar", alias="ext", rules=["Remote"])],
        namespaces=[ExternNamespace("corp")],
        extern_rules=[ExternRule("Remote")],
        rules=[Rule(name="r", condition=BooleanLiteral(True))],
    )

    out = CodeGenerator(options=GeneratorOptions(advanced=FormattingConfig())).generate(yara_file)

    assert "#include_once" in out
    assert 'import "pe"' in out
    assert 'import "external.yar" (Remote) as ext' in out
    assert "namespace corp" in out
    assert "extern rule Remote" in out
    assert "rule r {" in out


def test_advanced_generator_long_condition_path_and_string_styles() -> None:
    long_condition = BinaryExpression(
        left=BinaryExpression(BooleanLiteral(True), "and", BooleanLiteral(False)),
        operator="or",
        right=BinaryExpression(BooleanLiteral(True), "and", BooleanLiteral(True)),
    )
    rule = Rule(
        name="long_cond",
        strings=[PlainString(identifier="$a", value="v")],
        condition=BinaryExpression(StringIdentifier("$a"), "and", long_condition),
    )

    cfg = FormattingConfig(string_style=StringStyle.COMPACT, max_line_length=5)
    out = CodeGenerator(options=GeneratorOptions(advanced=cfg)).generate(YaraFile(rules=[rule]))

    assert '$a="v"' in out
    assert "condition:" in out
    condition_body = out.split("condition:\n", maxsplit=1)[1].split("\n}", maxsplit=1)[0]
    condition_lines = [line for line in condition_body.splitlines() if line.strip()]
    assert len(condition_lines) > 1


def test_advanced_generator_regex_suffix_alias_modifiers_are_adjacent() -> None:
    rule = Rule(
        name="regex_aliases",
        strings=[
            RegexString(
                "$r",
                regex="ab.*",
                modifiers=["i", "s", StringModifier(StringModifierType.FULLWORD)],
            )
        ],
        condition=StringIdentifier("$r"),
    )

    compact = CodeGenerator(
        options=GeneratorOptions(advanced=FormattingConfig(string_style=StringStyle.COMPACT))
    ).generate(YaraFile(rules=[rule]))
    aligned = CodeGenerator(
        options=GeneratorOptions(advanced=FormattingConfig(string_style=StringStyle.ALIGNED))
    ).generate(YaraFile(rules=[rule]))

    assert "$r=/ab.*/is fullword" in compact
    assert "$r = /ab.*/is  fullword" in aligned
    assert "/ab.*/ i" not in compact
    assert "/ab.*/ i" not in aligned


def test_advanced_generator_rejects_unsupported_regex_multiline_modifier() -> None:
    rule = Rule(
        name="regex_multiline",
        strings=[
            RegexString(
                "$m",
                regex="^line",
                modifiers=[StringModifier(StringModifierType.MULTILINE)],
            ),
        ],
        condition=StringIdentifier("$m"),
    )

    with pytest.raises(ValueError, match="Unsupported regex modifier"):
        CodeGenerator(options=GeneratorOptions(advanced=FormattingConfig())).generate(
            YaraFile(rules=[rule])
        )


def test_advanced_generator_rejects_invalid_plain_modifier_combination() -> None:
    rule = Rule(
        name="plain_base64_nocase",
        strings=[
            PlainString(
                "$a",
                value="abc",
                modifiers=[
                    StringModifier.from_name_value("base64"),
                    StringModifier.from_name_value("nocase"),
                ],
            ),
        ],
        condition=StringIdentifier("$a"),
    )

    with pytest.raises(ValueError, match="cannot be combined"):
        CodeGenerator(options=GeneratorOptions(advanced=FormattingConfig())).generate(
            YaraFile(rules=[rule])
        )


def test_advanced_generator_aligned_plain_strings_escape_values() -> None:
    rule = Rule(
        name="escaped_strings",
        strings=[
            PlainString(identifier="$a", value="a\nb"),
            PlainString(identifier="$b", value=b'A"\x00'),
        ],
        condition=BinaryExpression(StringIdentifier("$a"), "and", StringIdentifier("$b")),
    )

    for style in (StringStyle.ALIGNED, StringStyle.TABULAR):
        out = CodeGenerator(
            options=GeneratorOptions(advanced=FormattingConfig(string_style=style))
        ).generate(YaraFile(rules=[rule]))

        assert '$a = "a\\nb"' in out
        assert '$b = "A\\"\\x00"' in out


def test_advanced_generator_skips_missing_condition() -> None:
    ast = YaraFile(rules=[Rule(name="partial")])

    with pytest.raises(
        ValueError,
        match="Rule 'partial' must have a condition for libyara output",
    ):
        CodeGenerator(options=GeneratorOptions(advanced=FormattingConfig())).generate(ast)


def test_advanced_generator_generate_returns_direct_expression_output() -> None:
    assert (
        CodeGenerator(options=GeneratorOptions(advanced=FormattingConfig())).generate(
            BooleanLiteral(True)
        )
        == "true"
    )


def test_advanced_generator_meta_and_tags_branches() -> None:
    mod = StringModifier(StringModifierType.NOCASE)
    meta_list = [Meta("b", '"already"'), Meta("a", True)]

    rule = Rule(
        name="meta_rule",
        tags=cast(Any, [Tag("x"), "y", "object_tag"]),
        meta=meta_list,
        strings=[PlainString(identifier="$a", value="txt", modifiers=[mod])],
        condition=OfExpression("any", Identifier("them")),
    )

    cfg = FormattingConfig(
        string_style=StringStyle.TABULAR,
        sort_meta=True,
        space_before_colon=False,
        space_after_colon=False,
    )
    out = CodeGenerator(options=GeneratorOptions(advanced=cfg)).generate(
        YaraFile(imports=[Import("pe")], rules=[rule])
    )

    assert "rule meta_rule:x y object_tag" in out
    assert 'b             = "\\"already\\""' in out or 'b = "\\"already\\""' in out
    assert "a             = true" in out or "a = true" in out


def test_advanced_generator_binary_and_set_spacing() -> None:
    expr = BinaryExpression(BooleanLiteral(True), "and", BooleanLiteral(False))
    equality = BinaryExpression(IntegerLiteral(1), "==", IntegerLiteral(2))
    division = BinaryExpression(IntegerLiteral(5), "/", IntegerLiteral(2))

    spaced = CodeGenerator(
        options=GeneratorOptions(advanced=FormattingConfig(space_around_operators=True))
    )
    spaced.generate(YaraFile(rules=[]))
    assert "(true and false)" in spaced.visit_binary_expression(expr)
    assert "(5 \\ 2)" in spaced.visit_binary_expression(division)

    compact = CodeGenerator(
        options=GeneratorOptions(advanced=FormattingConfig(space_around_operators=False))
    )
    compact.generate(YaraFile(rules=[]))
    assert "(true and false)" in compact.visit_binary_expression(expr)
    assert "(1==2)" in compact.visit_binary_expression(equality)
    assert "(5\\2)" in compact.visit_binary_expression(division)


def test_code_generator_parenthesizes_compound_slice_targets() -> None:
    expr = SliceExpression(
        target=BinaryExpression(
            left=Identifier("a"),
            operator="+",
            right=Identifier("b"),
        ),
        start=IntegerLiteral(0),
        stop=IntegerLiteral(1),
    )

    assert CodeGenerator().visit(expr) == "(a + b)[0:1]"
    assert (
        CodeGenerator(options=GeneratorOptions(advanced=FormattingConfig())).visit(expr)
        == "(a + b)[0:1]"
    )
