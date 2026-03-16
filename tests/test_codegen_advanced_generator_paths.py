from __future__ import annotations

from yaraast.ast.base import YaraFile
from yaraast.ast.conditions import Condition
from yaraast.ast.expressions import BinaryExpression, BooleanLiteral
from yaraast.ast.meta import Meta
from yaraast.ast.modifiers import StringModifier, StringModifierType
from yaraast.ast.rules import Import, Rule, Tag
from yaraast.ast.strings import PlainString
from yaraast.codegen.advanced_generator import AdvancedCodeGenerator
from yaraast.codegen.formatting import BraceStyle, FormattingConfig, StringStyle


class _KeyOnly:
    def __init__(self, key: str) -> None:
        self.key = key


class _AsText:
    def __str__(self) -> str:
        return "object-tag"


def test_advanced_generator_brace_styles_and_section_layout() -> None:
    rule = Rule(name="r", condition=BooleanLiteral(True))
    yara_file = YaraFile(rules=[rule])

    same = AdvancedCodeGenerator(FormattingConfig(brace_style=BraceStyle.SAME_LINE)).generate(
        yara_file
    )
    assert "rule r {" in same

    new_line = AdvancedCodeGenerator(FormattingConfig(brace_style=BraceStyle.NEW_LINE)).generate(
        yara_file,
    )
    assert "rule r\n{" in new_line or "rule r\r\n{" in new_line

    kandr = AdvancedCodeGenerator(FormattingConfig(brace_style=BraceStyle.K_AND_R)).generate(
        yara_file
    )
    assert "rule r\n{" in kandr or "rule r\r\n{" in kandr


def test_advanced_generator_long_condition_path_and_string_styles() -> None:
    long_condition = BinaryExpression(
        left=BinaryExpression(BooleanLiteral(True), "and", BooleanLiteral(False)),
        operator="or",
        right=BinaryExpression(BooleanLiteral(True), "and", BooleanLiteral(True)),
    )
    rule = Rule(
        name="long_cond",
        strings=[PlainString(identifier="$a", value="v")],
        condition=long_condition,
    )

    cfg = FormattingConfig(string_style=StringStyle.COMPACT, max_line_length=5)
    out = AdvancedCodeGenerator(cfg).generate(YaraFile(rules=[rule]))

    assert '$a="v"' in out
    assert "condition:" in out


def test_advanced_generator_meta_and_tags_branches() -> None:
    mod = StringModifier(StringModifierType.NOCASE)
    meta_list = [Meta("b", '"already"'), _KeyOnly("missing_value"), Meta("a", True)]

    rule = Rule(
        name="meta_rule",
        tags=[Tag("x"), "y", _AsText()],
        meta=meta_list,
        strings=[PlainString(identifier="$a", value="txt", modifiers=[mod])],
        condition=Condition(),
    )

    cfg = FormattingConfig(
        string_style=StringStyle.TABULAR,
        sort_meta=True,
        space_before_colon=False,
        space_after_colon=False,
    )
    out = AdvancedCodeGenerator(cfg).generate(YaraFile(imports=[Import("pe")], rules=[rule]))

    assert "rule meta_rule:x y object-tag" in out
    assert 'b             = "already"' in out or 'b = "already"' in out
    assert 'missing_value = ""' in out or 'missing_value = ""' in out
    assert "a             = true" in out or "a = true" in out


def test_advanced_generator_binary_and_set_spacing() -> None:
    expr = BinaryExpression(BooleanLiteral(True), "and", BooleanLiteral(False))

    spaced = AdvancedCodeGenerator(FormattingConfig(space_around_operators=True))
    spaced.generate(YaraFile(rules=[]))
    assert "(true and false)" in spaced.visit_binary_expression(expr)

    compact = AdvancedCodeGenerator(FormattingConfig(space_around_operators=False))
    compact.generate(YaraFile(rules=[]))
    assert "(trueandfalse)" in compact.visit_binary_expression(expr)
