from __future__ import annotations

from yaraast.ast.base import YaraFile
from yaraast.ast.conditions import Condition, InExpression
from yaraast.ast.expressions import (
    BooleanLiteral,
    Identifier,
    IntegerLiteral,
    ParenthesesExpression,
    RangeExpression,
    SetExpression,
    StringLength,
    StringLiteral,
    StringOffset,
    UnaryExpression,
)
from yaraast.ast.meta import Meta
from yaraast.ast.modifiers import StringModifier
from yaraast.ast.modules import DictionaryAccess, ModuleReference
from yaraast.ast.operators import DefinedExpression, StringOperatorExpression
from yaraast.ast.rules import Import, Include, Rule, Tag
from yaraast.ast.strings import (
    HexAlternative,
    HexByte,
    HexNibble,
    HexString,
    PlainString,
    RegexString,
    StringDefinition,
)
from yaraast.codegen.advanced_generator import AdvancedCodeGenerator
from yaraast.codegen.formatting import BraceStyle, FormattingConfig, StringStyle
from yaraast.codegen.generator import CodeGenerator


def test_codegen_generator_additional_visit_paths() -> None:
    gen = CodeGenerator()

    yara_file = YaraFile(
        imports=[Import(module="pe", alias="p")],
        includes=[Include(path="common.yar")],
        rules=[
            Rule(
                name="r1",
                modifiers=["private"],
                tags=[Tag("t1")],
                meta=[Meta("author", "me"), object()],
                strings=[
                    PlainString(
                        "$a", value="x", modifiers=[StringModifier.from_name_value("ascii")]
                    ),
                    HexString("$h", tokens=[HexByte(0x4D), HexNibble(high=False, value=0xA)]),
                    RegexString("$r", regex="ab.*"),
                ],
                condition=BooleanLiteral(True),
            ),
        ],
    )
    out = gen.generate(yara_file)
    assert 'import "pe" as p' in out
    assert 'include "common.yar"' in out
    assert "private rule r1 : t1 {" in out

    assert gen.visit_string_definition(StringDefinition("$x")) == ""
    assert gen.visit_expression(Condition()) == ""
    assert gen.visit_condition(Condition()) == ""
    assert gen.visit_hex_token(HexByte(1)) == ""
    assert gen.visit_meta(Meta("k", "v")) == 'k = "v"'
    assert gen.visit_meta(Meta("k", False)) == "k = false"
    assert gen.visit_meta(Meta("k", 7)) == "k = 7"
    assert (
        gen.visit_dictionary_access(DictionaryAccess(ModuleReference("pe"), "CompanyName"))
        == 'pe["CompanyName"]'
    )
    assert (
        gen.visit_dictionary_access(DictionaryAccess(ModuleReference("pe"), IntegerLiteral(1)))
        == "pe[1]"
    )
    assert gen.visit_defined_expression(DefinedExpression(Identifier("$a"))) == "defined $a"
    assert (
        gen.visit_string_operator_expression(
            StringOperatorExpression(StringLiteral("a"), "icontains", StringLiteral("b")),
        )
        == '"a" icontains "b"'
    )
    assert (
        gen.visit_in_expression(InExpression(subject="$a", range=Identifier("filesize")))
        == "$a in filesize"
    )
    assert (
        gen.visit_hex_alternative(HexAlternative([[HexByte(0x4D)], [HexByte(0x5A)]]))
        == "( 4D | 5A )"
    )
    assert gen.visit_string_offset(StringOffset(string_id="a", index=None)) == "@a"
    assert gen.visit_string_length(StringLength(string_id="a", index=None)) == "!a"
    assert gen.visit_unary_expression(UnaryExpression("-", IntegerLiteral(1))) == "-1"
    assert (
        gen.visit_in_expression(
            InExpression(
                subject="$a",
                range=ParenthesesExpression(RangeExpression(IntegerLiteral(1), IntegerLiteral(3))),
            )
        )
        == "$a in (1..3)"
    )


def test_advanced_generator_additional_paths() -> None:
    cfg = FormattingConfig(
        sort_meta=True,
        string_style=StringStyle.COMPACT,
        space_before_colon=True,
        space_after_colon=False,
        sort_rules=False,
        max_line_length=4,
    )
    adv = AdvancedCodeGenerator(cfg)

    rule_with_meta = Rule(
        name="a_rule",
        modifiers=["private"],
        tags=["x"],
        meta=[Meta("z", "quoted"), Meta("missing", "")],
        strings=[
            PlainString("$a", value="x"),
            HexString("$h", tokens=[HexByte(0x4D)]),
            RegexString("$r", regex="re"),
        ],
        condition=BooleanLiteral(True),
    )
    rule_without_meta = Rule(name="b_rule", condition=BooleanLiteral(False))
    out = adv.generate(
        YaraFile(
            imports=[Import("pe")],
            includes=[Include("c.yar")],
            rules=[rule_without_meta, rule_with_meta],
        )
    )

    assert 'import "pe"' in out
    assert 'include "c.yar"' in out
    assert "rule a_rule :x" in out
    assert '$a="x"' in out
    assert "$h={ 4d }" in out or "$h = { 4d }" in out or "$h={ 4D }" in out or "$h = { 4D }" in out
    assert "$r=/re/" in out

    adv2 = AdvancedCodeGenerator(
        FormattingConfig(space_around_operators=False, space_after_comma=False)
    )
    adv2.generate(YaraFile(rules=[]))
    assert "(" in adv2.visit_set_expression(
        SetExpression(elements=[IntegerLiteral(1), IntegerLiteral(2)])
    )


def test_advanced_generator_additional_formatting_paths() -> None:
    new_line_cfg = FormattingConfig(
        brace_style=BraceStyle.NEW_LINE, string_style=StringStyle.TABULAR
    )
    adv = AdvancedCodeGenerator(new_line_cfg)
    rule = Rule(
        name="fmt",
        tags=[Tag("one"), Tag("two")],
        meta={"b": 2, "a": '"quoted"', "flag": True},
        strings=[
            PlainString("$b", value="x", modifiers=[StringModifier.from_name_value("ascii")]),
            PlainString("$a", value="y"),
        ],
        condition=BooleanLiteral(True),
    )
    out = adv.generate(YaraFile(rules=[rule]))
    assert "rule fmt" in out
    assert "{\n" in out
    assert 'a    = "quoted"' in out or 'a = "quoted"' in out
    assert "flag = true" in out
    assert "$a" in out and "$b" in out


def test_advanced_generator_direct_remaining_branches() -> None:
    adv = AdvancedCodeGenerator(
        FormattingConfig(
            string_style=StringStyle.ALIGNED,
            align_string_modifiers=False,
            blank_lines_between_sections=2,
            space_after_comma=True,
            max_line_length=999,
        )
    )

    invalid_meta_list = [Meta("k", ""), object()]
    adv._write_meta_section(invalid_meta_list)
    meta_output = adv.buffer.getvalue()
    assert 'k = ""' in meta_output

    adv.buffer.seek(0)
    adv.buffer.truncate(0)
    assert adv._get_max_key_length([]) == 0
    adv._string_definitions = []
    adv._write_aligned_strings()
    assert adv.buffer.getvalue() == ""

    plain = PlainString(
        "$a",
        value="x",
        modifiers=[StringModifier.from_name_value("ascii")],
    )
    hexs = HexString(
        "$h",
        tokens=[HexByte(0x4D)],
        modifiers=[StringModifier.from_name_value("wide")],
    )
    regex = RegexString(
        "$r",
        regex="abc",
        modifiers=[StringModifier.from_name_value("nocase")],
    )
    rule = Rule(
        name="styled",
        meta=[Meta("author", "me"), object()],
        strings=[plain, hexs, regex],
        condition=BooleanLiteral(True),
    )
    out = adv.generate(YaraFile(rules=[rule]))
    assert "\n\nmeta:\n" not in out
    assert "\n\n\n    strings:\n" in out
    assert '$a = "x" ascii' in out
    assert "$h = { 4d } wide" in out or "$h = { 4D } wide" in out
    assert "$r = /abc/ nocase" in out

    adv2 = AdvancedCodeGenerator(FormattingConfig(space_after_comma=False))
    expr_out = adv2.visit_set_expression(
        SetExpression(elements=[IntegerLiteral(1), IntegerLiteral(2)])
    )
    assert expr_out.endswith("(1,2)")

    adv3 = AdvancedCodeGenerator(FormattingConfig())
    assert adv3._format_hex_token(HexByte(0x4D)) in {"4d", "4D"}


def test_advanced_generator_final_remaining_string_and_section_paths() -> None:
    class FlakyMeta:
        def __init__(self) -> None:
            self._has_key = True

        @property
        def key(self) -> str:
            if self._has_key:
                self._has_key = False
                return "ephemeral"
            raise AttributeError("key disappeared")

    adv = AdvancedCodeGenerator(
        FormattingConfig(
            section_order=["strings", "meta", "condition"],
            blank_lines_between_sections=1,
            string_style=StringStyle.ALIGNED,
            space_after_comma=True,
        )
    )

    # Exercise the defensive continue in _write_meta_section when a key disappears.
    adv._write_meta_section([FlakyMeta()])
    assert "meta:" in adv.buffer.getvalue()

    adv.buffer.seek(0)
    adv.buffer.truncate(0)

    rule = Rule(
        name="ordered",
        meta=[Meta("author", "me")],
        strings=[
            PlainString("$a", value="x", modifiers=[StringModifier.from_name_value("ascii")]),
            HexString(
                "$h", tokens=[HexByte(0x4D)], modifiers=[StringModifier.from_name_value("wide")]
            ),
            RegexString("$r", regex="abc", modifiers=[StringModifier.from_name_value("nocase")]),
        ],
        condition=BooleanLiteral(True),
    )
    out = adv.generate(YaraFile(rules=[rule]))
    assert "\n\n    meta:\n" in out

    adv2 = AdvancedCodeGenerator(
        FormattingConfig(string_style=StringStyle.ALIGNED, space_after_comma=True)
    )
    adv2.generate(YaraFile(rules=[]))
    assert (
        adv2.visit_plain_string(
            PlainString("$a", value="x", modifiers=[StringModifier.from_name_value("ascii")])
        )
        == ""
    )
    plain_output = adv2.buffer.getvalue()
    assert plain_output == '$a = "x" '

    adv2.buffer.seek(0)
    adv2.buffer.truncate(0)
    assert (
        adv2.visit_hex_string(
            HexString(
                "$h", tokens=[HexByte(0x4D)], modifiers=[StringModifier.from_name_value("wide")]
            )
        )
        == ""
    )
    hex_output = adv2.buffer.getvalue()
    assert hex_output in {"$h = { 4d } ", "$h = { 4D } "}

    adv2.buffer.seek(0)
    adv2.buffer.truncate(0)
    assert (
        adv2.visit_regex_string(
            RegexString("$r", regex="abc", modifiers=[StringModifier.from_name_value("nocase")])
        )
        == ""
    )
    assert adv2.buffer.getvalue() == "$r = /abc/ "

    adv3 = AdvancedCodeGenerator(FormattingConfig(space_after_comma=True))
    assert adv3.visit_set_expression(
        SetExpression(elements=[IntegerLiteral(1), IntegerLiteral(2)])
    ).endswith("(1, 2)")
