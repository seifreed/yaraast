from __future__ import annotations

from yaraast.ast.base import YaraFile
from yaraast.ast.comments import Comment, CommentGroup
from yaraast.ast.conditions import (
    AtExpression,
    Condition,
    ForExpression,
    ForOfExpression,
    InExpression,
    OfExpression,
)
from yaraast.ast.expressions import (
    ArrayAccess,
    BinaryExpression,
    BooleanLiteral,
    DoubleLiteral,
    FunctionCall,
    Identifier,
    IntegerLiteral,
    MemberAccess,
    ParenthesesExpression,
    RangeExpression,
    RegexLiteral,
    SetExpression,
    StringCount,
    StringIdentifier,
    StringLength,
    StringLiteral,
    StringOffset,
    StringWildcard,
    UnaryExpression,
)
from yaraast.ast.extern import ExternImport, ExternNamespace, ExternRule
from yaraast.ast.meta import Meta
from yaraast.ast.modifiers import StringModifier
from yaraast.ast.modules import DictionaryAccess, ModuleReference
from yaraast.ast.pragmas import InRulePragma, Pragma, PragmaBlock, PragmaType
from yaraast.ast.rules import Import, Include, Rule, Tag
from yaraast.ast.strings import (
    HexAlternative,
    HexByte,
    HexJump,
    HexNibble,
    HexString,
    HexWildcard,
    PlainString,
    RegexString,
)
from yaraast.codegen.generator import CodeGenerator


def test_codegen_generator_visit_yara_file_imports_includes_and_multiple_rules() -> None:
    gen = CodeGenerator()
    ast = YaraFile(
        imports=[Import(module="pe", alias="p")],
        includes=[Include(path="common.yar")],
        rules=[
            Rule(name="one", tags=[Tag("tag1")], condition=BooleanLiteral(True)),
            Rule(name="two", condition=BooleanLiteral(False)),
        ],
    )

    out = gen.generate(ast)

    assert 'import "pe" as p' in out
    assert 'include "common.yar"' in out
    assert "rule one : tag1 {" in out
    assert "\n\nrule two {" in out
    assert CodeGenerator().visit_import(Import(module="elf")) == ""


def test_codegen_generator_meta_and_string_section_variants() -> None:
    gen = CodeGenerator()
    rule = Rule(
        name="sections",
        meta={"author": "me", "enabled": True},
        strings=[
            PlainString("$a", value="hello", modifiers=[StringModifier.from_name_value("ascii")]),
            HexString(
                "$h",
                tokens=[HexByte("4d"), HexNibble(high=True, value="A")],
                modifiers=[StringModifier.from_name_value("wide")],
            ),
            RegexString("$r", regex="ab.*", modifiers=[StringModifier.from_name_value("nocase")]),
        ],
        condition=BooleanLiteral(True),
    )

    out = gen.generate(YaraFile(rules=[rule]))

    assert 'author = "me"' in out
    assert "enabled = true" in out
    assert '$a = "hello" ascii' in out
    assert "$h = { 4D A? } wide" in out
    assert "$r = /ab.*/ nocase" in out

    gen2 = CodeGenerator()
    gen2._write_meta_section([Meta("score", 7), object()])
    assert "score = 7" in gen2.buffer.getvalue()
    gen3 = CodeGenerator()
    gen3._write_meta_section("ignored")
    assert "meta:" in gen3.buffer.getvalue()

    gen4 = CodeGenerator()
    gen4._write_strings_section([PlainString("$b", value="x")], has_condition=False)
    assert gen4.buffer.getvalue().endswith("\n")

    gen5 = CodeGenerator()
    gen5._write_condition_section(None)
    assert gen5.buffer.getvalue() == ""


def test_codegen_generator_expression_and_condition_paths() -> None:
    gen = CodeGenerator()

    assert gen.visit_string_literal(StringLiteral('a"b')) == '"a\\"b"'
    assert gen.visit_regex_literal(RegexLiteral("ab.*", "i")) == "/ab.*/i"
    assert gen.visit_double_literal(DoubleLiteral(1.5)) == "1.5"
    assert (
        gen.visit_binary_expression(BinaryExpression(IntegerLiteral(1), "+", IntegerLiteral(2)))
        == "1 + 2"
    )
    assert gen.visit_unary_expression(UnaryExpression("not", BooleanLiteral(False))) == "not false"
    assert gen.visit_parentheses_expression(ParenthesesExpression(IntegerLiteral(1))) == "(1)"
    assert (
        gen.visit_set_expression(SetExpression([IntegerLiteral(1), IntegerLiteral(2)])) == "(1, 2)"
    )
    assert (
        gen.visit_range_expression(RangeExpression(IntegerLiteral(1), IntegerLiteral(3))) == "1..3"
    )
    assert (
        gen.visit_function_call(
            FunctionCall("math.entropy", [IntegerLiteral(1), IntegerLiteral(2)])
        )
        == "math.entropy(1, 2)"
    )
    assert gen.visit_array_access(ArrayAccess(Identifier("arr"), IntegerLiteral(0))) == "arr[0]"
    assert gen.visit_member_access(MemberAccess(Identifier("pe"), "is_dll")) == "pe.is_dll"
    assert (
        gen.visit_for_expression(
            ForExpression(
                "any", "i", RangeExpression(IntegerLiteral(1), IntegerLiteral(2)), Identifier("i")
            )
        )
        == "for any i in 1..2 : (i)"
    )
    assert (
        gen.visit_for_of_expression(ForOfExpression("all", Identifier("them"), Identifier("$a")))
        == "for all of them : ($a)"
    )
    assert gen.visit_at_expression(AtExpression("$a", IntegerLiteral(0))) == "$a at 0"
    assert (
        gen.visit_in_expression(InExpression("$a", ParenthesesExpression(StringOffset("a"))))
        == "$a in @a"
    )
    assert (
        gen.visit_of_expression(OfExpression(StringLiteral("all"), Identifier("them")))
        == "all of them"
    )


def test_codegen_generator_misc_visitors_and_fallbacks() -> None:
    gen = CodeGenerator()

    assert gen.visit_string_count(StringCount("a")) == "#a"
    assert gen.visit_string_offset(StringOffset("a", IntegerLiteral(1))) == "@a[1]"
    assert gen.visit_string_length(StringLength("a", IntegerLiteral(2))) == "!a[2]"
    assert gen.visit_hex_jump(HexJump(1, 3)) == "[1-3]"
    assert (
        gen.visit_hex_alternative(HexAlternative([[HexByte(1)], [HexWildcard()]])) == "( 01 | ?? )"
    )
    assert gen.visit_comment(Comment("note")) == "// note"
    assert (
        gen.visit_comment_group(CommentGroup(comments=[Comment("a"), Comment("b")])) == "// a\n// b"
    )
    assert gen.visit_extern_import(ExternImport("mods.yar")) == 'import "mods.yar"'
    assert gen.visit_extern_namespace(ExternNamespace("ns")) == "namespace ns"
    assert gen.visit_extern_rule(ExternRule("R")) == "rule R"
    assert (
        gen.visit_in_rule_pragma(InRulePragma(pragma=Pragma(PragmaType.PRAGMA, "demo")))
        == "#pragma demo"
    )
    assert gen.visit_pragma(Pragma(PragmaType.PRAGMA, "demo")) == "#pragma demo"
    assert "#pragma pragma" in gen.visit_pragma_block(
        PragmaBlock(pragmas=[Pragma(PragmaType.PRAGMA, "pragma")])
    )
    assert gen.visit_string_wildcard(StringWildcard("$a*")) == "$a*"
    assert gen.visit_string_identifier(StringIdentifier("$a")) == "$a"
    assert gen.visit_module_reference(ModuleReference("pe")) == "pe"
    assert (
        gen.visit_dictionary_access(
            DictionaryAccess(ModuleReference("pe"), StringLiteral("Company"))
        )
        == 'pe["Company"]'
    )
    assert gen.visit_condition(Condition()) == ""
    assert gen.visit_tag(Tag("x")) == "x"
    assert gen.visit_string_modifier(StringModifier.from_name_value("xor", (1, 3))) == "xor(1-3)"
    assert (
        gen.visit_string_modifier(StringModifier.from_name_value("base64", "custom"))
        == 'base64("custom")'
    )

    real_rule = Rule(name="r", condition=BooleanLiteral(True))
    gen2 = CodeGenerator()
    gen2._write_rule_header(real_rule)
    assert gen2.buffer.getvalue() == "rule r"

    plain_no_mods = CodeGenerator()
    assert plain_no_mods.visit_plain_string(PlainString("$a", value="x")) == ""
    assert plain_no_mods.buffer.getvalue().endswith('$a = "x"')
