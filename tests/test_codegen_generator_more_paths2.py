from __future__ import annotations

from typing import Any, cast

import pytest

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
    Expression,
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
from yaraast.ast.extern import ExternImport, ExternNamespace, ExternRule, ExternRuleReference
from yaraast.ast.meta import Meta
from yaraast.ast.modifiers import StringModifier
from yaraast.ast.modules import DictionaryAccess, ModuleReference
from yaraast.ast.operators import StringOperatorExpression
from yaraast.ast.pragmas import (
    ConditionalDirective,
    CustomPragma,
    DefineDirective,
    IncludeOncePragma,
    InRulePragma,
    Pragma,
    PragmaBlock,
    PragmaType,
    UndefDirective,
)
from yaraast.ast.rules import Import, Include, Rule, Tag
from yaraast.ast.strings import (
    HexAlternative,
    HexByte,
    HexJump,
    HexNegatedByte,
    HexNibble,
    HexString,
    HexWildcard,
    PlainString,
    RegexString,
    StringDefinition,
)
from yaraast.codegen.formatting import FormattingConfig, StringStyle
from yaraast.codegen.generator import CodeGenerator
from yaraast.codegen.options import GeneratorOptions
from yaraast.codegen.pretty_printer import PrettyPrintOptions
from yaraast.lexer.lexer_tables import YARA_IDENTIFIER_MAX_LENGTH
from yaraast.limits import LIBYARA_HEX_JUMP_MAX
from yaraast.parser import Parser
from yaraast.serialization.json_serializer import JsonSerializer
from yaraast.shared.integer_semantics import INT64_MIN
from yaraast.yarax.ast_nodes import (
    ArrayComprehension,
    DictExpression,
    LambdaExpression,
    ListExpression,
    MatchCase,
    PatternMatch,
    TupleExpression,
    WithStatement,
)
from yaraast.yarax.generator import YaraXGenerator


class _BrokenCondition(Condition):
    def accept(self, visitor: Any) -> Any:
        raise RuntimeError("broken condition")


class _FalsyIntegerLiteral(IntegerLiteral):
    def __bool__(self) -> bool:
        return False


class _FalsyBooleanLiteral(BooleanLiteral):
    def __bool__(self) -> bool:
        return False


def test_alternate_generators_indent_nested_yarax_match_case_results() -> None:
    nested = PatternMatch(
        value=Identifier("y"),
        cases=[],
        default=BooleanLiteral(True),
    )
    condition = PatternMatch(
        value=Identifier("x"),
        cases=[MatchCase(pattern=IntegerLiteral(1), result=nested)],
        default=BooleanLiteral(False),
    )
    expected = (
        "match x {\n"
        "    1 => match y {\n"
        "        _ => true,\n"
        "    },\n"
        "    _ => false,\n"
        "}"
    )

    assert (
        CodeGenerator(options=GeneratorOptions(advanced=FormattingConfig())).generate(condition)
        == expected
    )
    assert CodeGenerator(options=GeneratorOptions.comment_aware()).generate(condition) == expected


def test_codegen_generator_visit_yara_file_imports_includes_and_multiple_rules() -> None:
    gen = CodeGenerator()
    ast = YaraFile(
        imports=[Import(module="pe")],
        extern_imports=[ExternImport("external.yar", alias="ext", rules=["ExternalRule"])],
        includes=[Include(path="common.yar")],
        pragmas=[IncludeOncePragma()],
        namespaces=[ExternNamespace("corp")],
        extern_rules=[ExternRule("ExternalRule")],
        rules=[
            Rule(name="one", tags=[Tag("tag1")], condition=BooleanLiteral(True)),
            Rule(name="two", condition=BooleanLiteral(False)),
        ],
    )

    out = gen.generate(ast)

    assert "#include_once" in out
    assert 'import "pe"' in out
    assert 'import "external.yar" (ExternalRule) as ext' in out
    assert 'include "common.yar"' in out
    assert "namespace corp" in out
    assert "extern rule ExternalRule" in out
    assert "rule one : tag1 {" in out
    assert "\n\nrule two {" in out
    assert CodeGenerator().visit_import(Import(module="elf")) == ""


def test_codegen_preserves_located_top_level_pragma_order() -> None:
    ast = Parser().parse("""
#define FEATURE 1
#ifdef FEATURE
rule guarded {
    condition:
        true
}
#endif
""")

    out = CodeGenerator().generate(ast)

    define_index = out.index("#define FEATURE 1")
    ifdef_index = out.index("#ifdef FEATURE")
    rule_index = out.index("rule guarded")
    endif_index = out.index("#endif")
    assert define_index < ifdef_index < rule_index < endif_index


@pytest.mark.parametrize(
    ("ast", "message"),
    [
        (
            YaraFile(imports=[Import("")], rules=[Rule("r", condition=BooleanLiteral(True))]),
            "Import module must not be empty",
        ),
        (
            YaraFile(imports=[Import("   ")], rules=[Rule("r", condition=BooleanLiteral(True))]),
            "Import module must not be empty",
        ),
        (
            YaraFile(includes=[Include("")], rules=[Rule("r", condition=BooleanLiteral(True))]),
            "Include path must not be empty",
        ),
        (
            YaraFile(includes=[Include("\t")], rules=[Rule("r", condition=BooleanLiteral(True))]),
            "Include path must not be empty",
        ),
        (
            YaraFile(
                extern_imports=[ExternImport("")],
                rules=[Rule("r", condition=BooleanLiteral(True))],
            ),
            "Import module must not be empty",
        ),
        (
            YaraFile(
                extern_imports=[ExternImport("   ")],
                rules=[Rule("r", condition=BooleanLiteral(True))],
            ),
            "Import module must not be empty",
        ),
    ],
)
def test_codegen_generators_reject_empty_import_and_include_paths(
    ast: YaraFile,
    message: str,
) -> None:
    with pytest.raises(ValueError, match=message):
        CodeGenerator().generate(ast)
    with pytest.raises(ValueError, match=message):
        CodeGenerator(options=GeneratorOptions(advanced=FormattingConfig())).generate(ast)
    with pytest.raises(ValueError, match=message):
        CodeGenerator(options=GeneratorOptions.comment_aware()).generate(ast)
    with pytest.raises(ValueError, match=message):
        CodeGenerator(options=GeneratorOptions(pretty=PrettyPrintOptions())).generate(ast)


@pytest.mark.parametrize(
    ("ast", "message"),
    [
        (
            YaraFile(
                imports=[Import('bad"module')], rules=[Rule("r", condition=BooleanLiteral(True))]
            ),
            "Import module must not contain quotes or control characters",
        ),
        (
            YaraFile(
                imports=[Import("bad\nmodule")], rules=[Rule("r", condition=BooleanLiteral(True))]
            ),
            "Import module must not contain quotes or control characters",
        ),
        (
            YaraFile(
                includes=[Include('bad"path')], rules=[Rule("r", condition=BooleanLiteral(True))]
            ),
            "Include path must not contain quotes or control characters",
        ),
        (
            YaraFile(
                includes=[Include("bad\npath")], rules=[Rule("r", condition=BooleanLiteral(True))]
            ),
            "Include path must not contain quotes or control characters",
        ),
        (
            YaraFile(
                extern_imports=[ExternImport('bad"module')],
                rules=[Rule("r", condition=BooleanLiteral(True))],
            ),
            "Import module must not contain quotes or control characters",
        ),
    ],
)
def test_codegen_generators_reject_invalid_directive_quoted_values(
    ast: YaraFile,
    message: str,
) -> None:
    with pytest.raises(ValueError, match=message):
        CodeGenerator().generate(ast)
    with pytest.raises(ValueError, match=message):
        CodeGenerator(options=GeneratorOptions(advanced=FormattingConfig())).generate(ast)
    with pytest.raises(ValueError, match=message):
        CodeGenerator(options=GeneratorOptions.comment_aware()).generate(ast)
    with pytest.raises(ValueError, match=message):
        CodeGenerator(options=GeneratorOptions(pretty=PrettyPrintOptions())).generate(ast)


@pytest.mark.parametrize(
    "string_def",
    [
        PlainString(identifier="$a", value="abc", is_anonymous=cast(Any, [])),
        HexString(identifier="$h", tokens=[HexByte(value=0x41)], is_anonymous=cast(Any, 1.5)),
        RegexString(identifier="$r", regex="abc", is_anonymous=cast(Any, "")),
    ],
)
def test_codegen_generators_reject_invalid_string_anonymous_flags(
    string_def: PlainString | HexString | RegexString,
) -> None:
    ast = YaraFile(
        rules=[
            Rule(
                name="r",
                strings=[string_def],
                condition=StringIdentifier(name=string_def.identifier),
            )
        ]
    )

    with pytest.raises(TypeError, match="is_anonymous must be a boolean"):
        CodeGenerator().generate(ast)
    with pytest.raises(TypeError, match="is_anonymous must be a boolean"):
        CodeGenerator(options=GeneratorOptions(advanced=FormattingConfig())).generate(ast)
    with pytest.raises(TypeError, match="is_anonymous must be a boolean"):
        CodeGenerator(options=GeneratorOptions.comment_aware()).generate(ast)
    with pytest.raises(TypeError, match="is_anonymous must be a boolean"):
        CodeGenerator(options=GeneratorOptions(pretty=PrettyPrintOptions())).generate(ast)


@pytest.mark.parametrize(
    "string_def",
    [
        PlainString(identifier="$a", value="abc", modifiers=cast(Any, None)),
        HexString(identifier="$h", tokens=[HexByte(value=0x41)], modifiers=cast(Any, None)),
        RegexString(identifier="$r", regex="abc", modifiers=cast(Any, None)),
    ],
)
def test_codegen_generators_reject_missing_string_modifier_collections(
    string_def: PlainString | HexString | RegexString,
) -> None:
    ast = YaraFile(
        rules=[
            Rule(
                name="r",
                strings=[string_def],
                condition=StringIdentifier(name=string_def.identifier),
            )
        ]
    )

    with pytest.raises(TypeError, match="String modifiers must be a list or tuple"):
        CodeGenerator().generate(ast)
    with pytest.raises(TypeError, match="String modifiers must be a list or tuple"):
        CodeGenerator(options=GeneratorOptions(advanced=FormattingConfig())).generate(ast)
    with pytest.raises(TypeError, match="String modifiers must be a list or tuple"):
        CodeGenerator(options=GeneratorOptions.comment_aware()).generate(ast)
    with pytest.raises(TypeError, match="String modifiers must be a list or tuple"):
        CodeGenerator(options=GeneratorOptions(pretty=PrettyPrintOptions())).generate(ast)


@pytest.mark.parametrize("bad_high", [None, 0, 1.5, "", [], {}])
def test_codegen_generators_reject_invalid_hex_nibble_high_flags(bad_high: Any) -> None:
    ast = YaraFile(
        rules=[
            Rule(
                name="r",
                strings=[
                    HexString(
                        identifier="$h",
                        tokens=[HexNibble(high=cast(bool, bad_high), value=0xA)],
                    )
                ],
                condition=StringIdentifier(name="$h"),
            )
        ]
    )

    with pytest.raises(TypeError, match="HexNibble high must be a boolean"):
        CodeGenerator().generate(ast)
    with pytest.raises(TypeError, match="HexNibble high must be a boolean"):
        CodeGenerator(options=GeneratorOptions(advanced=FormattingConfig())).generate(ast)
    with pytest.raises(TypeError, match="HexNibble high must be a boolean"):
        CodeGenerator(options=GeneratorOptions.comment_aware()).generate(ast)
    with pytest.raises(TypeError, match="HexNibble high must be a boolean"):
        CodeGenerator(options=GeneratorOptions(pretty=PrettyPrintOptions())).generate(ast)


def test_codegen_generator_formats_standard_leading_comments() -> None:
    rule = Rule("commented", condition=BooleanLiteral(True))
    rule.leading_comments = [Comment("plain lead")]

    out = CodeGenerator().generate(YaraFile(rules=[rule]))

    assert out.startswith("// plain lead\nrule commented")


@pytest.mark.parametrize(
    "comment_target",
    ["leading", "trailing"],
)
def test_codegen_generator_rejects_standard_comment_newlines(comment_target: str) -> None:
    rule = Rule("bad_comment", condition=BooleanLiteral(True))
    comment = Comment("first\nsecond")
    if comment_target == "leading":
        rule.leading_comments = [comment]
    else:
        rule.trailing_comment = comment

    with pytest.raises(ValueError, match="Comment text must not contain newlines"):
        CodeGenerator().generate(YaraFile(rules=[rule]))


@pytest.mark.parametrize(
    "comment_target",
    ["leading", "trailing"],
)
def test_codegen_generator_rejects_standard_comment_surrogates(
    comment_target: str,
) -> None:
    rule = Rule("bad_comment", condition=BooleanLiteral(True))
    comment = Comment("\ud800")
    if comment_target == "leading":
        rule.leading_comments = [comment]
    else:
        rule.trailing_comment = comment

    with pytest.raises(ValueError, match="Comment text must not contain Unicode surrogate"):
        CodeGenerator().generate(YaraFile(rules=[rule]))


@pytest.mark.parametrize(
    ("comment_target", "comment_text"),
    [
        ("leading", "null\x00line"),
        ("leading", "/* null\x00block */"),
        ("trailing", "null\x00line"),
        ("trailing", "/* null\x00block */"),
    ],
)
def test_codegen_generator_rejects_standard_comment_embedded_nul(
    comment_target: str,
    comment_text: str,
) -> None:
    rule = Rule("bad_comment", condition=BooleanLiteral(True))
    comment = Comment(comment_text)
    if comment_target == "leading":
        rule.leading_comments = [comment]
    else:
        rule.trailing_comment = comment

    with pytest.raises(ValueError, match="Comment text must not contain embedded NUL"):
        CodeGenerator().generate(YaraFile(rules=[rule]))


@pytest.mark.parametrize("comment_target", ["leading", "trailing"])
@pytest.mark.parametrize("is_multiline", [cast(Any, "yes"), cast(Any, 1), cast(Any, None)])
def test_codegen_generator_rejects_invalid_comment_multiline_flags(
    comment_target: str,
    is_multiline: Any,
) -> None:
    rule = Rule("bad_comment", condition=BooleanLiteral(True))
    comment = Comment("note", is_multiline=is_multiline)
    if comment_target == "leading":
        rule.leading_comments = [comment]
    else:
        rule.trailing_comment = comment

    with pytest.raises(TypeError, match="Comment is_multiline must be a boolean"):
        CodeGenerator().generate(YaraFile(rules=[rule]))


@pytest.mark.parametrize(
    ("comments", "message"),
    [
        (cast(Any, ""), "CommentGroup comments must be a list"),
        (cast(Any, {}), "CommentGroup comments must be a list"),
        (cast(Any, [object()]), "CommentGroup comments must contain Comment nodes"),
    ],
)
def test_codegen_generator_rejects_invalid_comment_group_containers(
    comments: Any,
    message: str,
) -> None:
    rule = Rule("bad_comment_group", condition=BooleanLiteral(True))
    cast(Any, rule).leading_comments = [CommentGroup(comments)]

    with pytest.raises(TypeError, match=message):
        CodeGenerator().generate(YaraFile(rules=[rule]))


def test_codegen_generate_resets_indent_after_failed_generation() -> None:
    gen = CodeGenerator()
    with pytest.raises(RuntimeError, match="broken condition"):
        gen.generate(YaraFile(rules=[Rule(name="bad", condition=_BrokenCondition())]))

    out = gen.generate(YaraFile(rules=[Rule(name="ok", condition=BooleanLiteral(True))]))

    assert out == "rule ok {\n    condition:\n        true\n}\n"


def test_codegen_generator_preserves_namespaced_extern_rules() -> None:
    out = CodeGenerator().generate(
        YaraFile(
            namespaces=[
                ExternNamespace(
                    "corp",
                    extern_rules=[
                        ExternRule("Nested"),
                        ExternRule("AlreadyQualified", namespace="legacy"),
                    ],
                )
            ]
        )
    )

    assert "namespace corp" in out
    assert "extern rule corp.Nested" in out
    assert "extern rule legacy.AlreadyQualified" in out


def test_codegen_generators_emit_anonymous_string_identifier() -> None:
    ast = Parser().parse("""
        rule anonymous_strings {
            strings:
                $ = "abc"
                $ = { 41 }
                $ = /def/
            condition:
                any of them
        }
        """)

    generated = CodeGenerator().generate(ast)
    pretty = CodeGenerator(options=GeneratorOptions(pretty=PrettyPrintOptions())).generate(ast)
    advanced = CodeGenerator(options=GeneratorOptions(advanced=FormattingConfig())).generate(ast)
    compact = CodeGenerator(
        options=GeneratorOptions(advanced=FormattingConfig(string_style=StringStyle.COMPACT))
    ).generate(ast)

    for output in (generated, advanced):
        assert '$ = "abc"' in output
        assert "$ = { 41 }" in output
        assert "$ = /def/" in output
        assert "$anon_" not in output
    assert '$  = "abc"' in pretty
    assert "$  = { 41 }" in pretty
    assert "$  = /def/" in pretty
    assert "$anon_" not in pretty
    assert '$="abc"' in compact
    assert "$={ 41 }" in compact
    assert "$=/def/" in compact
    assert "$anon_" not in compact


def test_codegen_generators_normalize_direct_ast_string_identifiers() -> None:
    ast = YaraFile(
        rules=[
            Rule(
                name="direct_string",
                strings=[PlainString(identifier="a", value="x")],
                condition=StringIdentifier("$a"),
            )
        ]
    )

    generated = CodeGenerator().generate(ast)
    pretty = CodeGenerator(options=GeneratorOptions(pretty=PrettyPrintOptions())).generate(ast)
    advanced = CodeGenerator(options=GeneratorOptions(advanced=FormattingConfig())).generate(ast)
    compact = CodeGenerator(
        options=GeneratorOptions(advanced=FormattingConfig(string_style=StringStyle.COMPACT))
    ).generate(ast)

    for output in (generated, pretty, advanced, compact):
        assert any(line.strip().startswith("$a") for line in output.splitlines())
        assert not any(line.strip().startswith('a = "x"') for line in output.splitlines())


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
                modifiers=[StringModifier.from_name_value("private")],
            ),
            RegexString("$r", regex="ab.*", modifiers=[StringModifier.from_name_value("nocase")]),
        ],
        condition=OfExpression("any", Identifier("them")),
    )

    out = gen.generate(YaraFile(rules=[rule]))

    assert 'author = "me"' in out
    assert "enabled = true" in out
    assert '$a = "hello" ascii' in out
    assert "$h = { 4D A? } private" in out
    assert "$r = /ab.*/ nocase" in out

    gen2 = CodeGenerator()
    gen2._write_meta_section([Meta("score", 7)])
    assert "score = 7" in gen2.buffer.getvalue()
    gen3 = CodeGenerator()
    with pytest.raises(TypeError, match="Rule meta must be a dictionary, list, or tuple"):
        gen3._write_meta_section("ignored")

    gen4 = CodeGenerator()
    gen4._write_strings_section([PlainString("$b", value="x")], has_condition=False)
    assert gen4.buffer.getvalue().endswith("\n")

    gen5 = CodeGenerator()
    gen5._write_condition_section(None)
    assert gen5.buffer.getvalue() == ""

    out_falsy = CodeGenerator().generate(
        YaraFile(rules=[Rule(name="falsy_condition", condition=_FalsyBooleanLiteral(False))])
    )
    assert "condition:" in out_falsy
    assert "false" in out_falsy


def test_codegen_generator_formats_string_backed_negated_hex_bytes() -> None:
    token = JsonSerializer()._deserialize_hex_token({"type": "HexNegatedByte", "value": "4d"})
    rule = Rule(
        name="negated_hex",
        strings=[HexString("$h", tokens=[token])],
        condition=StringIdentifier("$h"),
    )

    out = CodeGenerator().generate(YaraFile(rules=[rule]))

    assert "$h = { ~4D }" in out


@pytest.mark.parametrize(
    ("token", "message"),
    [
        (HexByte(True), "HexByte value must be a byte"),
        (HexByte(0x100), "HexByte value must be a byte"),
        (HexNegatedByte(True), "HexNegatedByte value must be a byte"),
        (HexNibble(high=True, value=True), "HexNibble value must be a nibble"),
        (HexNibble(high=False, value=0x10), "HexNibble value must be a nibble"),
        (HexJump(True, 1), "HexJump min_jump must be a non-negative integer"),
        (HexJump(2, 1), "HexJump min_jump cannot exceed max_jump"),
        (object(), "Unsupported hex token"),
    ],
)
def test_codegen_generator_rejects_invalid_direct_hex_tokens(token: object, message: str) -> None:
    rule = Rule(
        name="bad_hex",
        strings=[HexString("$h", tokens=[token])],
        condition=BooleanLiteral(True),
    )

    with pytest.raises(TypeError, match=message):
        CodeGenerator().generate(YaraFile(rules=[rule]))


def test_codegen_generators_reject_unsupported_hex_tokens() -> None:
    ast = YaraFile(
        rules=[
            Rule(
                name="bad_hex_token",
                strings=[HexString("$h", tokens=[HexByte(0x41), object(), HexByte(0x42)])],
                condition=StringIdentifier("$h"),
            )
        ]
    )

    with pytest.raises(TypeError, match="Unsupported hex token"):
        CodeGenerator().generate(ast)
    with pytest.raises(TypeError, match="Unsupported hex token"):
        CodeGenerator(options=GeneratorOptions(advanced=FormattingConfig())).generate(ast)
    with pytest.raises(TypeError, match="Unsupported hex token"):
        CodeGenerator(options=GeneratorOptions.comment_aware()).generate(ast)
    with pytest.raises(TypeError, match="Unsupported hex token"):
        CodeGenerator(options=GeneratorOptions(pretty=PrettyPrintOptions())).generate(ast)


def test_codegen_generator_rejects_invalid_direct_hex_alternative_scalar() -> None:
    with pytest.raises(TypeError, match="HexByte value must be a byte"):
        CodeGenerator().visit_hex_alternative(HexAlternative([True]))


@pytest.mark.parametrize(
    ("tokens", "message"),
    [
        ([], "Hex string must contain at least one token"),
        ([HexJump(0, 1), HexByte(0x41)], "HexJump cannot appear"),
        ([HexByte(0x41), HexJump(0, 1)], "HexJump cannot appear"),
        ([HexAlternative([])], "HexAlternative must contain at least one branch"),
        ([HexAlternative([[]])], "HexAlternative branches must not be empty"),
        (
            [HexByte(0x41), HexAlternative([[HexByte(0x42), HexJump(1, None), HexByte(0x43)]])],
            "Unbounded HexJump is not allowed inside hex alternatives",
        ),
    ],
)
def test_codegen_generator_rejects_invalid_hex_string_structure(
    tokens: list[object],
    message: str,
) -> None:
    rule = Rule(
        name="bad_hex_structure",
        strings=[HexString("$h", tokens=tokens)],
        condition=BooleanLiteral(True),
    )

    with pytest.raises(ValueError, match=message):
        CodeGenerator().generate(YaraFile(rules=[rule]))


def test_codegen_generator_allows_unbounded_hex_jump_between_tokens() -> None:
    rule = Rule(
        name="unbounded_jump",
        strings=[HexString("$h", tokens=[HexByte(0x41), HexJump(None, None), HexByte(0x42)])],
        condition=StringIdentifier("$h"),
    )

    out = CodeGenerator().generate(YaraFile(rules=[rule]))

    assert "$h = { 41 [-] 42 }" in out


def test_codegen_generator_regex_suffix_alias_modifiers_are_adjacent() -> None:
    gen = CodeGenerator()
    rule = Rule(
        name="regex_aliases",
        strings=[
            RegexString(
                "$r",
                regex="ab.*",
                modifiers=["i", "s", StringModifier.from_name_value("fullword")],
            ),
            RegexString(
                "$s",
                regex="cd.*",
                modifiers=[
                    StringModifier.from_name_value("dotall"),
                    StringModifier.from_name_value("fullword"),
                ],
            ),
        ],
        condition=BinaryExpression(StringIdentifier("$r"), "or", StringIdentifier("$s")),
    )

    out = gen.generate(YaraFile(rules=[rule]))

    assert "$r = /ab.*/is fullword" in out
    assert "$s = /cd.*/s fullword" in out
    assert "$r = /ab.*/ i" not in out


def test_codegen_generator_rejects_unsupported_regex_multiline_modifiers() -> None:
    gen = CodeGenerator()

    for modifiers in (["m"], [StringModifier.from_name_value("multiline")]):
        rule = Rule(
            name="regex_multiline",
            strings=[RegexString("$r", regex="^line", modifiers=modifiers)],
            condition=StringIdentifier("$r"),
        )

        with pytest.raises(ValueError, match="Unsupported regex modifier"):
            gen.generate(YaraFile(rules=[rule]))


@pytest.mark.parametrize(
    "rule",
    [
        Rule(
            name="regex_string_newline",
            strings=[RegexString("$r", regex="line\nbreak")],
            condition=StringIdentifier("$r"),
        ),
        Rule(
            name="regex_literal_newline",
            condition=RegexLiteral("line\nbreak"),
        ),
    ],
)
def test_codegen_generators_reject_regex_patterns_with_line_breaks(rule: Rule) -> None:
    ast = YaraFile(rules=[rule])
    message = "Regex pattern must not contain line breaks"

    with pytest.raises(ValueError, match=message):
        CodeGenerator().generate(ast)
    with pytest.raises(ValueError, match=message):
        CodeGenerator(options=GeneratorOptions(advanced=FormattingConfig())).generate(ast)
    with pytest.raises(ValueError, match=message):
        CodeGenerator(options=GeneratorOptions.comment_aware()).generate(ast)
    with pytest.raises(ValueError, match=message):
        CodeGenerator(options=GeneratorOptions(pretty=PrettyPrintOptions())).generate(ast)


@pytest.mark.parametrize(
    "rule",
    [
        Rule(
            name="regex_string_carriage_return",
            strings=[RegexString("$r", regex="line\rbreak")],
            condition=StringIdentifier("$r"),
        ),
        Rule(
            name="regex_literal_carriage_return",
            condition=StringOperatorExpression(
                StringLiteral("line\rbreak"),
                "matches",
                RegexLiteral("line\rbreak"),
            ),
        ),
    ],
)
def test_codegen_generators_escape_regex_carriage_returns(rule: Rule) -> None:
    ast = YaraFile(rules=[rule])

    for generator in [
        CodeGenerator(),
        CodeGenerator(options=GeneratorOptions(advanced=FormattingConfig())),
        CodeGenerator(options=GeneratorOptions.comment_aware()),
        CodeGenerator(options=GeneratorOptions(pretty=PrettyPrintOptions())),
    ]:
        out = generator.generate(ast)
        assert "/line\\rbreak/" in out
        assert "line\rbreak/" not in out


@pytest.mark.parametrize(
    "rule",
    [
        Rule(
            name="regex_string_nul",
            strings=[RegexString("$r", regex="nul\x00byte")],
            condition=StringIdentifier("$r"),
        ),
        Rule(
            name="regex_literal_nul",
            condition=RegexLiteral("nul\x00byte"),
        ),
    ],
)
def test_codegen_generators_reject_regex_patterns_with_nul_bytes(rule: Rule) -> None:
    ast = YaraFile(rules=[rule])
    message = "Regex pattern must not contain NUL bytes"

    with pytest.raises(ValueError, match=message):
        CodeGenerator().generate(ast)
    with pytest.raises(ValueError, match=message):
        CodeGenerator(options=GeneratorOptions(advanced=FormattingConfig())).generate(ast)
    with pytest.raises(ValueError, match=message):
        CodeGenerator(options=GeneratorOptions.comment_aware()).generate(ast)
    with pytest.raises(ValueError, match=message):
        CodeGenerator(options=GeneratorOptions(pretty=PrettyPrintOptions())).generate(ast)


@pytest.mark.parametrize(
    "rule",
    [
        Rule(
            name="regex_string_surrogate",
            strings=[RegexString("$r", regex="\ud800")],
            condition=StringIdentifier("$r"),
        ),
        Rule(
            name="regex_literal_surrogate",
            condition=RegexLiteral("\ud800"),
        ),
    ],
)
def test_codegen_generators_reject_regex_patterns_with_surrogates(rule: Rule) -> None:
    ast = YaraFile(rules=[rule])
    message = "Regex pattern must not contain Unicode surrogate code points"

    with pytest.raises(ValueError, match=message):
        CodeGenerator().generate(ast)
    with pytest.raises(ValueError, match=message):
        CodeGenerator(options=GeneratorOptions(advanced=FormattingConfig())).generate(ast)
    with pytest.raises(ValueError, match=message):
        CodeGenerator(options=GeneratorOptions.comment_aware()).generate(ast)
    with pytest.raises(ValueError, match=message):
        CodeGenerator(options=GeneratorOptions(pretty=PrettyPrintOptions())).generate(ast)


def test_codegen_generators_reject_plain_strings_with_surrogates() -> None:
    ast = YaraFile(
        rules=[
            Rule(
                name="plain_string_surrogate",
                strings=[PlainString("$a", value="\ud800")],
                condition=StringIdentifier("$a"),
            )
        ]
    )
    message = "String value must not contain Unicode surrogate code points"

    with pytest.raises(ValueError, match=message):
        CodeGenerator().generate(ast)
    with pytest.raises(ValueError, match=message):
        CodeGenerator(options=GeneratorOptions(advanced=FormattingConfig())).generate(ast)
    with pytest.raises(ValueError, match=message):
        CodeGenerator(options=GeneratorOptions.comment_aware()).generate(ast)
    with pytest.raises(ValueError, match=message):
        CodeGenerator(options=GeneratorOptions(pretty=PrettyPrintOptions())).generate(ast)


@pytest.mark.parametrize(
    "rule",
    [
        Rule(
            name="regex_string_empty",
            strings=[RegexString("$r", regex="")],
            condition=StringIdentifier("$r"),
        ),
        Rule(
            name="regex_literal_empty",
            condition=RegexLiteral(""),
        ),
    ],
)
def test_codegen_generators_reject_empty_regex_patterns(rule: Rule) -> None:
    ast = YaraFile(rules=[rule])
    message = "Regex pattern must not be empty"

    with pytest.raises(ValueError, match=message):
        CodeGenerator().generate(ast)
    with pytest.raises(ValueError, match=message):
        CodeGenerator(options=GeneratorOptions(advanced=FormattingConfig())).generate(ast)
    with pytest.raises(ValueError, match=message):
        CodeGenerator(options=GeneratorOptions.comment_aware()).generate(ast)
    with pytest.raises(ValueError, match=message):
        CodeGenerator(options=GeneratorOptions(pretty=PrettyPrintOptions())).generate(ast)


@pytest.mark.parametrize(
    "plain",
    [
        PlainString("$p", value=""),
        PlainString("$p", value=b""),
        PlainString("$p", value="placeholder", raw_bytes=b""),
    ],
)
def test_codegen_generators_reject_empty_plain_strings(plain: PlainString) -> None:
    ast = YaraFile(
        rules=[
            Rule(
                name="plain_string_empty",
                strings=[plain],
                condition=StringIdentifier("$p"),
            )
        ]
    )
    message = "Plain string value must not be empty"

    with pytest.raises(ValueError, match=message):
        CodeGenerator().generate(ast)
    with pytest.raises(ValueError, match=message):
        CodeGenerator(options=GeneratorOptions(advanced=FormattingConfig())).generate(ast)
    with pytest.raises(ValueError, match=message):
        CodeGenerator(options=GeneratorOptions.comment_aware()).generate(ast)
    with pytest.raises(ValueError, match=message):
        CodeGenerator(options=GeneratorOptions(pretty=PrettyPrintOptions())).generate(ast)


def test_codegen_generators_reject_invalid_plain_string_raw_bytes() -> None:
    plain = PlainString("$p", value="placeholder", raw_bytes=cast(Any, "placeholder"))
    ast = YaraFile(
        rules=[
            Rule(
                name="plain_string_invalid_raw_bytes",
                strings=[plain],
                condition=StringIdentifier("$p"),
            )
        ]
    )
    message = "Plain string raw_bytes must be bytes or None"

    with pytest.raises(TypeError, match=message):
        CodeGenerator().generate(ast)
    with pytest.raises(TypeError, match=message):
        CodeGenerator(options=GeneratorOptions(advanced=FormattingConfig())).generate(ast)
    with pytest.raises(TypeError, match=message):
        CodeGenerator(options=GeneratorOptions.comment_aware()).generate(ast)
    with pytest.raises(TypeError, match=message):
        CodeGenerator(options=GeneratorOptions(pretty=PrettyPrintOptions())).generate(ast)


@pytest.mark.parametrize(
    "pattern",
    [
        "[",
        "a**",
        "a{2,1}",
        "a{32768}",
        "(?=a)",
        r"\x",
    ],
)
def test_codegen_generators_reject_libyara_invalid_regex_patterns(pattern: str) -> None:
    rules = [
        Rule(
            name="regex_string_invalid",
            strings=[RegexString("$r", regex=pattern)],
            condition=StringIdentifier("$r"),
        ),
        Rule(
            name="regex_literal_invalid",
            condition=StringOperatorExpression(
                StringLiteral("abc"),
                "matches",
                RegexLiteral(pattern),
            ),
        ),
    ]

    for rule in rules:
        ast = YaraFile(rules=[rule])
        with pytest.raises(ValueError, match="Invalid regex pattern"):
            CodeGenerator().generate(ast)
        with pytest.raises(ValueError, match="Invalid regex pattern"):
            CodeGenerator(options=GeneratorOptions(advanced=FormattingConfig())).generate(ast)
        with pytest.raises(ValueError, match="Invalid regex pattern"):
            CodeGenerator(options=GeneratorOptions.comment_aware()).generate(ast)
        with pytest.raises(ValueError, match="Invalid regex pattern"):
            CodeGenerator(options=GeneratorOptions(pretty=PrettyPrintOptions())).generate(ast)


def test_codegen_generator_rejects_duplicate_regex_suffix_modifiers() -> None:
    gen = CodeGenerator()
    rule = Rule(
        name="regex_duplicate",
        strings=[RegexString("$r", regex="line", modifiers=["i", "i"])],
        condition=StringIdentifier("$r"),
    )

    with pytest.raises(ValueError, match="Duplicate regex modifier: i"):
        gen.generate(YaraFile(rules=[rule]))


def test_codegen_generator_canonicalizes_regex_suffix_modifier_order() -> None:
    rule = Rule(
        name="regex_order",
        strings=[RegexString("$r", regex="line", modifiers=["s", "i"])],
        condition=StringIdentifier("$r"),
    )

    assert "$r = /line/is" in CodeGenerator().generate(YaraFile(rules=[rule]))


def test_codegen_generator_rejects_unsupported_spaced_string_modifiers() -> None:
    gen = CodeGenerator()
    strings = [
        PlainString("$case", value="abc", modifiers=[StringModifier.from_name_value("case")]),
        PlainString("$utf", value="abc", modifiers=[StringModifier.from_name_value("utf16")]),
        PlainString("$raw", value="abc", modifiers=["i"]),
        PlainString("$dotall", value="abc", modifiers=[StringModifier.from_name_value("dotall")]),
        PlainString("$unknown", value="abc", modifiers=["unknown"]),
        RegexString("$regex", regex="abc", modifiers=[StringModifier.from_name_value("utf8")]),
    ]

    for string_def in strings:
        rule = Rule(
            name="bad_spaced_modifier",
            strings=[string_def],
            condition=StringIdentifier(string_def.identifier),
        )

        with pytest.raises(ValueError, match="Unsupported string modifier"):
            gen.generate(YaraFile(rules=[rule]))


def test_codegen_generator_rejects_invalid_string_modifier_applicability() -> None:
    gen = CodeGenerator()
    cases = [
        (
            PlainString(
                "$plain",
                value="abc",
                modifiers=[
                    StringModifier.from_name_value("nocase"),
                    StringModifier.from_name_value("base64"),
                ],
            ),
            "cannot be combined",
        ),
        (
            RegexString(
                "$regex",
                regex="abc",
                modifiers=[StringModifier.from_name_value("base64")],
            ),
            "not valid on regex strings",
        ),
        (
            HexString(
                "$hex",
                tokens=[HexByte(0x41)],
                modifiers=[StringModifier.from_name_value("wide")],
            ),
            "not valid on hex strings",
        ),
        (
            PlainString(
                "$plain_value",
                value="abc",
                modifiers=[StringModifier.from_name_value("wide", 1)],
            ),
            "does not accept a value",
        ),
        (
            RegexString(
                "$regex_value",
                regex="abc",
                modifiers=[StringModifier.from_name_value("dotall", 1)],
            ),
            "does not accept a value",
        ),
        (
            HexString(
                "$hex_value",
                tokens=[HexByte(0x41)],
                modifiers=[StringModifier.from_name_value("private", 1)],
            ),
            "does not accept a value",
        ),
    ]

    for string_def, message in cases:
        rule = Rule(
            name="bad_modifier_applicability",
            strings=[string_def],
            condition=StringIdentifier(string_def.identifier),
        )

        with pytest.raises(ValueError, match=message):
            gen.generate(YaraFile(rules=[rule]))

    bad_alphabet_rule = Rule(
        name="bad_base64_alphabet",
        strings=[
            PlainString(
                "$bad64",
                value="abc",
                modifiers=[StringModifier.from_name_value("base64", "short")],
            )
        ],
        condition=StringIdentifier("$bad64"),
    )

    with pytest.raises(TypeError, match="base64 alphabet must be 64 bytes"):
        gen.generate(YaraFile(rules=[bad_alphabet_rule]))


def test_codegen_generator_rejects_duplicate_string_modifiers() -> None:
    gen = CodeGenerator()
    cases = [
        PlainString(
            "$plain",
            value="abc",
            modifiers=[
                StringModifier.from_name_value("ascii"),
                StringModifier.from_name_value("ascii"),
            ],
        ),
        PlainString(
            "$xor",
            value="abc",
            modifiers=[
                StringModifier.from_name_value("xor"),
                StringModifier.from_name_value("xor", 1),
            ],
        ),
        HexString(
            "$hex",
            tokens=[HexByte(0x41)],
            modifiers=[
                StringModifier.from_name_value("private"),
                StringModifier.from_name_value("private"),
            ],
        ),
        RegexString(
            "$regex",
            regex="abc",
            modifiers=[
                StringModifier.from_name_value("nocase"),
                StringModifier.from_name_value("nocase"),
            ],
        ),
    ]

    for string_def in cases:
        rule = Rule(
            name="duplicate_modifiers",
            strings=[string_def],
            condition=StringIdentifier(string_def.identifier),
        )

        with pytest.raises(ValueError, match="Duplicate string modifier"):
            gen.generate(YaraFile(rules=[rule]))


def test_codegen_generator_rejects_non_sequence_string_modifiers() -> None:
    bad_plain_modifiers: Any = "wide"
    bad_hex_modifiers: Any = "private"
    bad_regex_modifiers: Any = "fullword"
    falsey_bad_modifiers: Any = False
    cases = [
        PlainString("$plain", value="abc", modifiers=bad_plain_modifiers),
        HexString("$hex", tokens=[HexByte(0x41)], modifiers=bad_hex_modifiers),
        RegexString("$regex", regex="abc", modifiers=bad_regex_modifiers),
        PlainString("$plain_false", value="abc", modifiers=falsey_bad_modifiers),
        HexString("$hex_false", tokens=[HexByte(0x41)], modifiers=falsey_bad_modifiers),
        RegexString("$regex_false", regex="abc", modifiers=falsey_bad_modifiers),
    ]

    for string_def in cases:
        rule = Rule(
            name="bad_string_modifiers",
            strings=[string_def],
            condition=BooleanLiteral(True),
        )
        with pytest.raises(TypeError, match="String modifiers must be a list or tuple"):
            CodeGenerator().generate(YaraFile(rules=[rule]))


def test_codegen_generators_reject_non_string_string_modifier_items() -> None:
    class AsWide:
        def __str__(self) -> str:
            return "wide"

    ast = YaraFile(
        rules=[
            Rule(
                name="bad_string_modifier_item",
                strings=[
                    PlainString(identifier="$a", value="x", modifiers=[AsWide()]),
                ],
                condition=BooleanLiteral(True),
            )
        ]
    )

    with pytest.raises(TypeError, match="String modifiers must contain strings or StringModifier"):
        CodeGenerator().generate(ast)
    with pytest.raises(TypeError, match="String modifiers must contain strings or StringModifier"):
        CodeGenerator(options=GeneratorOptions(advanced=FormattingConfig())).generate(ast)
    with pytest.raises(TypeError, match="String modifiers must contain strings or StringModifier"):
        CodeGenerator(options=GeneratorOptions.comment_aware()).generate(ast)
    with pytest.raises(TypeError, match="String modifiers must contain strings or StringModifier"):
        CodeGenerator(options=GeneratorOptions(pretty=PrettyPrintOptions())).generate(ast)


def test_codegen_generators_reject_unsupported_string_definitions() -> None:
    ast = YaraFile(
        rules=[
            Rule(
                name="unsupported_string",
                strings=[StringDefinition("$base")],
                condition=BooleanLiteral(True),
            )
        ]
    )

    with pytest.raises(TypeError, match="Unsupported string definition"):
        CodeGenerator().generate(ast)
    with pytest.raises(TypeError, match="Unsupported string definition"):
        CodeGenerator(options=GeneratorOptions(advanced=FormattingConfig())).generate(ast)
    with pytest.raises(TypeError, match="Unsupported string definition"):
        CodeGenerator(options=GeneratorOptions.comment_aware()).generate(ast)
    with pytest.raises(TypeError, match="Unsupported string definition"):
        CodeGenerator(options=GeneratorOptions(pretty=PrettyPrintOptions())).generate(ast)


@pytest.mark.parametrize("invalid_strings", [False, 0, "", None])
def test_codegen_generators_reject_invalid_rule_string_collections(
    invalid_strings: Any,
) -> None:
    ast = YaraFile(
        rules=[
            Rule(
                name="invalid_strings",
                strings=invalid_strings,
                condition=BooleanLiteral(True),
            )
        ]
    )

    with pytest.raises(TypeError, match="Rule strings must be a list or tuple"):
        CodeGenerator().generate(ast)
    with pytest.raises(TypeError, match="Rule strings must be a list or tuple"):
        CodeGenerator(options=GeneratorOptions(advanced=FormattingConfig())).generate(ast)
    with pytest.raises(TypeError, match="Rule strings must be a list or tuple"):
        CodeGenerator(options=GeneratorOptions.comment_aware()).generate(ast)
    with pytest.raises(TypeError, match="Rule strings must be a list or tuple"):
        CodeGenerator(options=GeneratorOptions(pretty=PrettyPrintOptions())).generate(ast)


@pytest.mark.parametrize(
    "field_name",
    [
        "imports",
        "includes",
        "rules",
        "extern_rules",
        "extern_imports",
        "pragmas",
        "namespaces",
    ],
)
@pytest.mark.parametrize("invalid_collection", [False, 0, "", None])
def test_codegen_generators_reject_invalid_yara_file_collections(
    field_name: str,
    invalid_collection: Any,
) -> None:
    ast = YaraFile(rules=[Rule(name="valid", condition=BooleanLiteral(True))])
    setattr(ast, field_name, invalid_collection)

    message = f"YaraFile {field_name} must be a list or tuple"
    with pytest.raises(TypeError, match=message):
        CodeGenerator().generate(ast)
    with pytest.raises(TypeError, match=message):
        CodeGenerator(options=GeneratorOptions(advanced=FormattingConfig())).generate(ast)
    with pytest.raises(TypeError, match=message):
        CodeGenerator(options=GeneratorOptions.comment_aware()).generate(ast)
    with pytest.raises(TypeError, match=message):
        CodeGenerator(options=GeneratorOptions(pretty=PrettyPrintOptions())).generate(ast)


@pytest.mark.parametrize(
    ("field_name", "message"),
    [
        ("tags", "Rule tags must be a list or tuple"),
        ("pragmas", "Rule pragmas must be a list or tuple"),
    ],
)
@pytest.mark.parametrize("invalid_collection", [False, 0, "", None])
def test_codegen_generators_reject_invalid_rule_collections(
    field_name: str,
    message: str,
    invalid_collection: Any,
) -> None:
    rule = Rule(name="invalid_rule_collection", condition=BooleanLiteral(True))
    setattr(rule, field_name, invalid_collection)
    ast = YaraFile(rules=[rule])

    with pytest.raises(TypeError, match=message):
        CodeGenerator().generate(ast)
    with pytest.raises(TypeError, match=message):
        CodeGenerator(options=GeneratorOptions(advanced=FormattingConfig())).generate(ast)
    with pytest.raises(TypeError, match=message):
        CodeGenerator(options=GeneratorOptions.comment_aware()).generate(ast)
    with pytest.raises(TypeError, match=message):
        CodeGenerator(options=GeneratorOptions(pretty=PrettyPrintOptions())).generate(ast)


@pytest.mark.parametrize("invalid_collection", [False, 0, "", None])
def test_codegen_generators_reject_invalid_leaf_collections(
    invalid_collection: Any,
) -> None:
    cases = [
        (
            ExternImport("mods.yar", rules=invalid_collection),
            "ExternImport rules must be a list or tuple",
        ),
        (
            ExternNamespace("corp", extern_rules=invalid_collection),
            "ExternNamespace extern_rules must be a list or tuple",
        ),
        (
            ExternRule("Remote", modifiers=invalid_collection),
            "ExternRule modifiers must be a list or tuple",
        ),
        (
            PragmaBlock(pragmas=invalid_collection),
            "PragmaBlock pragmas must be a list or tuple",
        ),
    ]

    for node, message in cases:
        with pytest.raises(TypeError, match=message):
            CodeGenerator().generate(node)
        with pytest.raises(TypeError, match=message):
            CodeGenerator(options=GeneratorOptions(advanced=FormattingConfig())).generate(node)
        with pytest.raises(TypeError, match=message):
            CodeGenerator(options=GeneratorOptions.comment_aware()).generate(node)
        with pytest.raises(TypeError, match=message):
            CodeGenerator(options=GeneratorOptions(pretty=PrettyPrintOptions())).generate(node)


@pytest.mark.parametrize("invalid_collection", [False, 0, "", None])
def test_codegen_generators_reject_invalid_expression_collections(
    invalid_collection: Any,
) -> None:
    cases = [
        (
            FunctionCall("foo", invalid_collection),
            "FunctionCall arguments must be a list or tuple",
        ),
        (
            SetExpression(invalid_collection),
            "SetExpression elements must be a list or tuple",
        ),
    ]

    for node, message in cases:
        with pytest.raises(TypeError, match=message):
            CodeGenerator().generate(node)
        with pytest.raises(TypeError, match=message):
            CodeGenerator(options=GeneratorOptions(advanced=FormattingConfig())).generate(node)
        with pytest.raises(TypeError, match=message):
            CodeGenerator(options=GeneratorOptions.comment_aware()).generate(node)
        with pytest.raises(TypeError, match=message):
            CodeGenerator(options=GeneratorOptions(pretty=PrettyPrintOptions())).generate(node)


@pytest.mark.parametrize("invalid_collection", [False, 0, "", None])
def test_yarax_codegen_generators_reject_invalid_collections(
    invalid_collection: Any,
) -> None:
    cases = [
        (
            WithStatement(invalid_collection, BooleanLiteral(True)),
            "WithStatement declarations must be a list or tuple",
        ),
        (
            TupleExpression(invalid_collection),
            "TupleExpression elements must be a list or tuple",
        ),
        (
            ListExpression(invalid_collection),
            "ListExpression elements must be a list or tuple",
        ),
        (
            DictExpression(invalid_collection),
            "DictExpression items must be a list or tuple",
        ),
        (
            LambdaExpression(invalid_collection, Identifier("x")),
            "LambdaExpression parameters must be a list or tuple",
        ),
        (
            PatternMatch(Identifier("x"), invalid_collection, default=StringLiteral("fallback")),
            "PatternMatch cases must be a list or tuple",
        ),
    ]

    for node, message in cases:
        with pytest.raises(TypeError, match=message):
            YaraXGenerator().generate(node)
        with pytest.raises(TypeError, match=message):
            CodeGenerator(options=GeneratorOptions(advanced=FormattingConfig())).generate(node)
        with pytest.raises(TypeError, match=message):
            CodeGenerator(options=GeneratorOptions.comment_aware()).generate(node)
        with pytest.raises(TypeError, match=message):
            CodeGenerator(options=GeneratorOptions(pretty=PrettyPrintOptions())).generate(node)


_BAD_PLAIN_STRING_VALUE: Any = 123
_BAD_REGEX_PATTERN: Any = 123


@pytest.mark.parametrize(
    ("string_def", "message"),
    [
        (
            PlainString("$plain", value=_BAD_PLAIN_STRING_VALUE),
            "Plain string value must be a string or bytes",
        ),
        (
            RegexString("$regex", regex=_BAD_REGEX_PATTERN),
            "Regex pattern must be a string",
        ),
    ],
)
def test_codegen_generators_reject_invalid_string_value_types(
    string_def: Any,
    message: str,
) -> None:
    ast = YaraFile(
        rules=[
            Rule(
                name="invalid_string_value",
                strings=[string_def],
                condition=BooleanLiteral(True),
            )
        ]
    )

    with pytest.raises(TypeError, match=message):
        CodeGenerator().generate(ast)
    with pytest.raises(TypeError, match=message):
        CodeGenerator(options=GeneratorOptions(advanced=FormattingConfig())).generate(ast)
    with pytest.raises(TypeError, match=message):
        CodeGenerator(options=GeneratorOptions.comment_aware()).generate(ast)
    with pytest.raises(TypeError, match=message):
        CodeGenerator(options=GeneratorOptions(pretty=PrettyPrintOptions())).generate(ast)


def test_codegen_generators_reject_duplicate_rule_tags() -> None:
    ast = YaraFile(
        rules=[
            Rule(
                name="duplicate_tags",
                tags=[Tag("tag"), Tag("tag")],
                condition=BooleanLiteral(True),
            )
        ]
    )

    with pytest.raises(ValueError, match="Duplicate tag identifier"):
        CodeGenerator().generate(ast)
    with pytest.raises(ValueError, match="Duplicate tag identifier"):
        CodeGenerator(options=GeneratorOptions(advanced=FormattingConfig())).generate(ast)
    with pytest.raises(ValueError, match="Duplicate tag identifier"):
        CodeGenerator(options=GeneratorOptions.comment_aware()).generate(ast)
    with pytest.raises(ValueError, match="Duplicate tag identifier"):
        CodeGenerator(options=GeneratorOptions(pretty=PrettyPrintOptions())).generate(ast)


@pytest.mark.parametrize("tag_name", ["bad-tag", "for"])
def test_codegen_generators_reject_invalid_rule_tags(tag_name: str) -> None:
    ast = YaraFile(
        rules=[
            Rule(
                name="invalid_tags",
                tags=[Tag(tag_name)],
                condition=BooleanLiteral(True),
            )
        ]
    )

    with pytest.raises(ValueError, match="Invalid tag identifier"):
        CodeGenerator().generate(ast)
    with pytest.raises(ValueError, match="Invalid tag identifier"):
        CodeGenerator(options=GeneratorOptions(advanced=FormattingConfig())).generate(ast)
    with pytest.raises(ValueError, match="Invalid tag identifier"):
        CodeGenerator(options=GeneratorOptions.comment_aware()).generate(ast)
    with pytest.raises(ValueError, match="Invalid tag identifier"):
        CodeGenerator(options=GeneratorOptions(pretty=PrettyPrintOptions())).generate(ast)


def test_codegen_generators_reject_non_string_rule_tags() -> None:
    ast = YaraFile(
        rules=[
            Rule(
                name="invalid_tags",
                tags=[cast(Any, True)],
                condition=BooleanLiteral(True),
            )
        ]
    )

    with pytest.raises(TypeError, match="Rule tags must contain strings or Tag nodes"):
        CodeGenerator().generate(ast)
    with pytest.raises(TypeError, match="Rule tags must contain strings or Tag nodes"):
        CodeGenerator(options=GeneratorOptions(advanced=FormattingConfig())).generate(ast)
    with pytest.raises(TypeError, match="Rule tags must contain strings or Tag nodes"):
        CodeGenerator(options=GeneratorOptions.comment_aware()).generate(ast)
    with pytest.raises(TypeError, match="Rule tags must contain strings or Tag nodes"):
        CodeGenerator(options=GeneratorOptions(pretty=PrettyPrintOptions())).generate(ast)


def test_codegen_generators_reject_expression_rule_tags() -> None:
    ast = YaraFile(
        rules=[
            Rule(
                name="invalid_tags",
                tags=[cast(Any, Identifier("not_a_tag"))],
                condition=BooleanLiteral(True),
            )
        ]
    )

    with pytest.raises(TypeError, match="Rule tags must contain strings or Tag nodes"):
        CodeGenerator().generate(ast)
    with pytest.raises(TypeError, match="Rule tags must contain strings or Tag nodes"):
        CodeGenerator(options=GeneratorOptions(advanced=FormattingConfig())).generate(ast)
    with pytest.raises(TypeError, match="Rule tags must contain strings or Tag nodes"):
        CodeGenerator(options=GeneratorOptions.comment_aware()).generate(ast)
    with pytest.raises(TypeError, match="Rule tags must contain strings or Tag nodes"):
        CodeGenerator(options=GeneratorOptions(pretty=PrettyPrintOptions())).generate(ast)


def test_codegen_generators_reject_invalid_rule_pragma_nodes() -> None:
    ast = YaraFile(
        rules=[
            Rule(
                name="invalid_pragmas",
                pragmas=[cast(Any, Identifier("not_a_pragma"))],
                condition=BooleanLiteral(True),
            )
        ]
    )

    with pytest.raises(TypeError, match="Rule pragmas must contain InRulePragma nodes"):
        CodeGenerator().generate(ast)
    with pytest.raises(TypeError, match="Rule pragmas must contain InRulePragma nodes"):
        CodeGenerator(options=GeneratorOptions(advanced=FormattingConfig())).generate(ast)
    with pytest.raises(TypeError, match="Rule pragmas must contain InRulePragma nodes"):
        CodeGenerator(options=GeneratorOptions.comment_aware()).generate(ast)
    with pytest.raises(TypeError, match="Rule pragmas must contain InRulePragma nodes"):
        CodeGenerator(options=GeneratorOptions(pretty=PrettyPrintOptions())).generate(ast)


def test_codegen_tag_visitors_reject_non_string_tag_names() -> None:
    tag = Tag(cast(Any, True))

    with pytest.raises(TypeError, match="Tag name must be a string"):
        CodeGenerator().generate(tag)
    with pytest.raises(TypeError, match="Tag name must be a string"):
        CodeGenerator(options=GeneratorOptions(advanced=FormattingConfig())).generate(tag)
    with pytest.raises(TypeError, match="Tag name must be a string"):
        CodeGenerator(options=GeneratorOptions.comment_aware()).generate(tag)
    with pytest.raises(TypeError, match="Tag name must be a string"):
        CodeGenerator(options=GeneratorOptions(pretty=PrettyPrintOptions())).generate(tag)


@pytest.mark.parametrize("tag_name", ["bad-tag", "for", "a" * (YARA_IDENTIFIER_MAX_LENGTH + 1)])
def test_codegen_tag_visitors_reject_invalid_rule_tags(tag_name: str) -> None:
    tag = Tag(tag_name)

    with pytest.raises(ValueError, match="Invalid tag identifier"):
        CodeGenerator().generate(tag)
    with pytest.raises(ValueError, match="Invalid tag identifier"):
        CodeGenerator(options=GeneratorOptions(advanced=FormattingConfig())).generate(tag)
    with pytest.raises(ValueError, match="Invalid tag identifier"):
        CodeGenerator(options=GeneratorOptions.comment_aware()).generate(tag)
    with pytest.raises(ValueError, match="Invalid tag identifier"):
        CodeGenerator(options=GeneratorOptions(pretty=PrettyPrintOptions())).generate(tag)


@pytest.mark.parametrize(
    ("node", "message"),
    [
        (Import("pe", alias="p"), "Import aliases are not supported"),
        (Import("pe", alias=""), "Import aliases are not supported"),
        (ExternImport("mods.yar", alias=""), "Invalid import alias identifier"),
        (ExternImport("mods.yar", alias="bad-alias"), "Invalid import alias identifier"),
        (ExternImport("mods.yar", rules=["bad-rule"]), "Invalid extern rule identifier"),
        (ExternNamespace("bad-ns"), "Invalid namespace identifier"),
        (ExternRule("bad-rule"), "Invalid extern rule identifier"),
        (ExternRule("Remote", namespace="bad-ns"), "Invalid namespace identifier"),
        (ExternRule("Remote", namespace=""), "Invalid namespace identifier"),
        (ExternRuleReference("bad-rule"), "Invalid extern rule identifier"),
        (
            ExternRuleReference("Remote", namespace="bad-ns"),
            "Invalid namespace identifier",
        ),
        (
            ExternRuleReference("Remote", namespace=""),
            "Invalid namespace identifier",
        ),
    ],
)
def test_codegen_generators_reject_invalid_top_level_reference_names(
    node: Any,
    message: str,
) -> None:
    with pytest.raises(ValueError, match=message):
        CodeGenerator().generate(node)
    with pytest.raises(ValueError, match=message):
        CodeGenerator(options=GeneratorOptions(advanced=FormattingConfig())).generate(node)
    with pytest.raises(ValueError, match=message):
        CodeGenerator(options=GeneratorOptions.comment_aware()).generate(node)
    with pytest.raises(ValueError, match=message):
        CodeGenerator(options=GeneratorOptions(pretty=PrettyPrintOptions())).generate(node)


@pytest.mark.parametrize(
    "node",
    [
        Import("pe", alias=cast(Any, False)),
        ExternImport("mods.yar", alias=cast(Any, False)),
    ],
)
def test_codegen_generators_reject_non_string_import_aliases(node: Any) -> None:
    with pytest.raises(TypeError, match="Import alias must be a string"):
        CodeGenerator().generate(node)
    with pytest.raises(TypeError, match="Import alias must be a string"):
        CodeGenerator(options=GeneratorOptions(advanced=FormattingConfig())).generate(node)
    with pytest.raises(TypeError, match="Import alias must be a string"):
        CodeGenerator(options=GeneratorOptions.comment_aware()).generate(node)
    with pytest.raises(TypeError, match="Import alias must be a string"):
        CodeGenerator(options=GeneratorOptions(pretty=PrettyPrintOptions())).generate(node)


@pytest.mark.parametrize(
    "node",
    [
        ExternRule("Remote", namespace=cast(Any, False)),
        ExternRuleReference("Remote", namespace=cast(Any, False)),
    ],
)
def test_codegen_generators_reject_non_string_optional_namespaces(node: Any) -> None:
    with pytest.raises(TypeError, match="Namespace must be a string"):
        CodeGenerator().generate(node)
    with pytest.raises(TypeError, match="Namespace must be a string"):
        CodeGenerator(options=GeneratorOptions(advanced=FormattingConfig())).generate(node)
    with pytest.raises(TypeError, match="Namespace must be a string"):
        CodeGenerator(options=GeneratorOptions.comment_aware()).generate(node)
    with pytest.raises(TypeError, match="Namespace must be a string"):
        CodeGenerator(options=GeneratorOptions(pretty=PrettyPrintOptions())).generate(node)


def test_codegen_generators_allow_qualified_extern_import_rule_names() -> None:
    node = ExternImport("mods.yar", alias="ext", rules=["legacy.LegacyRule"])
    expected = 'import "mods.yar" (legacy.LegacyRule) as ext'

    assert CodeGenerator().generate(node) == expected
    assert (
        CodeGenerator(options=GeneratorOptions(advanced=FormattingConfig())).generate(node)
        == expected
    )
    assert CodeGenerator(options=GeneratorOptions.comment_aware()).generate(node) == expected
    assert (
        CodeGenerator(options=GeneratorOptions(pretty=PrettyPrintOptions())).generate(node)
        == expected
    )


def test_codegen_generators_reject_duplicate_rule_identifiers() -> None:
    ast = YaraFile(
        rules=[
            Rule(name="duplicate", condition=BooleanLiteral(True)),
            Rule(name="duplicate", condition=BooleanLiteral(False)),
        ]
    )

    with pytest.raises(ValueError, match="Duplicate rule identifier"):
        CodeGenerator().generate(ast)
    with pytest.raises(ValueError, match="Duplicate rule identifier"):
        CodeGenerator(options=GeneratorOptions(advanced=FormattingConfig())).generate(ast)
    with pytest.raises(ValueError, match="Duplicate rule identifier"):
        CodeGenerator(options=GeneratorOptions.comment_aware()).generate(ast)
    with pytest.raises(ValueError, match="Duplicate rule identifier"):
        CodeGenerator(options=GeneratorOptions(pretty=PrettyPrintOptions())).generate(ast)


@pytest.mark.parametrize(
    "ast",
    [
        YaraFile(
            extern_rules=[
                ExternRule(name="duplicate"),
                ExternRule(name="duplicate"),
            ],
            rules=[Rule(name="r", condition=BooleanLiteral(True))],
        ),
        YaraFile(
            extern_rules=[ExternRule(name="duplicate")],
            rules=[Rule(name="duplicate", condition=BooleanLiteral(True))],
        ),
        YaraFile(
            extern_rules=[ExternRule(name="Nested", namespace="corp")],
            namespaces=[ExternNamespace(name="corp", extern_rules=[ExternRule(name="Nested")])],
            rules=[Rule(name="r", condition=BooleanLiteral(True))],
        ),
    ],
)
def test_codegen_generators_reject_conflicting_extern_rule_identifiers(ast: YaraFile) -> None:
    with pytest.raises(ValueError, match=r"Duplicate .*rule identifier"):
        CodeGenerator().generate(ast)
    with pytest.raises(ValueError, match=r"Duplicate .*rule identifier"):
        CodeGenerator(options=GeneratorOptions(advanced=FormattingConfig())).generate(ast)
    with pytest.raises(ValueError, match=r"Duplicate .*rule identifier"):
        CodeGenerator(options=GeneratorOptions.comment_aware()).generate(ast)
    with pytest.raises(ValueError, match=r"Duplicate .*rule identifier"):
        CodeGenerator(options=GeneratorOptions(pretty=PrettyPrintOptions())).generate(ast)


@pytest.mark.parametrize(
    "rule_name", ["bad name", "for", "1bad", "a" * (YARA_IDENTIFIER_MAX_LENGTH + 1)]
)
def test_codegen_generators_reject_invalid_rule_identifiers(rule_name: str) -> None:
    ast = YaraFile(rules=[Rule(name=rule_name, condition=BooleanLiteral(True))])

    with pytest.raises(ValueError, match="Invalid rule identifier"):
        CodeGenerator().generate(ast)
    with pytest.raises(ValueError, match="Invalid rule identifier"):
        CodeGenerator(options=GeneratorOptions(advanced=FormattingConfig())).generate(ast)
    with pytest.raises(ValueError, match="Invalid rule identifier"):
        CodeGenerator(options=GeneratorOptions.comment_aware()).generate(ast)
    with pytest.raises(ValueError, match="Invalid rule identifier"):
        CodeGenerator(options=GeneratorOptions(pretty=PrettyPrintOptions())).generate(ast)


def test_codegen_generators_reject_non_string_rule_identifiers() -> None:
    invalid_name: Any = False
    ast = YaraFile(rules=[Rule(name=invalid_name, condition=BooleanLiteral(True))])

    with pytest.raises(TypeError, match="Rule identifier must be a string"):
        CodeGenerator().generate(ast)
    with pytest.raises(TypeError, match="Rule identifier must be a string"):
        CodeGenerator(options=GeneratorOptions(advanced=FormattingConfig())).generate(ast)
    with pytest.raises(TypeError, match="Rule identifier must be a string"):
        CodeGenerator(options=GeneratorOptions.comment_aware()).generate(ast)
    with pytest.raises(TypeError, match="Rule identifier must be a string"):
        CodeGenerator(options=GeneratorOptions(pretty=PrettyPrintOptions())).generate(ast)


@pytest.mark.parametrize(
    "rule_name", ["bad-name", "for", "1bad", "a" * (YARA_IDENTIFIER_MAX_LENGTH + 1)]
)
def test_codegen_rule_visitors_reject_invalid_rule_identifiers(rule_name: str) -> None:
    rule = Rule(name=rule_name, condition=BooleanLiteral(True))

    with pytest.raises(ValueError, match="Invalid rule identifier"):
        CodeGenerator().generate(rule)
    with pytest.raises(ValueError, match="Invalid rule identifier"):
        CodeGenerator(options=GeneratorOptions(advanced=FormattingConfig())).generate(rule)
    with pytest.raises(ValueError, match="Invalid rule identifier"):
        CodeGenerator(options=GeneratorOptions.comment_aware()).generate(rule)
    with pytest.raises(ValueError, match="Invalid rule identifier"):
        CodeGenerator(options=GeneratorOptions(pretty=PrettyPrintOptions())).visit_rule(rule)


def test_codegen_rule_visitors_reject_non_string_rule_identifiers() -> None:
    invalid_name: Any = False
    rule = Rule(name=invalid_name, condition=BooleanLiteral(True))

    with pytest.raises(TypeError, match="Rule identifier must be a string"):
        CodeGenerator().generate(rule)
    with pytest.raises(TypeError, match="Rule identifier must be a string"):
        CodeGenerator(options=GeneratorOptions(advanced=FormattingConfig())).generate(rule)
    with pytest.raises(TypeError, match="Rule identifier must be a string"):
        CodeGenerator(options=GeneratorOptions.comment_aware()).generate(rule)
    with pytest.raises(TypeError, match="Rule identifier must be a string"):
        CodeGenerator(options=GeneratorOptions(pretty=PrettyPrintOptions())).visit_rule(rule)


def test_codegen_generators_reject_invalid_rule_modifiers() -> None:
    ast = YaraFile(
        rules=[Rule(name="invalid_modifier", modifiers=["foo"], condition=BooleanLiteral(True))]
    )

    with pytest.raises(ValueError, match="Invalid rule modifier"):
        CodeGenerator().generate(ast)
    with pytest.raises(ValueError, match="Invalid rule modifier"):
        CodeGenerator(options=GeneratorOptions(advanced=FormattingConfig())).generate(ast)
    with pytest.raises(ValueError, match="Invalid rule modifier"):
        CodeGenerator(options=GeneratorOptions.comment_aware()).generate(ast)
    with pytest.raises(ValueError, match="Invalid rule modifier"):
        CodeGenerator(options=GeneratorOptions(pretty=PrettyPrintOptions())).generate(ast)


@pytest.mark.parametrize(
    "rule",
    [
        Rule(name="false_modifier", modifiers=cast(Any, False), condition=BooleanLiteral(True)),
        Rule.from_raw(
            name="false_raw_modifier",
            modifiers=cast(Any, False),
            condition=BooleanLiteral(True),
        ),
    ],
)
def test_codegen_generators_reject_non_string_boolean_rule_modifiers(rule: Rule) -> None:
    ast = YaraFile(rules=[rule])

    with pytest.raises(TypeError, match="Rule modifiers must contain strings or RuleModifier"):
        CodeGenerator().generate(ast)
    with pytest.raises(TypeError, match="Rule modifiers must contain strings or RuleModifier"):
        CodeGenerator(options=GeneratorOptions(advanced=FormattingConfig())).generate(ast)
    with pytest.raises(TypeError, match="Rule modifiers must contain strings or RuleModifier"):
        CodeGenerator(options=GeneratorOptions.comment_aware()).generate(ast)
    with pytest.raises(TypeError, match="Rule modifiers must contain strings or RuleModifier"):
        CodeGenerator(options=GeneratorOptions(pretty=PrettyPrintOptions())).generate(ast)


def test_codegen_generators_reject_non_string_rule_modifiers() -> None:
    class AsPrivate:
        def __str__(self) -> str:
            return "private"

    ast = YaraFile(
        rules=[
            Rule(
                name="invalid_modifier",
                modifiers=[AsPrivate()],
                condition=BooleanLiteral(True),
            )
        ]
    )

    with pytest.raises(TypeError, match="Rule modifiers must contain strings or RuleModifier"):
        CodeGenerator().generate(ast)
    with pytest.raises(TypeError, match="Rule modifiers must contain strings or RuleModifier"):
        CodeGenerator(options=GeneratorOptions(advanced=FormattingConfig())).generate(ast)
    with pytest.raises(TypeError, match="Rule modifiers must contain strings or RuleModifier"):
        CodeGenerator(options=GeneratorOptions.comment_aware()).generate(ast)
    with pytest.raises(TypeError, match="Rule modifiers must contain strings or RuleModifier"):
        CodeGenerator(options=GeneratorOptions(pretty=PrettyPrintOptions())).generate(ast)


@pytest.mark.parametrize(
    "meta_key", ["bad-key", "for", "1bad", "a" * (YARA_IDENTIFIER_MAX_LENGTH + 1)]
)
def test_codegen_generators_reject_invalid_meta_keys(meta_key: str) -> None:
    ast = YaraFile(
        rules=[
            Rule(
                name="invalid_meta",
                meta=[Meta(meta_key, "x")],
                condition=BooleanLiteral(True),
            )
        ]
    )

    with pytest.raises(ValueError, match="Invalid meta identifier"):
        CodeGenerator().generate(ast)
    with pytest.raises(ValueError, match="Invalid meta identifier"):
        CodeGenerator(options=GeneratorOptions(advanced=FormattingConfig())).generate(ast)
    with pytest.raises(ValueError, match="Invalid meta identifier"):
        CodeGenerator(options=GeneratorOptions.comment_aware()).generate(ast)
    with pytest.raises(ValueError, match="Invalid meta identifier"):
        CodeGenerator(options=GeneratorOptions(pretty=PrettyPrintOptions())).generate(ast)


def test_codegen_generators_reject_invalid_rule_meta_collections() -> None:
    false_meta: Any = False
    cases = [
        Rule(name="invalid_meta_container", meta=false_meta, condition=BooleanLiteral(True)),
        Rule.from_raw(
            name="invalid_raw_meta_container",
            meta=false_meta,
            condition=BooleanLiteral(True),
        ),
        Rule(name="invalid_meta_item", meta=[false_meta], condition=BooleanLiteral(True)),
    ]

    for rule in cases:
        ast = YaraFile(rules=[rule])
        with pytest.raises(TypeError, match="Rule meta must contain meta entries"):
            CodeGenerator().generate(ast)
        with pytest.raises(TypeError, match="Rule meta must contain meta entries"):
            CodeGenerator(options=GeneratorOptions(advanced=FormattingConfig())).generate(ast)
        with pytest.raises(TypeError, match="Rule meta must contain meta entries"):
            CodeGenerator(options=GeneratorOptions.comment_aware()).generate(ast)
        with pytest.raises(TypeError, match="Rule meta must contain meta entries"):
            CodeGenerator(options=GeneratorOptions(pretty=PrettyPrintOptions())).generate(ast)


@pytest.mark.parametrize("invalid_meta", [False, 0])
def test_codegen_generators_reject_mutated_invalid_rule_meta_collections(
    invalid_meta: Any,
) -> None:
    rule = Rule(name="invalid_mutated_meta", condition=BooleanLiteral(True))
    rule.meta = invalid_meta
    ast = YaraFile(rules=[rule])

    with pytest.raises(TypeError, match="Rule meta must be a dictionary, list, or tuple"):
        CodeGenerator().generate(ast)
    with pytest.raises(TypeError, match="Rule meta must be a dictionary, list, or tuple"):
        CodeGenerator(options=GeneratorOptions(advanced=FormattingConfig())).generate(ast)
    with pytest.raises(TypeError, match="Rule meta must be a dictionary, list, or tuple"):
        CodeGenerator(options=GeneratorOptions.comment_aware()).generate(ast)
    with pytest.raises(TypeError, match="Rule meta must be a dictionary, list, or tuple"):
        CodeGenerator(options=GeneratorOptions(pretty=PrettyPrintOptions())).generate(ast)


def test_codegen_generators_allow_mutated_none_rule_meta_collection() -> None:
    rule = Rule(name="none_mutated_meta", condition=BooleanLiteral(True))
    rule.meta = None
    ast = YaraFile(rules=[rule])

    for output in (
        CodeGenerator().generate(ast),
        CodeGenerator(options=GeneratorOptions(advanced=FormattingConfig())).generate(ast),
        CodeGenerator(options=GeneratorOptions.comment_aware()).generate(ast),
        CodeGenerator(options=GeneratorOptions(pretty=PrettyPrintOptions())).generate(ast),
    ):
        assert "meta:" not in output
        assert "condition:" in output


def test_codegen_rejects_hex_jumps_above_libyara_limit() -> None:
    rule = Rule(
        name="large_jump",
        strings=[
            HexString(
                "$a",
                tokens=[
                    HexByte(0xAA),
                    HexJump(LIBYARA_HEX_JUMP_MAX + 1, LIBYARA_HEX_JUMP_MAX + 1),
                    HexByte(0xBB),
                ],
            )
        ],
        condition=BooleanLiteral(True),
    )
    ast = YaraFile(rules=[rule])

    with pytest.raises(ValueError, match="must not exceed"):
        CodeGenerator().generate(ast)
    with pytest.raises(ValueError, match="must not exceed"):
        CodeGenerator(options=GeneratorOptions(advanced=FormattingConfig())).generate(ast)
    with pytest.raises(ValueError, match="must not exceed"):
        CodeGenerator(options=GeneratorOptions.comment_aware()).generate(ast)
    with pytest.raises(ValueError, match="must not exceed"):
        CodeGenerator(options=GeneratorOptions(pretty=PrettyPrintOptions())).generate(ast)


@pytest.mark.parametrize("meta_value", [1.5, None, ["x"]])
def test_codegen_generators_reject_invalid_meta_values(meta_value: Any) -> None:
    ast = YaraFile(
        rules=[
            Rule(
                name="invalid_meta_value",
                meta=[Meta("bad", meta_value)],
                condition=BooleanLiteral(True),
            )
        ]
    )

    with pytest.raises(TypeError, match="Invalid meta value"):
        CodeGenerator().generate(ast)
    with pytest.raises(TypeError, match="Invalid meta value"):
        CodeGenerator(options=GeneratorOptions(advanced=FormattingConfig())).generate(ast)
    with pytest.raises(TypeError, match="Invalid meta value"):
        CodeGenerator(options=GeneratorOptions.comment_aware()).generate(ast)
    with pytest.raises(TypeError, match="Invalid meta value"):
        CodeGenerator(options=GeneratorOptions(pretty=PrettyPrintOptions())).generate(ast)


@pytest.mark.parametrize("meta_value", [2**63, -(2**63)])
def test_codegen_generators_reject_out_of_range_meta_integers(meta_value: int) -> None:
    ast = YaraFile(
        rules=[
            Rule(
                name="invalid_meta_integer",
                meta=[Meta("bad", meta_value)],
                condition=BooleanLiteral(True),
            )
        ]
    )

    with pytest.raises(ValueError, match="Integer literal value is outside libyara range"):
        CodeGenerator().generate(ast)
    with pytest.raises(ValueError, match="Integer literal value is outside libyara range"):
        CodeGenerator(options=GeneratorOptions(advanced=FormattingConfig())).generate(ast)
    with pytest.raises(ValueError, match="Integer literal value is outside libyara range"):
        CodeGenerator(options=GeneratorOptions.comment_aware()).generate(ast)
    with pytest.raises(ValueError, match="Integer literal value is outside libyara range"):
        CodeGenerator(options=GeneratorOptions(pretty=PrettyPrintOptions())).generate(ast)


def test_codegen_generator_renders_int64_min_condition_as_expression() -> None:
    ast = YaraFile(
        rules=[
            Rule(
                name="int64_min_condition",
                condition=IntegerLiteral(INT64_MIN),
            )
        ]
    )

    assert (
        CodeGenerator().generate(ast) == "rule int64_min_condition {\n"
        "    condition:\n"
        "        (-9223372036854775807 - 1)\n"
        "}\n"
    )


def test_codegen_generators_escape_quoted_meta_string_values() -> None:
    ast = YaraFile(
        rules=[
            Rule(
                name="quoted_meta",
                meta=[Meta("m", '"a" b"')],
                condition=BooleanLiteral(True),
            )
        ]
    )
    expected_literal = '"\\"a\\" b\\""'

    outputs = [
        CodeGenerator().generate(ast),
        CodeGenerator(options=GeneratorOptions(advanced=FormattingConfig())).generate(ast),
        CodeGenerator(options=GeneratorOptions.comment_aware()).generate(ast),
        CodeGenerator(options=GeneratorOptions(pretty=PrettyPrintOptions())).generate(ast),
    ]

    for output in outputs:
        assert any(
            line.strip().startswith("m =") and expected_literal in line
            for line in output.splitlines()
        )


def test_codegen_generators_reject_duplicate_string_identifiers() -> None:
    ast = YaraFile(
        rules=[
            Rule(
                name="duplicate_strings",
                strings=[
                    PlainString(identifier="$a", value="x"),
                    PlainString(identifier="$a", value="y"),
                ],
                condition=StringIdentifier("$a"),
            )
        ]
    )

    with pytest.raises(ValueError, match="Duplicate string identifier"):
        CodeGenerator().generate(ast)
    with pytest.raises(ValueError, match="Duplicate string identifier"):
        CodeGenerator(options=GeneratorOptions(advanced=FormattingConfig())).generate(ast)
    with pytest.raises(ValueError, match="Duplicate string identifier"):
        CodeGenerator(options=GeneratorOptions.comment_aware()).generate(ast)
    with pytest.raises(ValueError, match="Duplicate string identifier"):
        CodeGenerator(options=GeneratorOptions(pretty=PrettyPrintOptions())).generate(ast)


def test_codegen_generators_reject_invalid_string_identifiers() -> None:
    ast = YaraFile(
        rules=[
            Rule(
                name="invalid_string_identifier",
                strings=[PlainString(identifier="$bad-key", value="x")],
                condition=StringIdentifier("$bad-key"),
            )
        ]
    )

    with pytest.raises(ValueError, match="Invalid string identifier"):
        CodeGenerator().generate(ast)
    with pytest.raises(ValueError, match="Invalid string identifier"):
        CodeGenerator(options=GeneratorOptions(advanced=FormattingConfig())).generate(ast)
    with pytest.raises(ValueError, match="Invalid string identifier"):
        CodeGenerator(options=GeneratorOptions.comment_aware()).generate(ast)
    with pytest.raises(ValueError, match="Invalid string identifier"):
        CodeGenerator(options=GeneratorOptions(pretty=PrettyPrintOptions())).generate(ast)


@pytest.mark.parametrize(
    "string_def",
    [
        PlainString(identifier="$bad-key", value="x"),
        HexString(identifier="$bad-key", tokens=[HexByte(0x41)]),
        RegexString(identifier="$bad-key", regex="x"),
    ],
)
def test_codegen_string_visitors_reject_invalid_string_identifiers(
    string_def: Any,
) -> None:
    with pytest.raises(ValueError, match="Invalid string identifier"):
        CodeGenerator().generate(string_def)
    with pytest.raises(ValueError, match="Invalid string identifier"):
        CodeGenerator(options=GeneratorOptions(advanced=FormattingConfig())).generate(string_def)
    with pytest.raises(ValueError, match="Invalid string identifier"):
        CodeGenerator(options=GeneratorOptions.comment_aware()).generate(string_def)
    with pytest.raises(ValueError, match="Invalid string identifier"):
        CodeGenerator(options=GeneratorOptions(pretty=PrettyPrintOptions())).generate(string_def)


@pytest.mark.parametrize(
    "string_def",
    [
        PlainString(identifier=cast(Any, True), value="x"),
        HexString(identifier=cast(Any, True), tokens=[HexByte(0x41)]),
        RegexString(identifier=cast(Any, True), regex="x"),
    ],
)
def test_codegen_string_visitors_reject_non_string_string_identifiers(
    string_def: Any,
) -> None:
    with pytest.raises(TypeError, match="String identifier must be a string"):
        CodeGenerator().generate(string_def)
    with pytest.raises(TypeError, match="String identifier must be a string"):
        CodeGenerator(options=GeneratorOptions(advanced=FormattingConfig())).generate(string_def)
    with pytest.raises(TypeError, match="String identifier must be a string"):
        CodeGenerator(options=GeneratorOptions.comment_aware()).generate(string_def)
    with pytest.raises(TypeError, match="String identifier must be a string"):
        CodeGenerator(options=GeneratorOptions(pretty=PrettyPrintOptions())).generate(string_def)


@pytest.mark.parametrize(
    ("condition", "message"),
    [
        (Identifier("bad-key"), "Invalid identifier"),
        (Identifier("for"), "Invalid identifier"),
        (Identifier("as"), "Invalid identifier"),
        (Identifier("include"), "Invalid identifier"),
        (Identifier("all"), "Invalid identifier"),
        (Identifier("any"), "Invalid identifier"),
        (Identifier("none"), "Invalid identifier"),
        (Identifier("$bad-key"), "String references must use StringIdentifier"),
        (
            ForExpression(
                "any", "bad-name", SetExpression([IntegerLiteral(1)]), BooleanLiteral(True)
            ),
            "Invalid loop variable identifier",
        ),
    ],
)
def test_codegen_generators_reject_invalid_identifier_expressions(
    condition: Any,
    message: str,
) -> None:
    ast = YaraFile(rules=[Rule(name="invalid_identifier", condition=condition)])

    with pytest.raises(ValueError, match=message):
        CodeGenerator().generate(ast)
    with pytest.raises(ValueError, match=message):
        CodeGenerator(options=GeneratorOptions(advanced=FormattingConfig())).generate(ast)
    with pytest.raises(ValueError, match=message):
        CodeGenerator(options=GeneratorOptions.comment_aware()).generate(ast)
    with pytest.raises(ValueError, match=message):
        CodeGenerator(options=GeneratorOptions(pretty=PrettyPrintOptions())).generate(ast)


def test_codegen_rejects_unreferenced_strings_with_contextual_keyword_loop_variable() -> None:
    ast = YaraFile(
        rules=[
            Rule(
                name="contextual_loop",
                strings=[PlainString(identifier="$a", value="a")],
                condition=ForExpression(
                    "any",
                    "as",
                    SetExpression([IntegerLiteral(1)]),
                    BinaryExpression(Identifier("as"), ">", IntegerLiteral(0)),
                ),
            )
        ]
    )

    with pytest.raises(ValueError, match=r"Unreferenced string definitions.*\$a"):
        CodeGenerator().generate(ast)


@pytest.mark.parametrize(
    ("condition", "expected"),
    [
        (Identifier("filesize"), "filesize"),
        (Identifier("entrypoint"), "entrypoint"),
        (Identifier("true"), "true"),
        (Identifier("false"), "false"),
        (OfExpression(Identifier("any"), Identifier("them")), "any of them"),
        (OfExpression(Identifier("none"), Identifier("them")), "none of them"),
    ],
)
def test_codegen_generators_allow_valid_identifier_expressions(
    condition: Any,
    expected: str,
) -> None:
    strings: list[StringDefinition] = (
        [PlainString(identifier="$a", value="x")] if "of them" in expected else []
    )
    ast = YaraFile(rules=[Rule(name="valid_identifier", strings=strings, condition=condition)])

    assert expected in CodeGenerator().generate(ast)
    assert expected in CodeGenerator(
        options=GeneratorOptions(advanced=FormattingConfig())
    ).generate(ast)
    assert expected in CodeGenerator(options=GeneratorOptions.comment_aware()).generate(ast)
    assert expected in CodeGenerator(
        options=GeneratorOptions(pretty=PrettyPrintOptions())
    ).generate(ast)


@pytest.mark.parametrize(
    ("condition", "expected"),
    [
        ("$", "for any of them : ($)"),
        ("# > 0", "for any of them : (# > 0)"),
        ("@ > 0", "for any of them : (@ > 0)"),
        ("! > 0", "for any of them : (! > 0)"),
        ("$ at 0", "for any of them : ($ at 0)"),
        ("$ in (0..10)", "for any of them : ($ in (0..10))"),
    ],
)
def test_codegen_generators_allow_for_of_placeholder_references(
    condition: str,
    expected: str,
) -> None:
    ast = Parser(
        f'rule placeholder {{ strings: $a = "abc" condition: for any of them : ( {condition} ) }}'
    ).parse()

    assert expected in CodeGenerator().generate(ast)
    assert expected in CodeGenerator(
        options=GeneratorOptions(advanced=FormattingConfig())
    ).generate(ast)
    assert expected in CodeGenerator(options=GeneratorOptions.comment_aware()).generate(ast)
    assert expected in CodeGenerator(
        options=GeneratorOptions(pretty=PrettyPrintOptions())
    ).generate(ast)


@pytest.mark.parametrize(
    "condition",
    [
        StringIdentifier("$bad-key"),
        AtExpression("$bad-key", IntegerLiteral(0)),
        BinaryExpression(StringCount("bad-key"), ">", IntegerLiteral(0)),
        InExpression("$bad-key", RangeExpression(IntegerLiteral(0), IntegerLiteral(1))),
        OfExpression("any", "$bad-key"),
        OfExpression("any", ["$bad-key"]),
        OfExpression("any", StringLiteral("$bad-key")),
        OfExpression("any", Identifier("bad-key")),
        OfExpression("any", SetExpression([StringLiteral("$bad-key")])),
        OfExpression("any", StringWildcard("$bad-key*")),
        BinaryExpression(StringCount("#a"), ">", IntegerLiteral(0)),
        BinaryExpression(StringOffset("@a"), ">=", IntegerLiteral(0)),
        BinaryExpression(StringLength("!a"), ">", IntegerLiteral(0)),
        BinaryExpression(StringOffset("bad-key"), ">=", IntegerLiteral(0)),
        BinaryExpression(StringLength("bad-key"), ">", IntegerLiteral(0)),
    ],
)
def test_codegen_generators_reject_invalid_string_references(condition: Condition) -> None:
    ast = YaraFile(rules=[Rule(name="invalid_string_reference", condition=condition)])

    with pytest.raises(ValueError, match="Invalid string"):
        CodeGenerator().generate(ast)
    with pytest.raises(ValueError, match="Invalid string"):
        CodeGenerator(options=GeneratorOptions(advanced=FormattingConfig())).generate(ast)
    with pytest.raises(ValueError, match="Invalid string"):
        CodeGenerator(options=GeneratorOptions.comment_aware()).generate(ast)
    with pytest.raises(ValueError, match="Invalid string"):
        CodeGenerator(options=GeneratorOptions(pretty=PrettyPrintOptions())).generate(ast)


@pytest.mark.parametrize(
    "string_set",
    [
        StringLiteral(cast(Any, False)),
        SetExpression([StringLiteral(cast(Any, False))]),
        Identifier(cast(Any, False)),
        SetExpression([Identifier(cast(Any, False))]),
        StringWildcard(cast(Any, False)),
        SetExpression([StringWildcard(cast(Any, False))]),
    ],
)
def test_codegen_generators_reject_non_string_string_set_fields(string_set: Any) -> None:
    ast = YaraFile(
        rules=[Rule(name="invalid_string_set_field", condition=OfExpression("any", string_set))]
    )

    with pytest.raises(TypeError, match="must be a string"):
        CodeGenerator().generate(ast)
    with pytest.raises(TypeError, match="must be a string"):
        CodeGenerator(options=GeneratorOptions(advanced=FormattingConfig())).generate(ast)
    with pytest.raises(TypeError, match="must be a string"):
        CodeGenerator(options=GeneratorOptions.comment_aware()).generate(ast)
    with pytest.raises(TypeError, match="must be a string"):
        CodeGenerator(options=GeneratorOptions(pretty=PrettyPrintOptions())).generate(ast)


@pytest.mark.parametrize(
    "condition",
    [
        OfExpression("any", []),
        OfExpression(0, ()),
        OfExpression("any", frozenset()),
        ForOfExpression("any", [], BooleanLiteral(True)),
        ForOfExpression("any", (), None),
        ForOfExpression("any", frozenset(), None),
    ],
)
def test_codegen_generators_reject_empty_string_sets(condition: Condition) -> None:
    ast = YaraFile(rules=[Rule(name="empty_string_set", condition=condition)])

    with pytest.raises(ValueError, match="String set must contain at least one item"):
        CodeGenerator().generate(ast)
    with pytest.raises(ValueError, match="String set must contain at least one item"):
        CodeGenerator(options=GeneratorOptions(advanced=FormattingConfig())).generate(ast)
    with pytest.raises(ValueError, match="String set must contain at least one item"):
        CodeGenerator(options=GeneratorOptions.comment_aware()).generate(ast)
    with pytest.raises(ValueError, match="String set must contain at least one item"):
        CodeGenerator(options=GeneratorOptions(pretty=PrettyPrintOptions())).generate(ast)


@pytest.mark.parametrize(
    "condition",
    [
        OfExpression("any", SetExpression([])),
        ForOfExpression("any", SetExpression([]), BooleanLiteral(True)),
    ],
)
def test_codegen_generators_reject_empty_set_expression_string_sets(
    condition: Condition,
) -> None:
    with pytest.raises(ValueError, match="String set must contain at least one item"):
        CodeGenerator().generate(condition)
    with pytest.raises(ValueError, match="String set must contain at least one item"):
        CodeGenerator(options=GeneratorOptions(advanced=FormattingConfig())).generate(condition)
    with pytest.raises(ValueError, match="String set must contain at least one item"):
        CodeGenerator(options=GeneratorOptions.comment_aware()).generate(condition)
    with pytest.raises(ValueError, match="String set must contain at least one item"):
        CodeGenerator(options=GeneratorOptions(pretty=PrettyPrintOptions())).generate(condition)


@pytest.mark.parametrize(
    ("string_set", "expected"),
    [
        ("$a", "any of ($a)"),
        ("a", "any of ($a)"),
        ("$a*", "any of ($a*)"),
        (StringLiteral("$a"), "any of ($a)"),
        (StringLiteral("a*"), "any of ($a*)"),
        (StringIdentifier("$a"), "any of ($a)"),
        (Identifier("$a"), "any of ($a)"),
        (Identifier("a"), "any of (a)"),
        (Identifier("them"), "any of them"),
    ],
)
def test_codegen_generators_parenthesize_single_string_set_items(
    string_set: Any,
    expected: str,
) -> None:
    ast = YaraFile(
        rules=[
            Rule(
                name="single_string_set",
                strings=(
                    [] if expected == "any of (a)" else [PlainString(identifier="a", value="x")]
                ),
                condition=OfExpression("any", string_set),
            )
        ]
    )

    assert expected in CodeGenerator().generate(ast)
    assert expected in CodeGenerator(
        options=GeneratorOptions(advanced=FormattingConfig())
    ).generate(ast)
    assert expected in CodeGenerator(options=GeneratorOptions.comment_aware()).generate(ast)
    assert expected in CodeGenerator(
        options=GeneratorOptions(pretty=PrettyPrintOptions())
    ).generate(ast)


@pytest.mark.parametrize(
    ("string_set", "expected"),
    [
        (Identifier("helper"), "any of (helper)"),
        (StringWildcard("helper*"), "any of (helper*)"),
        (SetExpression([Identifier("helper")]), "any of (helper)"),
        (SetExpression([StringWildcard("helper*")]), "any of (helper*)"),
    ],
)
def test_codegen_generators_allow_rule_sets_in_conditionless_for_of_expression(
    string_set: Any,
    expected: str,
) -> None:
    ast = YaraFile(
        rules=[
            Rule(name="helper", condition=BooleanLiteral(True)),
            Rule(name="main", condition=ForOfExpression("any", string_set, None)),
        ]
    )

    assert expected in CodeGenerator().generate(ast)
    assert expected in CodeGenerator(
        options=GeneratorOptions(advanced=FormattingConfig())
    ).generate(ast)
    assert expected in CodeGenerator(options=GeneratorOptions.comment_aware()).generate(ast)
    assert expected in CodeGenerator(
        options=GeneratorOptions(pretty=PrettyPrintOptions())
    ).generate(ast)


@pytest.mark.parametrize(
    "condition",
    [
        OfExpression(-1, Identifier("them")),
        ForOfExpression(-1, Identifier("them"), BooleanLiteral(True)),
        OfExpression(True, Identifier("them")),
        OfExpression(1.01, Identifier("them")),
        OfExpression(DoubleLiteral(1.01), Identifier("them")),
        OfExpression("-1", Identifier("them")),
        OfExpression("101%", Identifier("them")),
        OfExpression(StringLiteral("-1"), Identifier("them")),
        OfExpression(StringLiteral("101%"), Identifier("them")),
        OfExpression(StringLiteral("x"), Identifier("them")),
        ForOfExpression(StringLiteral("x"), Identifier("them"), BooleanLiteral(True)),
        OfExpression("bad-key", Identifier("them")),
        OfExpression("true", Identifier("them")),
        OfExpression(StringLiteral("bad-key"), Identifier("them")),
        OfExpression(StringLiteral("true"), Identifier("them")),
        OfExpression(IntegerLiteral(-1), Identifier("them")),
        OfExpression(UnaryExpression("-", IntegerLiteral(1)), Identifier("them")),
        OfExpression(UnaryExpression("~", IntegerLiteral(1)), Identifier("them")),
        OfExpression(BooleanLiteral(True), Identifier("them")),
        OfExpression(Identifier("true"), Identifier("them")),
        ForOfExpression(
            UnaryExpression("-", IntegerLiteral(1)),
            Identifier("them"),
            StringIdentifier("$"),
        ),
        ForOfExpression(
            UnaryExpression("~", IntegerLiteral(1)),
            Identifier("them"),
            StringIdentifier("$"),
        ),
    ],
)
def test_codegen_generators_reject_invalid_quantifiers(condition: Any) -> None:
    ast = YaraFile(
        rules=[
            Rule(
                name="invalid_quantifier",
                strings=[PlainString(identifier="$a", value="x")],
                condition=condition,
            )
        ]
    )

    with pytest.raises(ValueError, match=r"Invalid .*quantifier"):
        CodeGenerator().generate(ast)
    with pytest.raises(ValueError, match=r"Invalid .*quantifier"):
        CodeGenerator(options=GeneratorOptions(advanced=FormattingConfig())).generate(ast)
    with pytest.raises(ValueError, match=r"Invalid .*quantifier"):
        CodeGenerator(options=GeneratorOptions.comment_aware()).generate(ast)
    with pytest.raises(ValueError, match=r"Invalid .*quantifier"):
        CodeGenerator(options=GeneratorOptions(pretty=PrettyPrintOptions())).generate(ast)


@pytest.mark.parametrize(
    "condition",
    [
        OfExpression(2**63, Identifier("them")),
        OfExpression(IntegerLiteral(2**63), Identifier("them")),
        ForOfExpression(2**63, Identifier("them"), StringIdentifier("$")),
        ForOfExpression(IntegerLiteral(2**63), Identifier("them"), StringIdentifier("$")),
    ],
)
def test_codegen_generators_reject_out_of_range_numeric_quantifiers(condition: Any) -> None:
    ast = YaraFile(
        rules=[
            Rule(
                name="invalid_quantifier_range",
                strings=[PlainString(identifier="$a", value="x")],
                condition=condition,
            )
        ]
    )

    with pytest.raises(ValueError, match="Integer literal value is outside libyara range"):
        CodeGenerator().generate(ast)
    with pytest.raises(ValueError, match="Integer literal value is outside libyara range"):
        CodeGenerator(options=GeneratorOptions(advanced=FormattingConfig())).generate(ast)
    with pytest.raises(ValueError, match="Integer literal value is outside libyara range"):
        CodeGenerator(options=GeneratorOptions.comment_aware()).generate(ast)
    with pytest.raises(ValueError, match="Integer literal value is outside libyara range"):
        CodeGenerator(options=GeneratorOptions(pretty=PrettyPrintOptions())).generate(ast)


@pytest.mark.parametrize(
    ("condition", "message"),
    [
        (
            ForExpression(
                "any",
                "i",
                RangeExpression(IntegerLiteral(-1), IntegerLiteral(1)),
                BooleanLiteral(True),
            ),
            "Range low bound cannot be negative",
        ),
        (
            ForExpression(
                "any",
                "i",
                RangeExpression(IntegerLiteral(3), IntegerLiteral(1)),
                BooleanLiteral(True),
            ),
            "Range low bound cannot exceed high bound",
        ),
    ],
)
def test_codegen_generators_reject_invalid_constant_range_bounds(
    condition: Any,
    message: str,
) -> None:
    ast = YaraFile(rules=[Rule(name="invalid_range_bounds", condition=condition)])

    with pytest.raises(ValueError, match=message):
        CodeGenerator().generate(ast)
    with pytest.raises(ValueError, match=message):
        CodeGenerator(options=GeneratorOptions(advanced=FormattingConfig())).generate(ast)
    with pytest.raises(ValueError, match=message):
        CodeGenerator(options=GeneratorOptions.comment_aware()).generate(ast)
    with pytest.raises(ValueError, match=message):
        CodeGenerator(options=GeneratorOptions(pretty=PrettyPrintOptions())).generate(ast)


def test_codegen_generators_allow_external_identifier_of_quantifier() -> None:
    ast = YaraFile(
        rules=[
            Rule(
                name="external_quantifier",
                strings=[PlainString("$a", value="x")],
                condition=OfExpression(Identifier("n"), Identifier("them")),
            )
        ]
    )

    assert "n of them" in CodeGenerator().generate(ast)
    assert "n of them" in CodeGenerator(
        options=GeneratorOptions(advanced=FormattingConfig())
    ).generate(ast)
    assert "n of them" in CodeGenerator(options=GeneratorOptions.comment_aware()).generate(ast)
    assert "n of them" in CodeGenerator(
        options=GeneratorOptions(pretty=PrettyPrintOptions())
    ).generate(ast)


def test_codegen_generators_reject_empty_set_expression() -> None:
    ast = YaraFile(rules=[Rule(name="empty_set", condition=SetExpression([]))])

    with pytest.raises(ValueError, match="Set expression must contain at least one element"):
        CodeGenerator().generate(ast)
    with pytest.raises(ValueError, match="Set expression must contain at least one element"):
        CodeGenerator(options=GeneratorOptions(advanced=FormattingConfig())).generate(ast)
    with pytest.raises(ValueError, match="Set expression must contain at least one element"):
        CodeGenerator(options=GeneratorOptions.comment_aware()).generate(ast)
    with pytest.raises(ValueError, match="Set expression must contain at least one element"):
        CodeGenerator(options=GeneratorOptions(pretty=PrettyPrintOptions())).generate(ast)


@pytest.mark.parametrize(
    "quantifier",
    [
        -1,
        True,
        0.5,
        "-1",
        "50%",
        "true",
        "bad-key",
        IntegerLiteral(-1),
        UnaryExpression("-", IntegerLiteral(1)),
        UnaryExpression("~", IntegerLiteral(1)),
        StringLiteral("50%"),
        StringLiteral("true"),
        DoubleLiteral(0.5),
        BooleanLiteral(True),
        Identifier("true"),
    ],
)
def test_codegen_generators_reject_invalid_for_quantifiers(quantifier: Any) -> None:
    ast = YaraFile(
        rules=[
            Rule(
                name="invalid_for_quantifier",
                condition=ForExpression(
                    quantifier,
                    "i",
                    SetExpression([IntegerLiteral(1)]),
                    BooleanLiteral(True),
                ),
            )
        ]
    )

    with pytest.raises(ValueError, match="Invalid for quantifier"):
        CodeGenerator().generate(ast)
    with pytest.raises(ValueError, match="Invalid for quantifier"):
        CodeGenerator(options=GeneratorOptions(advanced=FormattingConfig())).generate(ast)
    with pytest.raises(ValueError, match="Invalid for quantifier"):
        CodeGenerator(options=GeneratorOptions.comment_aware()).generate(ast)
    with pytest.raises(ValueError, match="Invalid for quantifier"):
        CodeGenerator(options=GeneratorOptions(pretty=PrettyPrintOptions())).generate(ast)


@pytest.mark.parametrize(
    "quantifier",
    [
        0.5,
        "50%",
        StringLiteral("50%"),
        DoubleLiteral(0.5),
    ],
)
def test_codegen_generators_reject_percentage_for_of_quantifiers(
    quantifier: Any,
) -> None:
    ast = YaraFile(
        rules=[
            Rule(
                name="invalid_for_of_quantifier",
                strings=[PlainString(identifier="$a", value="x")],
                condition=ForOfExpression(
                    quantifier=quantifier,
                    string_set=Identifier("them"),
                    condition=StringIdentifier("$"),
                ),
            )
        ]
    )

    with pytest.raises(ValueError, match="Invalid for quantifier"):
        CodeGenerator().generate(ast)
    with pytest.raises(ValueError, match="Invalid for quantifier"):
        CodeGenerator(options=GeneratorOptions(advanced=FormattingConfig())).generate(ast)
    with pytest.raises(ValueError, match="Invalid for quantifier"):
        CodeGenerator(options=GeneratorOptions.comment_aware()).generate(ast)
    with pytest.raises(ValueError, match="Invalid for quantifier"):
        CodeGenerator(options=GeneratorOptions(pretty=PrettyPrintOptions())).generate(ast)


@pytest.mark.parametrize(
    "source",
    [
        'rule r { strings: $a = "x" condition: for #a i in (1..2) : (@a[i] > 0) }',
        'rule r { strings: $a = "x" condition: for uint8(0) i in (1..2) : (@a[i] > 0) }',
        'rule r { strings: $a = "x" condition: for filesize i in (1..2) : (@a[i] > 0) }',
        'rule r { strings: $a = "x" $b = "y" condition: for #a of them : ($) }',
    ],
)
def test_codegen_round_trips_primary_expression_for_quantifier(source: str) -> None:
    from yaraast.parser.parser import Parser as _Parser

    ast = _Parser().parse(source)
    generated = CodeGenerator().generate(ast)
    reparsed = _Parser().parse(generated)
    assert CodeGenerator().generate(reparsed) == generated


@pytest.mark.parametrize(
    "quantifier",
    [IntegerLiteral(cast(Any, True)), IntegerLiteral(cast(Any, "any")), RegexLiteral("x")],
)
def test_codegen_generators_reject_malformed_quantifiers(quantifier: Any) -> None:
    expressions = [
        ForExpression(
            quantifier=quantifier,
            variable="i",
            iterable=RangeExpression(IntegerLiteral(0), IntegerLiteral(1)),
            body=BooleanLiteral(True),
        ),
        ForOfExpression(
            quantifier=quantifier,
            string_set=Identifier("them"),
            condition=BooleanLiteral(True),
        ),
        OfExpression(
            quantifier=quantifier,
            string_set=Identifier("them"),
        ),
    ]

    for expression in expressions:
        ast = YaraFile(
            rules=[
                Rule(
                    name="invalid_quantifier",
                    strings=[PlainString(identifier="$a", value="x")],
                    condition=BinaryExpression(StringIdentifier("$a"), "and", expression),
                )
            ]
        )
        with pytest.raises(ValueError, match=r"Invalid .*quantifier"):
            CodeGenerator().generate(ast)
        with pytest.raises(ValueError, match=r"Invalid .*quantifier"):
            CodeGenerator(options=GeneratorOptions(advanced=FormattingConfig())).generate(ast)
        with pytest.raises(ValueError, match=r"Invalid .*quantifier"):
            CodeGenerator(options=GeneratorOptions.comment_aware()).generate(ast)
        with pytest.raises(ValueError, match=r"Invalid .*quantifier"):
            CodeGenerator(options=GeneratorOptions(pretty=PrettyPrintOptions())).generate(ast)


def test_codegen_generators_render_fractional_quantifier_percentages() -> None:
    ast = YaraFile(
        rules=[
            Rule(
                name="fractional_quantifier",
                strings=[PlainString(identifier="a", value="x")],
                condition=OfExpression(0.29, Identifier("them")),
            )
        ]
    )

    assert "29% of them" in CodeGenerator().generate(ast)
    assert "29% of them" in CodeGenerator(
        options=GeneratorOptions(advanced=FormattingConfig())
    ).generate(ast)
    assert "29% of them" in CodeGenerator(options=GeneratorOptions.comment_aware()).generate(ast)
    assert "29% of them" in CodeGenerator(
        options=GeneratorOptions(pretty=PrettyPrintOptions())
    ).generate(ast)


def test_codegen_generators_reject_zero_percent_quantifiers() -> None:
    invalid_quantifiers: list[Expression | str | int | float] = [
        0.0,
        DoubleLiteral(0.0),
        "0%",
        StringLiteral("0%"),
        UnaryExpression("%", IntegerLiteral(0)),
        UnaryExpression("%", BinaryExpression(IntegerLiteral(51), "*", IntegerLiteral(2))),
        UnaryExpression(
            "%",
            UnaryExpression("-", UnaryExpression("-", DoubleLiteral(1.2))),
        ),
        UnaryExpression(
            "%",
            BinaryExpression(
                BinaryExpression(
                    UnaryExpression("-", StringCount("a")),
                    ">>",
                    IntegerLiteral(50),
                ),
                ">>",
                IntegerLiteral(101),
            ),
        ),
    ]

    for quantifier in invalid_quantifiers:
        with pytest.raises(ValueError, match="Invalid quantifier"):
            CodeGenerator().generate(OfExpression(quantifier, Identifier("them")))


def test_codegen_generators_render_dynamic_percentage_quantifiers() -> None:
    dynamic = OfExpression(UnaryExpression("%", StringCount("a")), Identifier("them"))
    parenthesized = OfExpression(
        UnaryExpression(
            "%",
            ParenthesesExpression(BinaryExpression(IntegerLiteral(25), "+", IntegerLiteral(25))),
        ),
        Identifier("them"),
    )
    multiplicative = OfExpression(
        UnaryExpression(
            "%",
            BinaryExpression(StringOffset("a"), "%", IntegerLiteral(50)),
        ),
        Identifier("them"),
    )
    signed_remainder = OfExpression(
        UnaryExpression(
            "%",
            BinaryExpression(
                UnaryExpression("-", UnaryExpression("-", IntegerLiteral(25))),
                "%",
                UnaryExpression("~", IntegerLiteral(100)),
            ),
        ),
        Identifier("them"),
    )

    assert CodeGenerator().generate(dynamic) == "#a% of them"
    assert CodeGenerator().generate(parenthesized) == "(25 + 25)% of them"
    assert CodeGenerator().generate(multiplicative) == "(@a % 50)% of them"
    assert CodeGenerator().generate(signed_remainder) == "(--25 % ~100)% of them"


@pytest.mark.parametrize(
    "quantifier",
    [
        DoubleLiteral(cast(Any, True)),
        DoubleLiteral(cast(Any, "0.5")),
        DoubleLiteral(float("nan")),
        DoubleLiteral(float("inf")),
    ],
)
def test_codegen_rejects_malformed_fractional_percentage_quantifiers(
    quantifier: DoubleLiteral,
) -> None:
    with pytest.raises(ValueError, match=r"Invalid quantifier"):
        CodeGenerator().generate(OfExpression(quantifier, Identifier("them")))
    with pytest.raises(ValueError, match=r"Invalid quantifier"):
        CodeGenerator().generate(ForOfExpression(quantifier, Identifier("them")))


@pytest.mark.parametrize(
    ("condition", "message"),
    [
        (BinaryExpression(IntegerLiteral(1), "???", IntegerLiteral(2)), "Invalid binary operator"),
        (
            StringOperatorExpression(StringLiteral("a"), "bad-op", StringLiteral("b")),
            "Invalid string operator",
        ),
        (
            StringOperatorExpression(StringLiteral("a"), "matches", StringLiteral("b")),
            "Right operand of 'matches' must be regex",
        ),
        (
            StringOperatorExpression(IntegerLiteral(1), "contains", StringLiteral("x")),
            "Left operand of 'contains' must be string-like or array",
        ),
        (
            StringOperatorExpression(StringLiteral("x"), "contains", IntegerLiteral(1)),
            "Right operand of 'contains' must be string",
        ),
        (
            BinaryExpression(BooleanLiteral(True), "contains", StringLiteral("x")),
            "Left operand of 'contains' must be string-like or array",
        ),
        (
            BinaryExpression(
                OfExpression("all", Identifier("other_rule")),
                "contains",
                StringLiteral("x"),
            ),
            "Left operand of 'contains' must be string-like or array",
        ),
        (
            BinaryExpression(StringLiteral("abc"), "matches", StringLiteral("a")),
            "Right operand of 'matches' must be regex",
        ),
        (
            BinaryExpression(
                StringLiteral("abc"),
                "contains",
                BinaryExpression(IntegerLiteral(-1), "^", Identifier("filesize")),
            ),
            "Right operand of 'contains' must be string",
        ),
        (
            BinaryExpression(BooleanLiteral(True), "==", BooleanLiteral(False)),
            "Boolean operands cannot be used with '==' comparisons",
        ),
        (
            BinaryExpression(BooleanLiteral(True), "!=", IntegerLiteral(1)),
            "Boolean operands cannot be used with '!=' comparisons",
        ),
        (
            BinaryExpression(IntegerLiteral(1), ">", BooleanLiteral(False)),
            "Boolean operands cannot be used with '>' comparisons",
        ),
        (
            BinaryExpression(
                Identifier("filesize"),
                "==",
                ParenthesesExpression(BinaryExpression(IntegerLiteral(1), "==", IntegerLiteral(1))),
            ),
            "Boolean operands cannot be used with '==' comparisons",
        ),
        (
            BinaryExpression(
                Identifier("filesize"),
                "==",
                OfExpression(IntegerLiteral(1), Identifier("other_rule")),
            ),
            "Boolean operands cannot be used with '==' comparisons",
        ),
        (
            BinaryExpression(RegexLiteral("a"), "==", RegexLiteral("b")),
            "Regex operands cannot be used with '==' comparisons",
        ),
        (
            BinaryExpression(IntegerLiteral(1), "<", StringLiteral("x")),
            "Incompatible types for '<': integer and string",
        ),
        (
            BinaryExpression(StringLiteral("x"), ">=", DoubleLiteral(1.5)),
            "Incompatible types for '>=': string and double",
        ),
        (
            BinaryExpression(IntegerLiteral(1), "==", StringLiteral("x")),
            "Incompatible types for '==': integer and string",
        ),
        (
            BinaryExpression(StringLiteral("x"), "!=", IntegerLiteral(1)),
            "Incompatible types for '!=': string and integer",
        ),
        (
            BinaryExpression(StringLiteral("x"), "==", Identifier("filesize")),
            "Incompatible types for '==': string and integer",
        ),
        (
            BinaryExpression(StringLiteral("x"), "!=", Identifier("entrypoint")),
            "Incompatible types for '!=': string and integer",
        ),
        (
            BinaryExpression(
                ParenthesesExpression(UnaryExpression("-", IntegerLiteral(1))),
                "==",
                StringLiteral("x"),
            ),
            "Incompatible types for '==': integer and string",
        ),
        (
            BinaryExpression(
                StringLiteral("x"),
                ">=",
                ParenthesesExpression(UnaryExpression("-", IntegerLiteral(1))),
            ),
            "Incompatible types for '>=': string and integer",
        ),
        (
            BinaryExpression(
                ParenthesesExpression(UnaryExpression("-", IntegerLiteral(1))),
                "contains",
                StringLiteral("x"),
            ),
            "Left operand of 'contains' must be string-like or array",
        ),
        (
            BinaryExpression(
                StringLiteral("x"),
                "startswith",
                ParenthesesExpression(UnaryExpression("-", IntegerLiteral(1))),
            ),
            "Right operand of 'startswith' must be string",
        ),
        (
            BinaryExpression(
                StringLiteral("x"),
                "matches",
                ParenthesesExpression(RegexLiteral("x")),
            ),
            "Right operand of 'matches' must be regex",
        ),
        (
            BinaryExpression(IntegerLiteral(1), "/", IntegerLiteral(0)),
            "Right operand of '/' cannot be zero",
        ),
        (
            BinaryExpression(IntegerLiteral(1), "\\", ParenthesesExpression(IntegerLiteral(0))),
            "Right operand of '\\\\' cannot be zero",
        ),
        (
            BinaryExpression(IntegerLiteral(1), "%", UnaryExpression("-", IntegerLiteral(0))),
            "Right operand of '%' cannot be zero",
        ),
        (
            BinaryExpression(StringLiteral("x"), "+", IntegerLiteral(1)),
            "Left operand of '\\+' must be numeric",
        ),
        (
            BinaryExpression(IntegerLiteral(1), "+", RegexLiteral("a")),
            "Right operand of '\\+' must be numeric",
        ),
        (
            BinaryExpression(
                IntegerLiteral(1), "+", OfExpression(IntegerLiteral(1), Identifier("other_rule"))
            ),
            "Right operand of '\\+' must be numeric",
        ),
        (
            BinaryExpression(DoubleLiteral(1.5), "%", IntegerLiteral(1)),
            "Left operand of '%' must be integer",
        ),
        (
            BinaryExpression(IntegerLiteral(1), "&", DoubleLiteral(1.5)),
            "Right operand of '&' must be integer",
        ),
        (
            BinaryExpression(
                ParenthesesExpression(UnaryExpression("-", DoubleLiteral(1.5))),
                "&",
                IntegerLiteral(1),
            ),
            "Left operand of '&' must be integer",
        ),
        (
            BinaryExpression(IntegerLiteral(1), "<<", UnaryExpression("-", IntegerLiteral(1))),
            "Right operand of '<<' cannot be negative",
        ),
        (
            BinaryExpression(
                IntegerLiteral(1),
                ">>",
                ParenthesesExpression(UnaryExpression("-", IntegerLiteral(1))),
            ),
            "Right operand of '>>' cannot be negative",
        ),
        (
            UnaryExpression("-", StringLiteral("x")),
            "Operand of '-' must be numeric",
        ),
        (
            UnaryExpression("~", DoubleLiteral(1.5)),
            "Operand of '~' must be integer",
        ),
        (
            UnaryExpression(
                "~",
                AtExpression(
                    OfExpression(IntegerLiteral(1), Identifier("other_rule")),
                    ParenthesesExpression(IntegerLiteral(10)),
                ),
            ),
            "Operand of '~' must be integer",
        ),
        (UnaryExpression("!", IntegerLiteral(1)), "Invalid unary operator"),
    ],
)
def test_codegen_generators_reject_invalid_expression_operators(
    condition: Any,
    message: str,
) -> None:
    ast = YaraFile(rules=[Rule(name="invalid_operator", condition=condition)])

    with pytest.raises(ValueError, match=message):
        CodeGenerator().generate(ast)
    with pytest.raises(ValueError, match=message):
        CodeGenerator(options=GeneratorOptions(advanced=FormattingConfig())).generate(ast)
    with pytest.raises(ValueError, match=message):
        CodeGenerator(options=GeneratorOptions.comment_aware()).generate(ast)
    with pytest.raises(ValueError, match=message):
        CodeGenerator(options=GeneratorOptions(pretty=PrettyPrintOptions())).generate(ast)


def test_codegen_generators_allow_string_count_in_as_integer_operand() -> None:
    condition = BinaryExpression(
        InExpression(
            StringCount("a"),
            RangeExpression(IntegerLiteral(0), Identifier("filesize")),
        ),
        "+",
        IntegerLiteral(1),
    )
    ast = YaraFile(
        rules=[
            Rule(
                name="string_count_in_integer_operand",
                strings=[PlainString(identifier="a", value="a")],
                condition=condition,
            )
        ]
    )

    assert "#a in (0..filesize) + 1" in CodeGenerator().generate(ast)


def test_codegen_rejects_non_integer_at_expression_offset_directly() -> None:
    with pytest.raises(ValueError, match="At expression offset must be integer"):
        CodeGenerator().generate(AtExpression("$a", UnaryExpression("not", BooleanLiteral(True))))


def test_codegen_rejects_unary_not_as_numeric_binary_operand_directly() -> None:
    condition = BinaryExpression(
        UnaryExpression("not", BooleanLiteral(True)),
        "+",
        IntegerLiteral(1),
    )

    with pytest.raises(ValueError, match="Left operand of '\\+' must be numeric"):
        CodeGenerator().generate(condition)


def test_codegen_rejects_non_integer_binary_range_bound_directly() -> None:
    condition = InExpression(
        "$a",
        RangeExpression(
            BinaryExpression(StringIdentifier("$a"), "or", IntegerLiteral(10)),
            IntegerLiteral(10),
        ),
    )

    with pytest.raises(ValueError, match="Range low bound must be integer"):
        CodeGenerator().generate(condition)


def test_codegen_rejects_computed_static_range_bounds_out_of_order_directly() -> None:
    condition = InExpression(
        StringCount("a"),
        RangeExpression(
            IntegerLiteral(10),
            BinaryExpression(IntegerLiteral(0), "-", IntegerLiteral(0)),
        ),
    )

    with pytest.raises(ValueError, match="Range low bound cannot exceed high bound"):
        CodeGenerator().generate(condition)


@pytest.mark.parametrize(
    ("condition", "message"),
    [
        (
            BinaryExpression(StringLiteral("x"), "==", StringCount("$a")),
            "Incompatible types for '==': string and integer",
        ),
        (
            BinaryExpression(StringLiteral("x"), "!=", StringOffset("$a")),
            "Incompatible types for '!=': string and integer",
        ),
        (
            BinaryExpression(StringLiteral("x"), ">=", StringLength("$a")),
            "Incompatible types for '>=': string and integer",
        ),
        (
            BinaryExpression(StringLiteral("x"), "contains", StringCount("$a")),
            "Right operand of 'contains' must be string",
        ),
        (
            BinaryExpression(StringLiteral("x"), "matches", StringLength("$a")),
            "Right operand of 'matches' must be regex",
        ),
    ],
)
def test_codegen_generators_reject_numeric_string_reference_operands(
    condition: Any,
    message: str,
) -> None:
    ast = YaraFile(
        rules=[
            Rule(
                name="invalid_string_reference_operand",
                strings=[PlainString(identifier="$a", value="x")],
                condition=condition,
            )
        ]
    )

    with pytest.raises(ValueError, match=message):
        CodeGenerator().generate(ast)
    with pytest.raises(ValueError, match=message):
        CodeGenerator(options=GeneratorOptions(advanced=FormattingConfig())).generate(ast)
    with pytest.raises(ValueError, match=message):
        CodeGenerator(options=GeneratorOptions.comment_aware()).generate(ast)
    with pytest.raises(ValueError, match=message):
        CodeGenerator(options=GeneratorOptions(pretty=PrettyPrintOptions())).generate(ast)


def test_codegen_generators_reject_undefined_string_references() -> None:
    ast = YaraFile(
        rules=[
            Rule(
                name="undefined_string",
                strings=[PlainString(identifier="$a", value="needle")],
                condition=BinaryExpression(
                    StringIdentifier("$missing"), "or", StringIdentifier("$a")
                ),
            )
        ]
    )

    message = "Undefined string references in rule 'undefined_string': \\$missing"
    with pytest.raises(ValueError, match=message):
        CodeGenerator().generate(ast)
    with pytest.raises(ValueError, match=message):
        CodeGenerator(options=GeneratorOptions(advanced=FormattingConfig())).generate(ast)
    with pytest.raises(ValueError, match=message):
        CodeGenerator(options=GeneratorOptions.comment_aware()).generate(ast)
    with pytest.raises(ValueError, match=message):
        CodeGenerator(options=GeneratorOptions(pretty=PrettyPrintOptions())).generate(ast)


def test_codegen_generators_reject_rules_without_conditions() -> None:
    ast = YaraFile(rules=[Rule(name="missing_condition")])

    message = "Rule 'missing_condition' must have a condition for libyara output"
    with pytest.raises(ValueError, match=message):
        CodeGenerator().generate(ast)
    with pytest.raises(ValueError, match=message):
        CodeGenerator(options=GeneratorOptions(advanced=FormattingConfig())).generate(ast)
    with pytest.raises(ValueError, match=message):
        CodeGenerator(options=GeneratorOptions.comment_aware()).generate(ast)
    with pytest.raises(ValueError, match=message):
        CodeGenerator(options=GeneratorOptions(pretty=PrettyPrintOptions())).generate(ast)


def test_codegen_generators_reject_them_without_string_definitions() -> None:
    ast = YaraFile(
        rules=[Rule(name="empty_them", condition=OfExpression("any", Identifier("them")))]
    )

    message = "Undefined string references in rule 'empty_them': \\$\\*"
    with pytest.raises(ValueError, match=message):
        CodeGenerator().generate(ast)
    with pytest.raises(ValueError, match=message):
        CodeGenerator(options=GeneratorOptions(advanced=FormattingConfig())).generate(ast)
    with pytest.raises(ValueError, match=message):
        CodeGenerator(options=GeneratorOptions.comment_aware()).generate(ast)
    with pytest.raises(ValueError, match=message):
        CodeGenerator(options=GeneratorOptions(pretty=PrettyPrintOptions())).generate(ast)


def test_codegen_generators_reject_unreferenced_string_definitions() -> None:
    ast = YaraFile(
        rules=[
            Rule(
                name="unreferenced_string",
                strings=[
                    PlainString(identifier="$a", value="needle"),
                    PlainString(identifier="$unused", value="unused"),
                ],
                condition=StringIdentifier("$a"),
            )
        ]
    )

    message = "Unreferenced string definitions in rule 'unreferenced_string': \\$unused"
    with pytest.raises(ValueError, match=message):
        CodeGenerator().generate(ast)
    with pytest.raises(ValueError, match=message):
        CodeGenerator(options=GeneratorOptions(advanced=FormattingConfig())).generate(ast)
    with pytest.raises(ValueError, match=message):
        CodeGenerator(options=GeneratorOptions.comment_aware()).generate(ast)
    with pytest.raises(ValueError, match=message):
        CodeGenerator(options=GeneratorOptions(pretty=PrettyPrintOptions())).generate(ast)


def test_codegen_generators_reject_unreferenced_anonymous_string_definition() -> None:
    ast = YaraFile(
        rules=[
            Rule(
                name="unreferenced_anonymous_string",
                strings=[PlainString(identifier="$", value="needle", is_anonymous=True)],
                condition=BooleanLiteral(True),
            )
        ]
    )

    message = "Unreferenced string definitions in rule " "'unreferenced_anonymous_string': \\$"
    with pytest.raises(ValueError, match=message):
        CodeGenerator().generate(ast)
    with pytest.raises(ValueError, match=message):
        CodeGenerator(options=GeneratorOptions(advanced=FormattingConfig())).generate(ast)
    with pytest.raises(ValueError, match=message):
        CodeGenerator(options=GeneratorOptions.comment_aware()).generate(ast)
    with pytest.raises(ValueError, match=message):
        CodeGenerator(options=GeneratorOptions(pretty=PrettyPrintOptions())).generate(ast)


@pytest.mark.parametrize(
    "condition",
    [
        StringWildcard("$a*"),
        BinaryExpression(StringWildcard("$a*"), "and", BooleanLiteral(True)),
    ],
)
def test_codegen_generators_reject_bare_string_wildcard_conditions(condition: Any) -> None:
    ast = YaraFile(
        rules=[
            Rule(
                name="bare_wildcard",
                strings=[PlainString(identifier="$a1", value="needle")],
                condition=condition,
            )
        ]
    )

    message = (
        "String wildcard expressions are only valid in string sets for " "libyara output: \\$a\\*"
    )
    with pytest.raises(ValueError, match=message):
        CodeGenerator().generate(ast)
    with pytest.raises(ValueError, match=message):
        CodeGenerator(options=GeneratorOptions(advanced=FormattingConfig())).generate(ast)
    with pytest.raises(ValueError, match=message):
        CodeGenerator(options=GeneratorOptions.comment_aware()).generate(ast)
    with pytest.raises(ValueError, match=message):
        CodeGenerator(options=GeneratorOptions(pretty=PrettyPrintOptions())).generate(ast)


@pytest.mark.parametrize(
    ("condition", "message"),
    [
        (
            SetExpression([IntegerLiteral(1), IntegerLiteral(2)]),
            "Set expressions are only valid in string set or iterable contexts for libyara output",
        ),
        (
            RangeExpression(IntegerLiteral(1), IntegerLiteral(2)),
            "Range expressions are only valid in iterable or range contexts for libyara output",
        ),
        (
            ParenthesesExpression(RangeExpression(IntegerLiteral(1), IntegerLiteral(2))),
            "Range expressions are only valid in iterable or range contexts for libyara output",
        ),
    ],
)
def test_codegen_generators_reject_bare_contextual_expressions(
    condition: Any,
    message: str,
) -> None:
    ast = YaraFile(rules=[Rule(name="bare_contextual", condition=condition)])

    with pytest.raises(ValueError, match=message):
        CodeGenerator().generate(ast)
    with pytest.raises(ValueError, match=message):
        CodeGenerator(options=GeneratorOptions(advanced=FormattingConfig())).generate(ast)
    with pytest.raises(ValueError, match=message):
        CodeGenerator(options=GeneratorOptions.comment_aware()).generate(ast)
    with pytest.raises(ValueError, match=message):
        CodeGenerator(options=GeneratorOptions(pretty=PrettyPrintOptions())).generate(ast)


@pytest.mark.parametrize(
    ("condition", "message"),
    [
        (
            InExpression("$a", BooleanLiteral(True)),
            "In expression range must be a range expression",
        ),
        (
            InExpression("$a", Identifier("filesize")),
            "In expression range must be a range expression",
        ),
        (
            InExpression("$a", ParenthesesExpression(StringCount("a"))),
            "In expression range must be a range expression",
        ),
        (
            ForExpression("any", "i", BooleanLiteral(True), StringIdentifier("$a")),
            "For expression iterable must be a range, set, or iterable expression",
        ),
        (
            ForExpression("any", "i", IntegerLiteral(1), StringIdentifier("$a")),
            "For expression iterable must be a range, set, or iterable expression",
        ),
        (
            ForExpression(
                "any", "i", SetExpression([BooleanLiteral(True)]), StringIdentifier("$a")
            ),
            "For expression iterable set items must be integer or string expressions",
        ),
        (
            ForExpression("any", "i", SetExpression([DoubleLiteral(1.5)]), StringIdentifier("$a")),
            "For expression iterable set items must be integer or string expressions",
        ),
        (
            ForExpression("any", "i", SetExpression([RegexLiteral("x")]), StringIdentifier("$a")),
            "For expression iterable set items must be integer or string expressions",
        ),
        (
            ForExpression(
                "any", "i", SetExpression([StringIdentifier("$a")]), StringIdentifier("$a")
            ),
            "For expression iterable set items must be integer or string expressions",
        ),
    ],
)
def test_codegen_generators_reject_invalid_in_and_for_iterables(
    condition: Any,
    message: str,
) -> None:
    ast = YaraFile(
        rules=[
            Rule(
                name="invalid_iterable",
                strings=[PlainString(identifier="$a", value="needle")],
                condition=condition,
            )
        ]
    )

    with pytest.raises(ValueError, match=message):
        CodeGenerator().generate(ast)
    with pytest.raises(ValueError, match=message):
        CodeGenerator(options=GeneratorOptions(advanced=FormattingConfig())).generate(ast)
    with pytest.raises(ValueError, match=message):
        CodeGenerator(options=GeneratorOptions.comment_aware()).generate(ast)
    with pytest.raises(ValueError, match=message):
        CodeGenerator(options=GeneratorOptions(pretty=PrettyPrintOptions())).generate(ast)


@pytest.mark.parametrize(
    "condition",
    [
        OfExpression(IntegerLiteral(1), IntegerLiteral(1)),
        OfExpression(IntegerLiteral(1), SetExpression([IntegerLiteral(1)])),
        ForOfExpression("any", IntegerLiteral(1), StringIdentifier("$")),
        ForOfExpression("any", SetExpression([IntegerLiteral(1)]), StringIdentifier("$")),
    ],
)
def test_codegen_generators_reject_invalid_string_set_items(condition: Any) -> None:
    ast = YaraFile(rules=[Rule(name="invalid_string_set", condition=condition)])

    message = "String set items must be string or rule identifiers for libyara output"
    with pytest.raises(ValueError, match=message):
        CodeGenerator().generate(ast)
    with pytest.raises(ValueError, match=message):
        CodeGenerator(options=GeneratorOptions(advanced=FormattingConfig())).generate(ast)
    with pytest.raises(ValueError, match=message):
        CodeGenerator(options=GeneratorOptions.comment_aware()).generate(ast)
    with pytest.raises(ValueError, match=message):
        CodeGenerator(options=GeneratorOptions(pretty=PrettyPrintOptions())).generate(ast)


@pytest.mark.parametrize(
    "condition",
    [
        BinaryExpression(StringIdentifier("$a"), "<", IntegerLiteral(1)),
        BinaryExpression(IntegerLiteral(1), "==", StringIdentifier("$a")),
    ],
)
def test_codegen_generators_reject_string_identifier_comparisons(condition: Any) -> None:
    ast = YaraFile(
        rules=[
            Rule(
                name="invalid_string_comparison",
                strings=[PlainString(identifier="$a", value="needle")],
                condition=condition,
            )
        ]
    )

    message = (
        "String identifiers cannot be used with comparison operators in rule "
        "'invalid_string_comparison': \\$a"
    )
    with pytest.raises(ValueError, match=message):
        CodeGenerator().generate(ast)
    with pytest.raises(ValueError, match=message):
        CodeGenerator(options=GeneratorOptions(advanced=FormattingConfig())).generate(ast)
    with pytest.raises(ValueError, match=message):
        CodeGenerator(options=GeneratorOptions.comment_aware()).generate(ast)
    with pytest.raises(ValueError, match=message):
        CodeGenerator(options=GeneratorOptions(pretty=PrettyPrintOptions())).generate(ast)


def test_codegen_generators_reject_string_identifier_matches_operand() -> None:
    ast = YaraFile(
        rules=[
            Rule(
                name="invalid_string_matches",
                strings=[PlainString(identifier="$a", value="needle")],
                condition=BinaryExpression(
                    StringLiteral("needle"), "matches", StringIdentifier("$a")
                ),
            )
        ]
    )

    message = "Right operand of 'matches' must be regex"
    with pytest.raises(ValueError, match=message):
        CodeGenerator().generate(ast)
    with pytest.raises(ValueError, match=message):
        CodeGenerator(options=GeneratorOptions(advanced=FormattingConfig())).generate(ast)
    with pytest.raises(ValueError, match=message):
        CodeGenerator(options=GeneratorOptions.comment_aware()).generate(ast)
    with pytest.raises(ValueError, match=message):
        CodeGenerator(options=GeneratorOptions(pretty=PrettyPrintOptions())).generate(ast)


def test_codegen_generators_allow_matches_regex_literal() -> None:
    ast = YaraFile(
        rules=[
            Rule(
                name="matches_regex",
                condition=StringOperatorExpression(
                    StringLiteral("abc"),
                    "matches",
                    RegexLiteral("a.c"),
                ),
            )
        ]
    )

    assert '"abc" matches /a.c/' in CodeGenerator().generate(ast)
    assert '"abc" matches /a.c/' in CodeGenerator(
        options=GeneratorOptions(advanced=FormattingConfig())
    ).generate(ast)
    assert '"abc" matches /a.c/' in CodeGenerator(
        options=GeneratorOptions.comment_aware()
    ).generate(ast)
    assert '"abc" matches /a.c/' in CodeGenerator(
        options=GeneratorOptions(pretty=PrettyPrintOptions())
    ).generate(ast)


@pytest.mark.parametrize(
    ("condition", "message"),
    [
        (FunctionCall("bad-name", []), "Invalid function identifier"),
        (FunctionCall("math..entropy", []), "Invalid function identifier"),
        (Identifier("$a"), "String references must use StringIdentifier"),
        (MemberAccess(ModuleReference("pe"), "bad-name"), "Invalid member identifier"),
        (ModuleReference("bad-mod"), "Invalid module identifier"),
    ],
)
def test_codegen_generators_reject_invalid_reference_names(
    condition: Any,
    message: str,
) -> None:
    ast = YaraFile(
        imports=[Import("bad-mod"), Import("math"), Import("pe")],
        rules=[Rule(name="invalid_reference_name", condition=condition)],
    )

    with pytest.raises(ValueError, match=message):
        CodeGenerator().generate(ast)
    with pytest.raises(ValueError, match=message):
        CodeGenerator(options=GeneratorOptions(advanced=FormattingConfig())).generate(ast)
    with pytest.raises(ValueError, match=message):
        CodeGenerator(options=GeneratorOptions.comment_aware()).generate(ast)
    with pytest.raises(ValueError, match=message):
        CodeGenerator(options=GeneratorOptions(pretty=PrettyPrintOptions())).generate(ast)


@pytest.mark.parametrize(
    ("condition", "message"),
    [
        (
            FunctionCall("uint8", []),
            "Builtin function 'uint8' expects exactly 1 argument",
        ),
        (
            FunctionCall("uint8", [IntegerLiteral(0), IntegerLiteral(1)]),
            "Builtin function 'uint8' expects exactly 1 argument",
        ),
        (
            FunctionCall("uint8", [BooleanLiteral(True)]),
            "Builtin function 'uint8' argument must be integer",
        ),
        (
            FunctionCall("uint16", [StringLiteral("0")]),
            "Builtin function 'uint16' argument must be integer",
        ),
        (
            FunctionCall("uint32", [DoubleLiteral(1.5)]),
            "Builtin function 'uint32' argument must be integer",
        ),
        (
            FunctionCall("int16le", [IntegerLiteral(0)]),
            "Builtin function 'int16le' is not supported by libyara",
        ),
        (
            FunctionCall("int32le", [IntegerLiteral(0)]),
            "Builtin function 'int32le' is not supported by libyara",
        ),
        (
            FunctionCall("uint16le", [IntegerLiteral(0)]),
            "Builtin function 'uint16le' is not supported by libyara",
        ),
        (
            FunctionCall("uint32le", [IntegerLiteral(0)]),
            "Builtin function 'uint32le' is not supported by libyara",
        ),
    ],
)
def test_codegen_generators_reject_invalid_integer_builtin_calls(
    condition: Any,
    message: str,
) -> None:
    ast = YaraFile(rules=[Rule(name="invalid_builtin_call", condition=condition)])

    with pytest.raises(ValueError, match=message):
        CodeGenerator().generate(ast)
    with pytest.raises(ValueError, match=message):
        CodeGenerator(options=GeneratorOptions(advanced=FormattingConfig())).generate(ast)
    with pytest.raises(ValueError, match=message):
        CodeGenerator(options=GeneratorOptions.comment_aware()).generate(ast)
    with pytest.raises(ValueError, match=message):
        CodeGenerator(options=GeneratorOptions(pretty=PrettyPrintOptions())).generate(ast)


def test_codegen_libyara_generators_reject_unknown_unqualified_function_calls() -> None:
    ast = YaraFile(rules=[Rule(name="unknown_function", condition=FunctionCall("foo", []))])
    message = "Function 'foo' is not supported by libyara output"

    with pytest.raises(ValueError, match=message):
        CodeGenerator().generate(ast)
    with pytest.raises(ValueError, match=message):
        CodeGenerator(options=GeneratorOptions.comment_aware()).generate(ast)
    with pytest.raises(ValueError, match=message):
        CodeGenerator(options=GeneratorOptions(pretty=PrettyPrintOptions())).generate(ast)


@pytest.mark.parametrize(
    ("condition", "message"),
    [
        (
            FunctionCall("math.entropy", []),
            "Module function 'math\\.entropy' expects at least 1 argument",
        ),
        (
            FunctionCall("math.entropy", [IntegerLiteral(0)]),
            "Module function 'math\\.entropy' does not accept these argument types",
        ),
        (
            FunctionCall("math.entropy", [StringLiteral("x"), IntegerLiteral(1)]),
            "Module function 'math\\.entropy' does not accept these argument types",
        ),
        (
            FunctionCall(
                "math.in_range",
                [IntegerLiteral(1), IntegerLiteral(1), IntegerLiteral(1)],
            ),
            "Module function 'math\\.in_range' does not accept these argument types",
        ),
        (
            FunctionCall("hash.md5", []),
            "Module function 'hash\\.md5' expects at least 1 argument",
        ),
        (
            FunctionCall("hash.md5", [IntegerLiteral(0)]),
            "Module function 'hash\\.md5' does not accept these argument types",
        ),
        (
            FunctionCall("hash.md5", [StringLiteral("x"), IntegerLiteral(1)]),
            "Module function 'hash\\.md5' does not accept these argument types",
        ),
        (
            FunctionCall("pe.imphash", [IntegerLiteral(0)]),
            "Module function 'pe\\.imphash' expects at most 0 argument",
        ),
        (
            FunctionCall("pe.signatures.valid_on", [IntegerLiteral(0)]),
            "Module function 'pe\\.signatures\\.valid_on' requires an indexed receiver",
        ),
        (
            FunctionCall("pe.imports", [IntegerLiteral(0)]),
            "Module function 'pe\\.imports' does not accept these argument types",
        ),
        (
            FunctionCall("pe.imports", [StringLiteral("kernel32.dll"), RegexLiteral("CreateFile")]),
            "Module function 'pe\\.imports' does not accept these argument types",
        ),
        (
            FunctionCall("pe.exports", [BooleanLiteral(True)]),
            "Module function 'pe\\.exports' does not accept these argument types",
        ),
        (
            FunctionCall("math.nope", []),
            "Module function 'math\\.nope' is not supported by libyara",
        ),
        (
            FunctionCall("hash.nope", []),
            "Module function 'hash\\.nope' is not supported by libyara",
        ),
        (
            FunctionCall("pe.nope", []),
            "Module function 'pe\\.nope' is not supported by libyara",
        ),
    ],
)
def test_codegen_generators_reject_invalid_module_function_calls(
    condition: Any,
    message: str,
) -> None:
    ast = YaraFile(
        imports=[Import("hash"), Import("math"), Import("pe")],
        rules=[Rule(name="invalid_module_function", condition=condition)],
    )

    with pytest.raises(ValueError, match=message):
        CodeGenerator().generate(ast)
    with pytest.raises(ValueError, match=message):
        CodeGenerator(options=GeneratorOptions(advanced=FormattingConfig())).generate(ast)
    with pytest.raises(ValueError, match=message):
        CodeGenerator(options=GeneratorOptions.comment_aware()).generate(ast)
    with pytest.raises(ValueError, match=message):
        CodeGenerator(options=GeneratorOptions(pretty=PrettyPrintOptions())).generate(ast)


@pytest.mark.parametrize(
    ("condition", "message"),
    [
        (
            FunctionCall("console.hex", [StringLiteral("x")]),
            "Module function 'console\\.hex' does not accept these argument types",
        ),
        (
            FunctionCall("console.hex", [IntegerLiteral(0), IntegerLiteral(0)]),
            "Module function 'console\\.hex' does not accept these argument types",
        ),
        (
            FunctionCall("console.log", [IntegerLiteral(0), IntegerLiteral(0)]),
            "Module function 'console\\.log' does not accept these argument types",
        ),
        (
            FunctionCall("console.log", [BooleanLiteral(True)]),
            "Module function 'console\\.log' does not accept these argument types",
        ),
    ],
)
def test_codegen_generators_reject_invalid_console_module_function_calls(
    condition: Any,
    message: str,
) -> None:
    ast = YaraFile(
        imports=[Import("console")],
        rules=[Rule(name="invalid_console_module_function", condition=condition)],
    )

    with pytest.raises(ValueError, match=message):
        CodeGenerator().generate(ast)
    with pytest.raises(ValueError, match=message):
        CodeGenerator(options=GeneratorOptions(advanced=FormattingConfig())).generate(ast)
    with pytest.raises(ValueError, match=message):
        CodeGenerator(options=GeneratorOptions.comment_aware()).generate(ast)
    with pytest.raises(ValueError, match=message):
        CodeGenerator(options=GeneratorOptions(pretty=PrettyPrintOptions())).generate(ast)


@pytest.mark.parametrize(
    ("condition", "message"),
    [
        (
            MemberAccess(ModuleReference("pe"), "no_such_field"),
            "Module member 'pe\\.no_such_field' is not supported by libyara",
        ),
        (
            MemberAccess(ModuleReference("pe"), "NO_SUCH_CONST"),
            "Module member 'pe\\.NO_SUCH_CONST' is not supported by libyara",
        ),
        (
            MemberAccess(ModuleReference("math"), "nope"),
            "Module member 'math\\.nope' is not supported by libyara",
        ),
        (
            MemberAccess(ModuleReference("hash"), "nope"),
            "Module member 'hash\\.nope' is not supported by libyara",
        ),
    ],
)
def test_codegen_generators_reject_unknown_builtin_module_members(
    condition: Any,
    message: str,
) -> None:
    ast = YaraFile(
        imports=[Import("hash"), Import("math"), Import("pe")],
        rules=[Rule(name="invalid_module_member", condition=condition)],
    )

    with pytest.raises(ValueError, match=message):
        CodeGenerator().generate(ast)
    with pytest.raises(ValueError, match=message):
        CodeGenerator(options=GeneratorOptions(advanced=FormattingConfig())).generate(ast)
    with pytest.raises(ValueError, match=message):
        CodeGenerator(options=GeneratorOptions.comment_aware()).generate(ast)
    with pytest.raises(ValueError, match=message):
        CodeGenerator(options=GeneratorOptions(pretty=PrettyPrintOptions())).generate(ast)


@pytest.mark.parametrize(
    ("condition", "message"),
    [
        (
            DictionaryAccess(ModuleReference("pe"), "Company"),
            "Module 'pe' cannot be indexed as a dictionary",
        ),
        (
            DictionaryAccess(ModuleReference("pe"), StringLiteral("Company")),
            "Module 'pe' cannot be indexed as a dictionary",
        ),
        (
            ArrayAccess(ModuleReference("pe"), IntegerLiteral(0)),
            "Module 'pe' cannot be indexed as an array",
        ),
        (
            DictionaryAccess(MemberAccess(ModuleReference("pe"), "rich_signature"), "nope"),
            "Module expression 'pe\\.rich_signature' cannot be indexed as a dictionary",
        ),
        (
            ArrayAccess(MemberAccess(ModuleReference("pe"), "rich_signature"), IntegerLiteral(0)),
            "Module expression 'pe\\.rich_signature' cannot be indexed as an array",
        ),
        (
            MemberAccess(MemberAccess(ModuleReference("pe"), "version_info"), "nope"),
            "Module expression 'pe\\.version_info' does not support member access",
        ),
        (
            MemberAccess(
                ArrayAccess(MemberAccess(ModuleReference("pe"), "sections"), IntegerLiteral(0)),
                "nope",
            ),
            "Module member 'pe\\.sections\\[0\\]\\.nope' is not supported by libyara",
        ),
    ],
)
def test_codegen_generators_reject_invalid_module_container_access(
    condition: Any,
    message: str,
) -> None:
    ast = YaraFile(imports=[Import("pe")], rules=[Rule(name="indexed_module", condition=condition)])

    with pytest.raises(ValueError, match=message):
        CodeGenerator().generate(ast)
    with pytest.raises(ValueError, match=message):
        CodeGenerator(options=GeneratorOptions(advanced=FormattingConfig())).generate(ast)
    with pytest.raises(ValueError, match=message):
        CodeGenerator(options=GeneratorOptions.comment_aware()).generate(ast)
    with pytest.raises(ValueError, match=message):
        CodeGenerator(options=GeneratorOptions(pretty=PrettyPrintOptions())).generate(ast)


@pytest.mark.parametrize(
    ("condition", "message"),
    [
        (
            ModuleReference("pe"),
            "Module 'pe' cannot be used as a condition value",
        ),
        (
            MemberAccess(ModuleReference("pe"), "sections"),
            "Module expression 'pe\\.sections' cannot be used as a condition value",
        ),
        (
            MemberAccess(ModuleReference("pe"), "version_info"),
            "Module expression 'pe\\.version_info' cannot be used as a condition value",
        ),
        (
            MemberAccess(ModuleReference("pe"), "rich_signature"),
            "Module expression 'pe\\.rich_signature' cannot be used as a condition value",
        ),
        (
            ArrayAccess(MemberAccess(ModuleReference("pe"), "sections"), IntegerLiteral(0)),
            "Module expression 'pe\\.sections\\[0\\]' cannot be used as a condition value",
        ),
        (
            BinaryExpression(
                MemberAccess(ModuleReference("pe"), "sections"), "==", IntegerLiteral(0)
            ),
            "Module expression 'pe\\.sections' cannot be used as a condition value",
        ),
        (
            ForExpression(
                "any",
                "item",
                MemberAccess(ModuleReference("pe"), "rich_signature"),
                BooleanLiteral(True),
            ),
            "Module expression 'pe\\.rich_signature' cannot be used as a condition value",
        ),
    ],
)
def test_codegen_generators_reject_bare_module_container_condition_values(
    condition: Any,
    message: str,
) -> None:
    ast = YaraFile(
        imports=[Import("pe")],
        rules=[Rule(name="bare_module_container_condition", condition=condition)],
    )

    with pytest.raises(ValueError, match=message):
        CodeGenerator().generate(ast)
    with pytest.raises(ValueError, match=message):
        CodeGenerator(options=GeneratorOptions(advanced=FormattingConfig())).generate(ast)
    with pytest.raises(ValueError, match=message):
        CodeGenerator(options=GeneratorOptions.comment_aware()).generate(ast)
    with pytest.raises(ValueError, match=message):
        CodeGenerator(options=GeneratorOptions(pretty=PrettyPrintOptions())).generate(ast)


@pytest.mark.parametrize(
    "condition",
    [
        MemberAccess(ModuleReference("pe"), "is_pe"),
        MemberAccess(Identifier("pe"), "is_pe"),
        FunctionCall("math.entropy", [StringLiteral("abc")]),
        FunctionCall(
            "valid_on",
            [IntegerLiteral(0)],
            receiver=ArrayAccess(
                MemberAccess(ModuleReference("pe"), "signatures"), IntegerLiteral(0)
            ),
        ),
    ],
)
def test_codegen_generators_reject_missing_module_imports(condition: Any) -> None:
    ast = YaraFile(rules=[Rule(name="missing_module_import", condition=condition)])

    with pytest.raises(ValueError, match="Module imports are required"):
        CodeGenerator().generate(ast)
    with pytest.raises(ValueError, match="Module imports are required"):
        CodeGenerator(options=GeneratorOptions(advanced=FormattingConfig())).generate(ast)
    with pytest.raises(ValueError, match="Module imports are required"):
        CodeGenerator(options=GeneratorOptions.comment_aware()).generate(ast)
    with pytest.raises(ValueError, match="Module imports are required"):
        CodeGenerator(options=GeneratorOptions(pretty=PrettyPrintOptions())).generate(ast)


@pytest.mark.parametrize(
    "condition",
    [
        FunctionCall("math.entropy", [StringLiteral("abc")]),
        FunctionCall("math.entropy", [IntegerLiteral(0), IntegerLiteral(10)]),
        FunctionCall(
            "math.in_range",
            [DoubleLiteral(1.0), DoubleLiteral(0.0), DoubleLiteral(2.0)],
        ),
        FunctionCall("hash.md5", [StringLiteral("abc")]),
        FunctionCall("hash.md5", [IntegerLiteral(0), IntegerLiteral(10)]),
        FunctionCall("pe.imphash", []),
        FunctionCall("pe.imports", [RegexLiteral("kernel32"), RegexLiteral("CreateFile")]),
        FunctionCall("pe.imports", [IntegerLiteral(1), StringLiteral("kernel32.dll")]),
        FunctionCall(
            "pe.imports",
            [IntegerLiteral(1), RegexLiteral("kernel32"), RegexLiteral("CreateFile")],
        ),
        FunctionCall("pe.exports", [RegexLiteral("ExportedFunc")]),
        FunctionCall("pe.exports_index", [RegexLiteral("ExportedFunc")]),
        MemberAccess(ModuleReference("pe"), "is_pe"),
        MemberAccess(ModuleReference("pe"), "MACHINE_I386"),
        DictionaryAccess(MemberAccess(ModuleReference("pe"), "version_info"), "CompanyName"),
        MemberAccess(
            ArrayAccess(MemberAccess(ModuleReference("pe"), "sections"), IntegerLiteral(0)),
            "name",
        ),
        MemberAccess(MemberAccess(ModuleReference("pe"), "rich_signature"), "offset"),
        ForExpression(
            "any",
            "section",
            MemberAccess(ModuleReference("pe"), "sections"),
            BinaryExpression(
                MemberAccess(Identifier("section"), "name"),
                "==",
                StringLiteral(".text"),
            ),
        ),
        ForExpression(
            "any",
            "key,value",
            MemberAccess(ModuleReference("pe"), "version_info"),
            BinaryExpression(Identifier("key"), "==", StringLiteral("CompanyName")),
        ),
    ],
)
def test_codegen_generators_allow_valid_module_function_calls(condition: Any) -> None:
    ast = YaraFile(
        imports=[Import("hash"), Import("math"), Import("pe")],
        rules=[Rule(name="valid_module_function", condition=condition)],
    )

    CodeGenerator().generate(ast)
    CodeGenerator(options=GeneratorOptions(advanced=FormattingConfig())).generate(ast)
    CodeGenerator(options=GeneratorOptions.comment_aware()).generate(ast)
    CodeGenerator(options=GeneratorOptions(pretty=PrettyPrintOptions())).generate(ast)


@pytest.mark.parametrize(
    "condition",
    [
        FunctionCall("console.hex", [IntegerLiteral(0)]),
        FunctionCall("console.hex", [StringLiteral("offset"), IntegerLiteral(0)]),
        FunctionCall("console.log", [IntegerLiteral(0)]),
        FunctionCall("console.log", [StringLiteral("value")]),
        FunctionCall("console.log", [StringLiteral("value"), IntegerLiteral(0)]),
    ],
)
def test_codegen_generators_allow_valid_console_module_function_calls(
    condition: Any,
) -> None:
    ast = YaraFile(
        imports=[Import("console")],
        rules=[Rule(name="valid_console_module_function", condition=condition)],
    )

    CodeGenerator().generate(ast)
    CodeGenerator(options=GeneratorOptions(advanced=FormattingConfig())).generate(ast)
    CodeGenerator(options=GeneratorOptions.comment_aware()).generate(ast)
    CodeGenerator(options=GeneratorOptions(pretty=PrettyPrintOptions())).generate(ast)


def test_codegen_generators_allow_for_of_placeholder_string_reference() -> None:
    ast = Parser().parse("""
        rule placeholder {
            strings:
                $a = "a"
            condition:
                for any of them : ($)
        }
        """)

    assert "for any of them : ($)" in CodeGenerator().generate(ast)
    assert "for any of them : ($)" in CodeGenerator(
        options=GeneratorOptions(advanced=FormattingConfig())
    ).generate(ast)
    assert "for any of them : ($)" in CodeGenerator(
        options=GeneratorOptions.comment_aware()
    ).generate(ast)
    assert "for any of them : ($)" in CodeGenerator(
        options=GeneratorOptions(pretty=PrettyPrintOptions())
    ).generate(ast)


def test_codegen_generators_allow_libyara_string_identifier_forms() -> None:
    ast = YaraFile(
        rules=[
            Rule(
                name="valid_string_identifiers",
                strings=[
                    PlainString(identifier="$1", value="x"),
                    PlainString(identifier="$for", value="y"),
                ],
                condition=BinaryExpression(
                    StringIdentifier("$1"),
                    "or",
                    StringIdentifier("$for"),
                ),
            )
        ]
    )

    assert '$1 = "x"' in CodeGenerator().generate(ast)
    assert '$for = "y"' in CodeGenerator(
        options=GeneratorOptions(advanced=FormattingConfig())
    ).generate(ast)
    assert '$1 = "x"' in CodeGenerator(options=GeneratorOptions.comment_aware()).generate(ast)
    assert '$for  = "y"' in CodeGenerator(
        options=GeneratorOptions(pretty=PrettyPrintOptions())
    ).generate(ast)


def test_codegen_generators_allow_multiple_anonymous_strings() -> None:
    ast = YaraFile(
        rules=[
            Rule(
                name="anonymous_strings",
                strings=[
                    PlainString(identifier="$anon_1", value="x", is_anonymous=True),
                    PlainString(identifier="$anon_2", value="y", is_anonymous=True),
                ],
                condition=OfExpression("any", Identifier("them")),
            )
        ]
    )

    assert '$ = "x"' in CodeGenerator().generate(ast)
    assert '$ = "x"' in CodeGenerator(
        options=GeneratorOptions(advanced=FormattingConfig())
    ).generate(ast)
    assert '$ = "x"' in CodeGenerator(options=GeneratorOptions.comment_aware()).generate(ast)
    assert '$  = "x"' in CodeGenerator(
        options=GeneratorOptions(pretty=PrettyPrintOptions())
    ).generate(ast)


def test_codegen_generator_expression_and_condition_paths() -> None:
    gen = CodeGenerator()

    assert gen.visit_string_literal(StringLiteral('a"b')) == '"a\\"b"'
    assert gen.visit_string_literal(StringLiteral("a\nb\t\x00")) == '"a\\nb\\t\\x00"'
    with pytest.raises(ValueError, match="String value must not contain Unicode surrogate"):
        gen.visit_string_literal(StringLiteral("\ud800"))
    assert gen.visit_regex_literal(RegexLiteral("ab.*", "i")) == "/ab.*/i"
    with pytest.raises(ValueError, match="Invalid regex modifier: m"):
        gen.visit_regex_literal(RegexLiteral("ab.*", "m"))
    with pytest.raises(ValueError, match="Duplicate regex modifier: i"):
        gen.visit_regex_literal(RegexLiteral("ab.*", "ii"))
    assert gen.visit_double_literal(DoubleLiteral(1.5)) == "1.5"
    with pytest.raises(TypeError, match="Double literal value must be numeric"):
        gen.visit_double_literal(DoubleLiteral(True))
    string_double_value: Any = "1.5"
    with pytest.raises(TypeError, match="Double literal value must be numeric"):
        gen.visit_double_literal(DoubleLiteral(string_double_value))
    with pytest.raises(ValueError, match="Double literal value must be finite"):
        gen.visit_double_literal(DoubleLiteral(float("nan")))
    with pytest.raises(ValueError, match="Double literal value must be finite"):
        gen.visit_double_literal(DoubleLiteral(float("inf")))
    with pytest.raises(ValueError, match="Integer literal value is outside libyara range"):
        gen.visit_double_literal(DoubleLiteral(2**63))
    assert gen.visit_double_literal(DoubleLiteral(INT64_MIN)) == "(-9223372036854775807 - 1)"
    bad_integer_text: Any = "abc"
    with pytest.raises(TypeError, match="Integer literal value must be an integer"):
        gen.visit_integer_literal(IntegerLiteral(bad_integer_text))
    bad_integer_number: Any = 1.5
    with pytest.raises(TypeError, match="Integer literal value must be an integer"):
        gen.visit_integer_literal(IntegerLiteral(bad_integer_number))
    hex_integer_text: Any = "0x10"
    assert gen.visit_integer_literal(IntegerLiteral(hex_integer_text)) == "0x10"
    assert gen.visit_integer_literal(IntegerLiteral(2**63 - 1)) == "9223372036854775807"
    assert gen.visit_integer_literal(IntegerLiteral(-(2**63) + 1)) == "-9223372036854775807"
    assert gen.visit_integer_literal(IntegerLiteral(INT64_MIN)) == "(-9223372036854775807 - 1)"
    min_hex_integer_text: Any = "-0x8000000000000000"
    assert gen.visit_integer_literal(IntegerLiteral(min_hex_integer_text)) == (
        "(-9223372036854775807 - 1)"
    )
    with pytest.raises(ValueError, match="Integer literal value is outside libyara range"):
        gen.visit_integer_literal(IntegerLiteral(2**63))
    oversized_hex_integer_text: Any = "0x8000000000000000"
    with pytest.raises(ValueError, match="Integer literal value is outside libyara range"):
        gen.visit_integer_literal(IntegerLiteral(oversized_hex_integer_text))
    assert gen.visit_double_literal(DoubleLiteral(1e3)) == "1000.0"
    assert gen.visit_double_literal(DoubleLiteral(1e308)).startswith("100000")
    assert "e" not in gen.visit_double_literal(DoubleLiteral(1e308)).lower()
    bad_boolean_value: Any = "false"
    with pytest.raises(TypeError, match="Boolean literal value must be a boolean"):
        gen.visit_boolean_literal(BooleanLiteral(bad_boolean_value))
    assert (
        gen.visit_binary_expression(BinaryExpression(IntegerLiteral(1), "+", IntegerLiteral(2)))
        == "1 + 2"
    )
    assert (
        gen.visit_binary_expression(BinaryExpression(IntegerLiteral(5), "\\", IntegerLiteral(2)))
        == "5 \\ 2"
    )
    assert (
        gen.visit_binary_expression(BinaryExpression(IntegerLiteral(5), "/", IntegerLiteral(2)))
        == "5 \\ 2"
    )
    assert (
        gen.generate(
            BinaryExpression(
                BinaryExpression(IntegerLiteral(1), "+", IntegerLiteral(2)),
                "*",
                IntegerLiteral(3),
            )
        )
        == "(1 + 2) * 3"
    )
    assert (
        gen.generate(
            BinaryExpression(
                IntegerLiteral(1),
                "*",
                BinaryExpression(IntegerLiteral(2), "+", IntegerLiteral(3)),
            )
        )
        == "1 * (2 + 3)"
    )
    assert (
        gen.generate(
            BinaryExpression(
                BinaryExpression(IntegerLiteral(1), "|", IntegerLiteral(2)),
                "&",
                IntegerLiteral(0),
            )
        )
        == "(1 | 2) & 0"
    )
    assert (
        gen.generate(
            BinaryExpression(
                IntegerLiteral(1),
                "|",
                BinaryExpression(IntegerLiteral(2), "&", IntegerLiteral(0)),
            )
        )
        == "1 | 2 & 0"
    )
    assert gen.visit_unary_expression(UnaryExpression("not", BooleanLiteral(False))) == "not false"
    assert (
        gen.generate(
            UnaryExpression("not", BinaryExpression(Identifier("a"), "or", Identifier("b")))
        )
        == "not (a or b)"
    )
    assert (
        gen.generate(
            UnaryExpression("-", BinaryExpression(IntegerLiteral(1), "+", IntegerLiteral(2)))
        )
        == "-(1 + 2)"
    )
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
        == "for any i in (1..2) : (i)"
    )
    assert (
        gen.visit_for_of_expression(
            ForOfExpression("all", Identifier("them"), StringIdentifier("$a"))
        )
        == "for all of them : ($a)"
    )
    assert (
        gen.visit_for_of_expression(
            ForOfExpression("all", Identifier("them"), _FalsyIntegerLiteral(0))
        )
        == "for all of them : (0)"
    )
    with pytest.raises(ValueError, match="For-of string set cannot contain rule"):
        gen.visit_for_of_expression(
            ForOfExpression("any", SetExpression([StringWildcard("helper*")]), BooleanLiteral(True))
        )
    with pytest.raises(ValueError, match="For-of string set cannot contain rule"):
        gen.visit_for_of_expression(
            ForOfExpression("any", Identifier("helper"), BooleanLiteral(True))
        )
    assert (
        gen.visit_for_of_expression(
            ForOfExpression("any", SetExpression([StringWildcard("helper*")]), None)
        )
        == "any of (helper*)"
    )
    assert gen.visit_for_of_expression(ForOfExpression("any", Identifier("helper"), None)) == (
        "any of (helper)"
    )
    assert gen.visit_at_expression(AtExpression("$a", IntegerLiteral(0))) == "$a at 0"
    with pytest.raises(ValueError, match="In expression range must be a range expression"):
        gen.visit_in_expression(InExpression("$a", ParenthesesExpression(StringOffset("a"))))
    assert (
        gen.visit_of_expression(OfExpression(StringLiteral("all"), Identifier("them")))
        == "all of them"
    )


def test_codegen_generator_misc_visitors_and_fallbacks() -> None:
    gen = CodeGenerator()

    assert gen.visit_string_count(StringCount("a")) == "#a"
    assert gen.visit_string_offset(StringOffset("a", IntegerLiteral(1))) == "@a[1]"
    assert gen.visit_string_length(StringLength("a", IntegerLiteral(2))) == "!a[2]"
    assert gen.visit_string_offset(StringOffset("a", _FalsyIntegerLiteral(0))) == "@a[0]"
    assert gen.visit_string_length(StringLength("a", _FalsyIntegerLiteral(0))) == "!a[0]"
    assert gen.visit_string_count(StringCount("$a")) == "#a"
    assert gen.visit_string_offset(StringOffset("$a", IntegerLiteral(1))) == "@a[1]"
    assert gen.visit_string_length(StringLength("$a", IntegerLiteral(2))) == "!a[2]"
    assert gen.visit_hex_jump(HexJump(1, 3)) == "[1-3]"
    assert (
        gen.visit_hex_alternative(HexAlternative([[HexByte(1)], [HexWildcard()]])) == "( 01 | ?? )"
    )
    assert gen.visit_hex_alternative(HexAlternative([0x90, "91"])) == "( 90 | 91 )"
    assert gen.visit_comment(Comment("note")) == "// note"
    assert (
        gen.visit_comment_group(CommentGroup(comments=[Comment("a"), Comment("b")])) == "// a\n// b"
    )
    assert gen.visit_extern_import(ExternImport("mods.yar")) == 'import "mods.yar"'
    with pytest.raises(ValueError, match="Import module must not contain quotes"):
        gen.visit_extern_import(ExternImport('mods"\\file.yar'))
    assert gen.visit_extern_import(ExternImport("mods.yar", alias="mods", rules=["R1", "R2"])) == (
        'import "mods.yar" (R1, R2) as mods'
    )
    assert gen.visit_extern_namespace(ExternNamespace("ns")) == "namespace ns"
    assert gen.visit_extern_rule(ExternRule("R")) == "extern rule R"
    assert (
        gen.visit_in_rule_pragma(InRulePragma(pragma=Pragma(PragmaType.PRAGMA, "demo")))
        == "#pragma demo"
    )
    assert gen.visit_pragma(Pragma(PragmaType.PRAGMA, "demo")) == "#pragma demo"
    assert gen.visit_pragma(IncludeOncePragma()) == "#include_once"
    assert gen.visit_pragma(DefineDirective("FEATURE", "1")) == "#define FEATURE 1"
    assert gen.visit_in_rule_pragma(InRulePragma(pragma=UndefDirective("FEATURE"))) == (
        "#undef FEATURE"
    )
    assert "#pragma pragma" in gen.visit_pragma_block(
        PragmaBlock(pragmas=[Pragma(PragmaType.PRAGMA, "pragma")])
    )
    with pytest.raises(ValueError, match="Invalid pragma identifier"):
        gen.visit_pragma(Pragma(PragmaType.PRAGMA, 'bad"name'))
    with pytest.raises(ValueError, match="Invalid pragma identifier"):
        gen.visit_pragma(Pragma(PragmaType.PRAGMA, "bad\rname"))
    with pytest.raises(ValueError, match="Pragma argument must not contain quotes"):
        gen.visit_pragma(CustomPragma("vendor", ['bad"arg']))
    with pytest.raises(ValueError, match="Invalid pragma macro identifier"):
        gen.visit_pragma(DefineDirective('BAD"NAME', "1"))
    with pytest.raises(ValueError, match="Pragma value must not contain quotes"):
        gen.visit_pragma(DefineDirective("FEATURE", 'bad"value'))
    with pytest.raises(ValueError, match="Invalid pragma macro identifier"):
        gen.visit_in_rule_pragma(InRulePragma(pragma=UndefDirective('BAD"NAME')))
    with pytest.raises(ValueError, match="Invalid pragma condition identifier"):
        gen.visit_pragma(ConditionalDirective.ifdef('BAD"NAME'))
    assert gen.visit_string_wildcard(StringWildcard("$a*")) == "$a*"
    assert gen.visit_string_identifier(StringIdentifier("$a")) == "$a"
    assert gen.visit_module_reference(ModuleReference("pe")) == "pe"
    assert (
        gen.visit_dictionary_access(
            DictionaryAccess(
                MemberAccess(ModuleReference("pe"), "version_info"),
                StringLiteral("Company"),
            )
        )
        == 'pe.version_info["Company"]'
    )
    assert (
        gen.visit_dictionary_access(DictionaryAccess(Identifier("items"), 'Company"\\Path'))
        == 'items["Company\\"\\\\Path"]'
    )
    yarax = YaraXGenerator()
    array_comp = ArrayComprehension(
        expression=IntegerLiteral(1),
        variable="x",
        iterable=Identifier("xs"),
        condition=_FalsyIntegerLiteral(0),
    )
    assert yarax.visit_array_comprehension(array_comp) == "[1 for x in xs if 0]"
    pattern_match = PatternMatch(Identifier("x"), [], default=_FalsyIntegerLiteral(0))
    assert "_ => 0," in yarax.visit_pattern_match(pattern_match)
    assert gen.visit_condition(Condition()) == ""
    assert gen.visit_tag(Tag("x")) == "x"
    assert gen.visit_string_modifier(StringModifier.from_name_value("xor", (1, 3))) == "xor(1-3)"
    assert gen.visit_string_modifier(StringModifier.from_name_value("xor", "0x10")) == "xor(0x10)"
    assert (
        gen.visit_string_modifier(StringModifier.from_name_value("xor", "0x01-0xff"))
        == "xor(0x01-0xff)"
    )
    alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_"
    assert (
        gen.visit_string_modifier(StringModifier.from_name_value("base64", alphabet))
        == f'base64("{alphabet}")'
    )
    escaped_alphabet = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789"\\'
    assert (
        gen.visit_string_modifier(StringModifier.from_name_value("base64", escaped_alphabet))
        == 'base64("ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789\\"\\\\")'
    )
    with pytest.raises(TypeError, match="xor value must be a byte"):
        gen.visit_string_modifier(StringModifier.from_name_value("xor", True))
    with pytest.raises(TypeError, match="xor range value must contain byte bounds"):
        gen.visit_string_modifier(StringModifier.from_name_value("xor", (True, 3)))
    with pytest.raises(TypeError, match="xor range value must be ascending"):
        gen.visit_string_modifier(StringModifier.from_name_value("xor", (4, 3)))
    with pytest.raises(TypeError, match="xor value must be a byte"):
        gen.visit_string_modifier(StringModifier.from_name_value("xor", 256))
    for value in ("a", "ff", "1f", "0X0A", "+10"):
        with pytest.raises(TypeError, match="xor value must be a byte"):
            gen.visit_string_modifier(StringModifier.from_name_value("xor", value))
    for value in ("custom", "A" * 63, "A" * 65):
        with pytest.raises(TypeError, match="base64 alphabet must be 64 bytes"):
            gen.visit_string_modifier(StringModifier.from_name_value("base64", value))
    with pytest.raises(TypeError, match="base64 value must be a string"):
        gen.visit_string_modifier(StringModifier.from_name_value("base64", True))

    real_rule = Rule(name="r", condition=BooleanLiteral(True))
    gen2 = CodeGenerator()
    gen2._write_rule_header(real_rule)
    assert gen2.buffer.getvalue() == "rule r"

    plain_no_mods = CodeGenerator()
    assert plain_no_mods.visit_plain_string(PlainString("$a", value="x")) == ""
    assert plain_no_mods.buffer.getvalue().endswith('$a = "x"')

    bytes_plain = CodeGenerator()
    assert bytes_plain.visit_plain_string(PlainString("$b", value=b'A"\x00\xff\\\n')) == ""
    assert bytes_plain.buffer.getvalue().endswith('$b = "A\\"\\x00\\xff\\\\\\n"')
