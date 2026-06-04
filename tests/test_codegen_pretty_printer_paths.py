from __future__ import annotations

import pytest

from yaraast.ast.base import YaraFile
from yaraast.ast.comments import Comment
from yaraast.ast.conditions import Condition, OfExpression
from yaraast.ast.expressions import (
    BinaryExpression,
    BooleanLiteral,
    FunctionCall,
    Identifier,
    IntegerLiteral,
    StringIdentifier,
)
from yaraast.ast.extern import ExternImport, ExternNamespace, ExternRule
from yaraast.ast.meta import Meta
from yaraast.ast.modifiers import StringModifier
from yaraast.ast.pragmas import CustomPragma, IncludeOncePragma, InRulePragma
from yaraast.ast.rules import Import, Include, Rule, Tag
from yaraast.ast.strings import HexByte, HexString, PlainString, RegexString
from yaraast.codegen.generator import CodeGenerator
from yaraast.codegen.options import GeneratorOptions
from yaraast.codegen.pretty_printer import (
    PrettyPrintOptions,
    StylePresets,
    pretty_print,
    pretty_print_compact,
    pretty_print_dense,
    pretty_print_readable,
    pretty_print_verbose,
)
from yaraast.codegen.pretty_printer_sections import (
    write_hex_string_aligned,
    write_plain_string_aligned,
    write_regex_string_aligned,
    write_wrapped_condition,
)
from yaraast.yarax.ast_nodes import (
    DictComprehension,
    DictExpression,
    DictItem,
    LambdaExpression,
    ListExpression,
    TupleExpression,
    WithDeclaration,
    WithStatement,
)


def test_pretty_printer_paths_for_includes_modifiers_wrapping_and_fallback() -> None:
    rule = Rule(
        name="r1",
        modifiers=["private", "global"],
        meta=[Meta("z", True), Meta("a", "x")],
        strings=[
            PlainString(identifier="$a", value="abc"),
            HexString(identifier="$h", tokens=[HexByte(0x4D), HexByte(0x5A)]),
            RegexString(identifier="$r", regex="ab.*"),
        ],
        condition=OfExpression("any", Identifier("them")),
    )
    yf = YaraFile(imports=[Import("pe")], includes=[Include("common.yar")], rules=[rule])

    opts = PrettyPrintOptions(
        sort_meta_keys=True,
        align_string_definitions=False,
        blank_lines_before_rule=1,
        blank_lines_after_imports=1,
        blank_lines_after_includes=1,
        blank_lines_between_sections=1,
        wrap_long_conditions=True,
        max_line_length=8,
    )
    out = CodeGenerator(options=GeneratorOptions(pretty=opts)).generate(yf)

    assert 'include "common.yar"' in out
    assert "private global rule r1 {" in out
    assert "meta:" in out and "z =" in out and "true" in out
    assert "$h = { 4D 5A }" in out
    assert "$r = /ab.*/" in out
    assert "condition:" in out


def test_pretty_printer_indents_string_entries_under_section() -> None:
    rule = Rule(
        name="indented_strings",
        strings=[
            PlainString("$a", value="abc"),
            HexString("$h", tokens=[HexByte(0x4D)]),
            RegexString("$r", regex="ab.*"),
        ],
        condition=OfExpression("any", Identifier("them")),
    )

    out = CodeGenerator(
        options=GeneratorOptions(pretty=PrettyPrintOptions(align_string_definitions=False))
    ).generate(YaraFile(rules=[rule]))

    assert (
        "\n    strings:\n"
        '        $a = "abc"\n'
        "        $h = { 4D }\n"
        "        $r = /ab.*/\n"
        "\n    condition:\n"
    ) in out


def test_pretty_printer_indents_meta_entries_under_section() -> None:
    rule = Rule(
        name="indented_meta",
        meta=[Meta("author", "me"), Meta("ok", True)],
        condition=BooleanLiteral(True),
    )

    out = CodeGenerator(
        options=GeneratorOptions(pretty=PrettyPrintOptions(align_meta_values=False))
    ).generate(YaraFile(rules=[rule]))

    assert (
        "\n    meta:\n" '        author = "me"\n' "        ok = true\n" "\n    condition:\n"
    ) in out


def test_pretty_printer_honors_tab_indentation_option() -> None:
    rule = Rule(
        name="tabbed",
        meta=[Meta("a", 1)],
        strings=[PlainString("$s", value="x")],
        condition=OfExpression("any", Identifier("them")),
    )

    out = CodeGenerator(
        options=GeneratorOptions(
            pretty=PrettyPrintOptions(
                indent_with_tabs=True,
                align_meta_values=False,
                align_string_definitions=False,
            )
        )
    ).generate(YaraFile(rules=[rule]))

    assert (
        "rule tabbed {\n"
        "\tmeta:\n"
        "\t\ta = 1\n"
        "\n"
        "\tstrings:\n"
        '\t\t$s = "x"\n'
        "\n"
        "\tcondition:\n"
        "\t\tany of them\n"
        "}\n"
    ) in out


def test_pretty_printer_uses_tabs_for_wrapped_condition_continuations() -> None:
    condition = BinaryExpression(
        BinaryExpression(Identifier("alpha"), "and", Identifier("beta")),
        "or",
        BinaryExpression(Identifier("gamma"), "and", Identifier("delta")),
    )
    rule = Rule(name="wrapped_tabs", condition=condition)

    out = CodeGenerator(
        options=GeneratorOptions(
            pretty=PrettyPrintOptions(
                indent_with_tabs=True,
                wrap_long_conditions=True,
                max_line_length=12,
            )
        )
    ).generate(YaraFile(rules=[rule]))

    assert "\t\t    " not in out
    assert "\n\t\t\tbeta" in out


def test_pretty_printer_does_not_insert_blank_line_before_long_wrapped_token() -> None:
    rule = Rule(
        name="long_first_word",
        condition=Identifier("very_long_identifier_name"),
    )

    out = CodeGenerator(
        options=GeneratorOptions(
            pretty=PrettyPrintOptions(wrap_long_conditions=True, max_line_length=8)
        )
    ).generate(YaraFile(rules=[rule]))

    assert "\n    condition:\n\n" not in out
    assert "\n        very_long_identifier_name\n" in out


def test_pretty_printer_honors_compact_symbolic_operators() -> None:
    rule = Rule(
        name="compact_ops",
        condition=BinaryExpression(Identifier("a"), "==", Identifier("b")),
    )

    out = CodeGenerator(
        options=GeneratorOptions(pretty=PrettyPrintOptions(space_around_operators=False))
    ).generate(YaraFile(rules=[rule]))

    assert "\n        a==b\n" in out
    assert "\n        a == b\n" not in out


def test_pretty_printer_honors_compact_expression_commas() -> None:
    rule = Rule(
        name="compact_commas",
        condition=FunctionCall(
            "foo",
            [FunctionCall("bar", [Identifier("a"), Identifier("b")]), Identifier("c")],
        ),
    )

    out = CodeGenerator(
        options=GeneratorOptions(pretty=PrettyPrintOptions(space_after_comma=False))
    ).generate(YaraFile(rules=[rule]))

    assert "\n        foo(bar(a,b),c)\n" in out
    assert "\n        foo(bar(a, b), c)\n" not in out


def test_pretty_printer_honors_compact_yarax_expression_commas() -> None:
    rule = Rule(
        name="compact_yarax_commas",
        condition=WithStatement(
            [
                WithDeclaration("a", Identifier("one")),
                WithDeclaration("b", Identifier("two")),
            ],
            FunctionCall(
                "foo",
                [
                    ListExpression([Identifier("a"), Identifier("b")]),
                    TupleExpression([Identifier("c"), Identifier("d")]),
                    DictExpression(
                        [
                            DictItem(Identifier("key"), Identifier("value")),
                            DictItem(Identifier("next"), Identifier("other")),
                        ]
                    ),
                    DictComprehension(
                        Identifier("k"),
                        Identifier("v"),
                        "k",
                        "v",
                        Identifier("items"),
                    ),
                    LambdaExpression(["x", "y"], Identifier("x")),
                ],
            ),
        ),
    )

    out = CodeGenerator(
        options=GeneratorOptions(pretty=PrettyPrintOptions(space_after_comma=False))
    ).generate(YaraFile(rules=[rule]))

    assert (
        "\n        with a = one,b = two: "
        "foo([a,b],(c,d),{key: value,next: other},{k: v for k,v in items},lambda x,y: x)\n"
    ) in out
    assert "a = one, b = two" not in out
    assert "[a, b]" not in out
    assert "(c, d)" not in out
    assert "{key: value, next: other}" not in out
    assert "for k, v in items" not in out
    assert "lambda x, y: x" not in out


def test_pretty_printer_preserves_top_level_extensions() -> None:
    yf = YaraFile(
        pragmas=[IncludeOncePragma()],
        imports=[Import("pe")],
        extern_imports=[ExternImport("external.yar", alias="ext", rules=["Remote"])],
        includes=[Include("common.yar")],
        namespaces=[ExternNamespace("corp")],
        extern_rules=[ExternRule("Remote")],
        rules=[Rule(name="r", condition=BooleanLiteral(True))],
    )

    out = CodeGenerator(options=GeneratorOptions(pretty=PrettyPrintOptions())).generate(yf)

    assert "#include_once" in out
    assert 'import "pe"' in out
    assert 'import "external.yar" (Remote) as ext' in out
    assert 'include "common.yar"' in out
    assert "namespace corp" in out
    assert "extern rule Remote" in out
    assert "rule r {" in out


def test_pretty_printer_preserves_nested_comments_when_enabled() -> None:
    meta = Meta("author", "alice")
    meta.leading_comments = [Comment("meta lead")]
    meta.trailing_comment = Comment("meta tail")

    plain = PlainString("$a", value="abc")
    plain.leading_comments = [Comment("string lead")]
    plain.trailing_comment = Comment("string tail")

    condition = StringIdentifier("$a")
    condition.leading_comments = [Comment("condition lead")]
    condition.trailing_comment = Comment("condition tail")

    in_rule_pragma = InRulePragma(
        CustomPragma("opt", arguments=["on"]),
        position="before_condition",
    )
    in_rule_pragma.leading_comments = [Comment("pragma lead")]
    in_rule_pragma.trailing_comment = Comment("pragma tail")

    rule = Rule(
        name="commented",
        meta=[meta],
        strings=[plain],
        condition=condition,
        pragmas=[in_rule_pragma],
    )
    rule.leading_comments = [Comment("rule lead")]
    rule.trailing_comment = Comment("rule tail")

    options = PrettyPrintOptions(
        align_comments=False,
        align_meta_values=False,
        align_string_definitions=False,
    )
    out = CodeGenerator(options=GeneratorOptions(pretty=options)).generate(YaraFile(rules=[rule]))

    assert "// rule lead" in out
    assert "rule commented {  // rule tail" in out
    assert "// meta lead" in out
    assert 'author = "alice"  // meta tail' in out
    assert "// string lead" in out
    assert '$a = "abc"  // string tail' in out
    assert "// pragma lead" in out
    assert "#pragma opt on  // pragma tail" in out
    assert "// condition lead" in out
    assert "$a  // condition tail" in out

    suppressed = CodeGenerator(
        options=GeneratorOptions(
            pretty=PrettyPrintOptions(
                align_comments=False,
                align_meta_values=False,
                align_string_definitions=False,
                preserve_comments=False,
            )
        )
    ).generate(YaraFile(rules=[rule]))

    assert "lead" not in suppressed
    assert "tail" not in suppressed


def test_pretty_printer_rejects_inline_multiline_comments() -> None:
    rule = Rule("bad_inline_comment", condition=BooleanLiteral(True))
    rule.trailing_comment = Comment("line1\nline2")

    with pytest.raises(ValueError, match="Inline comment text must not contain newlines"):
        CodeGenerator(options=GeneratorOptions(pretty=PrettyPrintOptions())).generate(
            YaraFile(rules=[rule])
        )


def test_pretty_printer_honors_inline_comment_spacing_options() -> None:
    meta = Meta("author", "alice")
    meta.trailing_comment = Comment("meta tail")
    rule = Rule(
        name="inline_comments",
        meta=[meta],
        condition=BooleanLiteral(True),
    )

    spaced = CodeGenerator(
        options=GeneratorOptions(
            pretty=PrettyPrintOptions(
                align_comments=False,
                align_meta_values=False,
                inline_comment_spacing=5,
            )
        )
    ).generate(YaraFile(rules=[rule]))

    assert 'author = "alice"     // meta tail' in spaced
    assert 'author = "alice"  // meta tail' not in spaced

    aligned = CodeGenerator(
        options=GeneratorOptions(
            pretty=PrettyPrintOptions(
                align_comments=True,
                align_meta_values=False,
                comment_column=32,
                inline_comment_spacing=1,
            )
        )
    ).generate(YaraFile(rules=[rule]))
    meta_line = next(line for line in aligned.splitlines() if "author =" in line)

    assert meta_line.index("//") == 32


def test_pretty_printer_regex_suffix_alias_modifiers_are_adjacent() -> None:
    rule = Rule(
        name="regex_aliases",
        strings=[
            RegexString(
                "$r",
                regex="ab.*",
                modifiers=["i", "s", StringModifier.from_name_value("fullword")],
            ),
        ],
        condition=StringIdentifier("$r"),
    )

    out = CodeGenerator(options=GeneratorOptions(pretty=PrettyPrintOptions())).generate(
        YaraFile(rules=[rule])
    )

    assert "$r  = /ab.*/is fullword" in out
    assert "$r = /ab.*/ i" not in out


def test_pretty_printer_rejects_unsupported_regex_multiline_modifier() -> None:
    rule = Rule(
        name="regex_multiline",
        strings=[
            RegexString(
                "$m",
                regex="^line",
                modifiers=[StringModifier.from_name_value("multiline")],
            ),
        ],
        condition=StringIdentifier("$m"),
    )

    with pytest.raises(ValueError, match="Unsupported regex modifier"):
        CodeGenerator(options=GeneratorOptions(pretty=PrettyPrintOptions())).generate(
            YaraFile(rules=[rule])
        )


def test_pretty_printer_rejects_invalid_regex_string_modifier() -> None:
    rule = Rule(
        name="regex_base64",
        strings=[
            RegexString(
                "$r",
                regex="abc",
                modifiers=[StringModifier.from_name_value("base64")],
            ),
        ],
        condition=StringIdentifier("$r"),
    )

    with pytest.raises(ValueError, match="not valid on regex strings"):
        CodeGenerator(options=GeneratorOptions(pretty=PrettyPrintOptions())).generate(
            YaraFile(rules=[rule])
        )


def test_pretty_printer_keeps_yara_string_literals_valid_for_quote_styles() -> None:
    rule = Rule(
        name="quotes",
        meta=[Meta("author", "a\nb")],
        strings=[PlainString("$a", value="abc")],
        condition=StringIdentifier("$a"),
    )

    for quote_style in ("single", "preserve"):
        out = CodeGenerator(
            options=GeneratorOptions(
                pretty=PrettyPrintOptions(
                    quote_style=quote_style,
                    align_meta_values=False,
                    align_string_definitions=False,
                )
            )
        ).generate(YaraFile(rules=[rule]))

        assert 'author = "a\\nb"' in out
        assert '$a = "abc"' in out
        assert "'abc'" not in out


def test_pretty_printer_style_presets_and_convenience_functions() -> None:
    ast = YaraFile(rules=[Rule(name="x", condition=Condition())])

    compact = CodeGenerator(options=GeneratorOptions(pretty=StylePresets.compact())).generate(ast)
    readable = CodeGenerator(options=GeneratorOptions(pretty=StylePresets.readable())).generate(ast)
    dense = CodeGenerator(options=GeneratorOptions(pretty=StylePresets.dense())).generate(ast)
    verbose = CodeGenerator(options=GeneratorOptions(pretty=StylePresets.verbose())).generate(ast)
    assert len(verbose) >= len(compact)
    assert len(readable) >= len(dense)

    assert pretty_print(ast, PrettyPrintOptions())
    assert pretty_print_compact(ast)
    assert pretty_print_readable(ast)
    assert pretty_print_dense(ast)
    assert pretty_print_verbose(ast)


def test_pretty_printer_handles_partial_sections_sorting_and_wrapped_condition_lines() -> None:
    only_meta = Rule(
        name="meta_only",
        tags=[Tag("z"), Tag("a")],
        meta={"b": 2, "a": "x"},
        condition=BooleanLiteral(True),
    )
    only_strings = Rule(
        name="strings_only",
        strings=[RegexString(identifier="$r", regex="ab.*")],
        condition=StringIdentifier("$r"),
    )
    long_condition = Rule(
        name="cond_only",
        condition=BinaryExpression(
            BinaryExpression(Identifier("alpha"), "and", Identifier("beta")),
            "or",
            BinaryExpression(Identifier("gamma"), "and", IntegerLiteral(1)),
        ),
    )
    ast = YaraFile(rules=[only_meta, only_strings, long_condition])

    out = CodeGenerator(
        options=GeneratorOptions(
            pretty=PrettyPrintOptions(
                sort_tags=True,
                sort_meta_keys=True,
                align_string_definitions=True,
                wrap_long_conditions=True,
                max_line_length=12,
            )
        )
    ).generate(ast)

    assert "rule meta_only : a z {" in out
    assert "a =" in out and '"x"' in out
    assert "b =" in out and "2" in out
    assert "strings:" in out
    assert "$r  = /ab.*/" in out
    assert "condition:" in out
    assert "beta or" in out
    assert "\n            and 1\n" in out


def test_pretty_printer_direct_remaining_helper_paths() -> None:
    printer = CodeGenerator(
        options=GeneratorOptions(
            pretty=PrettyPrintOptions(
                sort_imports=True,
                sort_includes=True,
                sort_meta_keys=False,
                align_string_definitions=True,
                wrap_long_conditions=False,
                blank_lines_after_imports=3,
            )
        )
    )

    ast = YaraFile(
        imports=[Import("b"), Import("a")],
        includes=[Include("z.yar"), Include("a.yar")],
        rules=[
            Rule(name="one", condition=BooleanLiteral(True)),
            Rule(name="two", condition=BooleanLiteral(False)),
        ],
    )
    out = printer.generate(ast)
    assert out.index('import "a"') < out.index('import "b"')
    assert out.index('include "a.yar"') < out.index('include "z.yar"')
    assert '\n\n\ninclude "a.yar"' in out

    printer2 = CodeGenerator(
        options=GeneratorOptions(
            pretty=PrettyPrintOptions(
                sort_meta_keys=False, align_string_definitions=True, wrap_long_conditions=False
            )
        )
    )
    from yaraast.codegen.pretty_layout import PrettyLayout

    layout2 = printer2._layout
    assert isinstance(layout2, PrettyLayout)
    layout2._meta_alignment_column = 0
    from yaraast.ast.modifiers import MetaEntry

    printer2._write_meta_section([MetaEntry(key="b", value=2), MetaEntry(key="a", value="x")])
    meta_out = printer2.buffer.getvalue()
    assert 'a = "x"' in meta_out
    assert "b = 2" in meta_out

    printer2.buffer.seek(0)
    printer2.buffer.truncate(0)
    layout2._string_alignment_column = 4
    write_plain_string_aligned(printer2, PlainString("$a", value="x"))
    write_hex_string_aligned(printer2, HexString("$h", tokens=[HexByte(0x4D)]))
    aligned_out = printer2.buffer.getvalue()
    assert '$a   = "x"' in aligned_out
    assert "$h   = { 4D }" in aligned_out

    printer2.buffer.seek(0)
    printer2.buffer.truncate(0)
    printer2.indent_level = 1
    write_regex_string_aligned(printer2, RegexString("$r", regex="x"))
    assert printer2.buffer.getvalue() == "    $r   = /x/\n"
    printer2.indent_level = 0

    printer2.buffer.seek(0)
    printer2.buffer.truncate(0)
    printer2._write_condition_section(BooleanLiteral(True))
    assert printer2.buffer.getvalue() == "true\n"

    printer2.buffer.seek(0)
    printer2.buffer.truncate(0)
    write_wrapped_condition(printer2, "")
    assert printer2.buffer.getvalue() == ""
