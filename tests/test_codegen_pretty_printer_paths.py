from __future__ import annotations

from yaraast.ast.base import YaraFile
from yaraast.ast.conditions import Condition
from yaraast.ast.expressions import BinaryExpression, BooleanLiteral, Identifier, IntegerLiteral
from yaraast.ast.meta import Meta
from yaraast.ast.rules import Import, Include, Rule, Tag
from yaraast.ast.strings import HexByte, HexString, PlainString, RegexString, StringDefinition
from yaraast.codegen.pretty_printer import (
    PrettyPrinter,
    PrettyPrintOptions,
    StylePresets,
    pretty_print,
    pretty_print_compact,
    pretty_print_dense,
    pretty_print_readable,
    pretty_print_verbose,
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
            StringDefinition(identifier="$fallback"),
        ],
        condition=BinaryExpression(Identifier("a"), "and", Identifier("b")),
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
    out = PrettyPrinter(opts).pretty_print(yf)

    assert 'include "common.yar"' in out
    assert "private global rule r1 {" in out
    assert "meta:" in out and "z =" in out and "true" in out
    assert "$h = { 4D 5A }" in out
    assert "$r = /ab.*/" in out
    assert "condition:" in out


def test_pretty_printer_style_presets_and_convenience_functions() -> None:
    ast = YaraFile(rules=[Rule(name="x", condition=Condition())])

    compact = PrettyPrinter(StylePresets.compact()).pretty_print(ast)
    readable = PrettyPrinter(StylePresets.readable()).pretty_print(ast)
    dense = PrettyPrinter(StylePresets.dense()).pretty_print(ast)
    verbose = PrettyPrinter(StylePresets.verbose()).pretty_print(ast)
    assert len(verbose) >= len(compact)
    assert len(readable) >= len(dense)

    assert pretty_print(ast, PrettyPrintOptions())
    assert pretty_print_compact(ast)
    assert pretty_print_readable(ast)
    assert pretty_print_dense(ast)
    assert pretty_print_verbose(ast)


def test_pretty_printer_handles_partial_sections_sorting_and_wrapped_condition_lines() -> None:
    only_meta = Rule(name="meta_only", tags=[Tag("z"), Tag("a")], meta={"b": 2, "a": "x"})
    only_strings = Rule(name="strings_only", strings=[RegexString(identifier="$r", regex="ab.*")])
    long_condition = Rule(
        name="cond_only",
        condition=BinaryExpression(
            BinaryExpression(Identifier("alpha"), "and", Identifier("beta")),
            "or",
            BinaryExpression(Identifier("gamma"), "and", IntegerLiteral(1)),
        ),
    )
    ast = YaraFile(rules=[only_meta, only_strings, long_condition])

    out = PrettyPrinter(
        PrettyPrintOptions(
            sort_tags=True,
            sort_meta_keys=True,
            align_string_definitions=True,
            wrap_long_conditions=True,
            max_line_length=12,
        )
    ).pretty_print(ast)

    assert "rule meta_only : a z {" in out
    assert "a =" in out and '"x"' in out
    assert "b =" in out and "2" in out
    assert "strings:" in out
    assert "$r  = /ab.*/" in out
    assert "condition:" in out
    assert "beta or" in out
    assert "\n            and 1\n" in out


def test_pretty_printer_direct_remaining_helper_paths() -> None:
    printer = PrettyPrinter(
        PrettyPrintOptions(
            sort_imports=True,
            sort_includes=True,
            sort_meta_keys=False,
            align_string_definitions=True,
            wrap_long_conditions=False,
            blank_lines_after_imports=3,
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
    out = printer.pretty_print(ast)
    assert out.index('import "a"') < out.index('import "b"')
    assert out.index('include "a.yar"') < out.index('include "z.yar"')
    assert '\n\n\ninclude "a.yar"' in out

    printer2 = PrettyPrinter(
        PrettyPrintOptions(
            sort_meta_keys=False, align_string_definitions=True, wrap_long_conditions=False
        )
    )
    printer2._meta_alignment_column = 0
    printer2._write_meta_section({"b": 2, "a": "x"})
    printer2._write_meta_section([Meta("b", 2), object()])
    meta_out = printer2.buffer.getvalue()
    assert 'a = "x"' in meta_out
    assert "b = 2" in meta_out

    printer2.buffer.seek(0)
    printer2.buffer.truncate(0)
    printer2._string_alignment_column = 4
    printer2._write_plain_string_aligned(PlainString("$a", value="x"))
    printer2._write_hex_string_aligned(HexString("$h", tokens=[HexByte(0x4D)]))
    aligned_out = printer2.buffer.getvalue()
    assert '$a   = "x"' in aligned_out
    assert "$h   = { 4D }" in aligned_out

    printer2.buffer.seek(0)
    printer2.buffer.truncate(0)
    printer2._write_condition_section(BooleanLiteral(True))
    assert printer2.buffer.getvalue() == "true\n"

    printer2.buffer.seek(0)
    printer2.buffer.truncate(0)
    printer2._write_wrapped_condition("")
    assert printer2.buffer.getvalue() == ""
