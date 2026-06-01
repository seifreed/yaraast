from __future__ import annotations

from typing import Any, cast

from yaraast.ast.base import YaraFile
from yaraast.ast.comments import Comment, CommentGroup
from yaraast.ast.conditions import Condition
from yaraast.ast.expressions import BooleanLiteral, IntegerLiteral
from yaraast.ast.meta import Meta
from yaraast.ast.modifiers import StringModifier, StringModifierType
from yaraast.ast.rules import Rule
from yaraast.ast.strings import HexByte, HexString, RegexString
from yaraast.codegen.comment_aware_generator import CommentAwareCodeGenerator
from yaraast.yarax.ast_nodes import MatchCase, PatternMatch


class _FalsyBooleanLiteral(BooleanLiteral):
    def __bool__(self) -> bool:
        return False


def test_comment_aware_generator_write_comments_and_generate_non_file_node() -> None:
    gen = CommentAwareCodeGenerator()
    gen._write_comments([Comment("// one"), CommentGroup(comments=[Comment("// two")])])
    gen._write_comments([])

    out = gen.buffer.getvalue()
    assert "// one" in out
    assert "// two" in out

    rule = Rule(name="standalone", meta=[], strings=[], condition=None)
    generated = gen.generate(cast(Any, rule))
    assert "rule standalone {" in generated


def test_comment_aware_generator_meta_dict_and_missing_sections() -> None:
    file_ast = YaraFile(
        rules=[
            Rule(
                name="dict_meta",
                meta={"author": "alice", "enabled": True, "count": 3, "quoted": '"x"'},
                strings=[],
                condition=None,
            ),
            Rule(
                name="only_condition",
                meta=[],
                strings=[],
                condition=Condition(),
            ),
        ],
    )

    out = CommentAwareCodeGenerator().generate(file_ast)

    assert 'author = "alice"' in out
    assert "enabled = true" in out
    assert "count = 3" in out
    assert 'quoted = "\\"x\\""' in out
    assert "rule only_condition {" in out
    assert "condition:" in out


def test_comment_aware_generator_writes_falsy_present_condition() -> None:
    file_ast = YaraFile(
        rules=[
            Rule(
                name="falsy_condition",
                condition=_FalsyBooleanLiteral(False),
            )
        ]
    )

    out = CommentAwareCodeGenerator().generate(file_ast)

    assert "condition:" in out
    assert "false" in out


def test_comment_aware_generator_hex_and_regex_modifier_paths() -> None:
    hexs = HexString(
        identifier="$h",
        tokens=[HexByte(0xAA)],
        modifiers=[StringModifier(StringModifierType.PRIVATE)],
    )
    regex = RegexString(
        identifier="$r",
        regex="abc",
        modifiers=[],
    )
    meta = Meta("author", '"bob"')
    cond = Condition()
    cond.leading_comments = [Comment("cond lead")]

    rule = Rule(
        name="paths",
        meta=[meta],
        strings=[hexs, regex],
        condition=cond,
    )
    file_ast = YaraFile(rules=[rule])

    out = CommentAwareCodeGenerator().generate(file_ast)

    assert "$h = { AA } private" in out
    assert "$r = /abc/" in out
    assert 'author = "\\"bob\\""' in out
    assert "// cond lead" in out


def test_comment_aware_generator_import_include_without_trailing_comments() -> None:
    from yaraast.ast.rules import Import, Include

    file_ast = YaraFile(
        imports=[Import("pe")],
        includes=[Include("common.yar"), Include("more.yar")],
        rules=[],
    )

    out = CommentAwareCodeGenerator().generate(file_ast)

    assert 'import "pe"' in out
    assert 'include "common.yar"\ninclude "more.yar"' in out


def test_comment_aware_generator_condition_trailing_comment_stays_on_condition_line() -> None:
    condition = BooleanLiteral(True)
    condition.trailing_comment = Comment("condition tail")
    file_ast = YaraFile(rules=[Rule(name="commented_condition", condition=condition)])

    out = CommentAwareCodeGenerator().generate(file_ast)

    assert "true  // condition tail\n    }" in out
    assert "// condition tail    }" not in out


def test_comment_aware_generator_indents_multiline_match_condition() -> None:
    condition = PatternMatch(
        value=IntegerLiteral(1),
        cases=[MatchCase(pattern=IntegerLiteral(1), result=BooleanLiteral(True))],
        default=BooleanLiteral(False),
    )
    file_ast = YaraFile(rules=[Rule(name="match_rule", condition=condition)])

    out = CommentAwareCodeGenerator().generate(file_ast)

    assert (
        "    condition:\n"
        "        match 1 {\n"
        "            1 => true,\n"
        "            _ => false,\n"
        "        }\n"
    ) in out
    assert "\n    1 => true,\n" not in out


def test_comment_aware_generator_uses_configured_indent_for_match_cases() -> None:
    condition = PatternMatch(
        value=IntegerLiteral(1),
        cases=[MatchCase(pattern=IntegerLiteral(1), result=BooleanLiteral(True))],
        default=BooleanLiteral(False),
    )
    file_ast = YaraFile(rules=[Rule(name="match_rule", condition=condition)])

    out = CommentAwareCodeGenerator(indent_size=2).generate(file_ast)

    assert (
        "  condition:\n" "    match 1 {\n" "      1 => true,\n" "      _ => false,\n" "    }\n"
    ) in out
    assert "\n        1 => true,\n" not in out
