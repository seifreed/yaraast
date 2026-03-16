from __future__ import annotations

from yaraast.ast.base import YaraFile
from yaraast.ast.comments import Comment, CommentGroup
from yaraast.ast.conditions import Condition
from yaraast.ast.meta import Meta
from yaraast.ast.modifiers import StringModifier, StringModifierType
from yaraast.ast.rules import Rule
from yaraast.ast.strings import HexByte, HexString, RegexString
from yaraast.codegen.comment_aware_generator import CommentAwareCodeGenerator


def test_comment_aware_generator_write_comments_and_generate_non_file_node() -> None:
    gen = CommentAwareCodeGenerator()
    gen._write_comments([Comment("// one"), CommentGroup(comments=[Comment("// two")])])
    gen._write_comments([])

    out = gen.buffer.getvalue()
    assert "// one" in out
    assert "// two" in out

    rule = Rule(name="standalone", meta=[], strings=[], condition=None)
    generated = gen.generate(rule)  # type: ignore[arg-type]
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
    assert 'quoted = "x"' in out
    assert "rule only_condition {" in out
    assert "condition:" in out


def test_comment_aware_generator_hex_and_regex_modifier_paths() -> None:
    hexs = HexString(
        identifier="$h",
        tokens=[HexByte(0xAA)],
        modifiers=[StringModifier(StringModifierType.FULLWORD)],
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

    assert "$h = { AA } fullword" in out
    assert "$r = /abc/" in out
    assert 'author = "bob"' in out
    assert "// cond lead" in out


def test_comment_aware_generator_import_include_without_trailing_comments() -> None:
    from yaraast.ast.rules import Import, Include

    file_ast = YaraFile(
        imports=[Import("pe")],
        includes=[Include("common.yar")],
        rules=[],
    )

    out = CommentAwareCodeGenerator().generate(file_ast)

    assert 'import "pe"' in out
    assert 'include "common.yar"' in out
