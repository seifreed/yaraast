from __future__ import annotations

from typing import Any, cast

import pytest

from yaraast.ast.base import YaraFile
from yaraast.ast.comments import Comment, CommentGroup
from yaraast.ast.conditions import Condition, OfExpression
from yaraast.ast.expressions import Identifier
from yaraast.ast.extern import ExternImport, ExternNamespace, ExternRule
from yaraast.ast.meta import Meta
from yaraast.ast.modifiers import StringModifier, StringModifierType
from yaraast.ast.pragmas import IncludeOncePragma
from yaraast.ast.rules import Import, Include, Rule, Tag
from yaraast.ast.strings import HexByte, HexString, PlainString, RegexString
from yaraast.codegen.generator import CodeGenerator
from yaraast.codegen.options import GeneratorOptions


def test_comment_aware_generator_comment_shapes_and_disable_flag() -> None:
    gen = CodeGenerator(options=GeneratorOptions.comment_aware())
    gen._write_comment(Comment("// trimmed"))
    gen._write_comment(Comment("/* block */"), inline=True)
    gen._write_comment(Comment("line1\nline2"))
    gen._write_comment(CommentGroup(comments=[Comment("g1"), Comment("g2")]))

    out = gen.buffer.getvalue()
    assert "// trimmed" in out
    assert "// block" in out
    assert "/*" in out and "* line1" in out and "* line2" in out
    assert "// g1" in out and "// g2" in out

    disabled = CodeGenerator(options=GeneratorOptions.comment_aware(preserve_comments=False))
    disabled._write_comment(Comment("// no"))
    assert disabled.buffer.getvalue() == ""


def test_comment_aware_generator_rejects_inline_multiline_comments() -> None:
    gen = CodeGenerator(options=GeneratorOptions.comment_aware())

    with pytest.raises(ValueError, match="Inline comment text must not contain newlines"):
        gen._write_comment(Comment("line1\nline2"), inline=True)

    rule = Rule("bad_inline_comment", condition=Condition())
    rule.trailing_comment = Comment("line1\nline2")

    with pytest.raises(ValueError, match="Inline comment text must not contain newlines"):
        CodeGenerator(options=GeneratorOptions.comment_aware()).generate(YaraFile(rules=[rule]))


def test_comment_aware_generator_full_file_paths() -> None:
    file_comment = Comment("file lead")
    tail_comment = Comment("file tail")

    imp = Import("pe")
    imp.leading_comments = [Comment("import lead")]
    imp.trailing_comment = Comment("import tail")

    inc = Include("common.yar")
    inc.leading_comments = [Comment("include lead")]
    inc.trailing_comment = Comment("include tail")

    meta1 = Meta("author", "alice")
    meta1.leading_comments = [Comment("meta lead")]
    meta1.trailing_comment = Comment("meta tail")

    plain = PlainString(
        identifier="$a",
        value="abc",
        modifiers=[StringModifier(StringModifierType.NOCASE)],
    )
    plain.leading_comments = [Comment("string lead")]
    plain.trailing_comment = Comment("string tail")

    hexs = HexString(identifier="$h", tokens=[HexByte(0xAA)], modifiers=[])
    regex = RegexString(
        identifier="$r",
        regex="abc.*",
        modifiers=["i", StringModifier(StringModifierType.FULLWORD)],
    )

    cond = OfExpression("any", Identifier("them"))
    cond.leading_comments = [Comment("cond lead")]
    cond.trailing_comment = Comment("cond tail")

    rule = Rule(
        name="r1",
        modifiers=["private"],
        tags=cast(Any, [Tag("t1"), "t2"]),
        meta=[meta1],
        strings=[plain, hexs, regex],
        condition=cond,
    )
    rule.leading_comments = [Comment("rule lead")]
    rule.trailing_comment = Comment("rule tail")

    yara_file = YaraFile(imports=[imp], includes=[inc], rules=[rule])
    yara_file.leading_comments = [file_comment]
    yara_file.trailing_comment = tail_comment

    out = CodeGenerator(options=GeneratorOptions.comment_aware()).generate(yara_file)

    assert "// file lead" in out and "// file tail" in out
    assert 'import "pe"  // import tail' in out
    assert 'include "common.yar"  // include tail' in out
    assert "private rule r1 : t1 t2 {  // rule tail" in out
    assert "// meta lead" in out and "// meta tail" in out
    assert '$a = "abc" nocase  // string tail' in out
    assert "$h = { AA }" in out
    assert "$r = /abc.*/i fullword" in out
    assert "// cond lead" in out and "// cond tail" in out


def test_comment_aware_generator_preserves_top_level_extensions() -> None:
    pragma = IncludeOncePragma()
    pragma.leading_comments = [Comment("pragma lead")]

    extern_import = ExternImport("external.yar", alias="ext", rules=["Remote"])
    extern_import.leading_comments = [Comment("extern import lead")]
    extern_import.trailing_comment = Comment("extern import tail")

    namespace = ExternNamespace("corp")
    extern_rule = ExternRule("Remote")

    yara_file = YaraFile(
        pragmas=[pragma],
        imports=[Import("pe")],
        extern_imports=[extern_import],
        namespaces=[namespace],
        extern_rules=[extern_rule],
        rules=[Rule(name="r", condition=Condition())],
    )

    out = CodeGenerator(options=GeneratorOptions.comment_aware()).generate(yara_file)

    assert "// pragma lead" in out
    assert "#include_once" in out
    assert "// extern import lead" in out
    assert 'import "external.yar" (Remote) as ext  // extern import tail' in out
    assert "namespace corp" in out
    assert "extern rule Remote" in out
