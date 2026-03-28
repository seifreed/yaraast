"""Tests for comment preservation through parse -> codegen roundtrip."""
from __future__ import annotations

from yaraast.codegen import CodeGenerator
from yaraast.parser.comment_aware_parser import CommentAwareParser


class TestCommentPreservation:
    """Test that comments survive parse -> codegen roundtrip."""

    def test_leading_block_comment_preserved(self) -> None:
        rule = (
            "/* Rule description */\n"
            "rule test {\n"
            "    condition:\n"
            "        true\n"
            "}\n"
        )
        ast = CommentAwareParser().parse(rule)
        output = CodeGenerator().generate(ast)
        assert "/* Rule description */" in output

    def test_leading_multiline_comment_preserved(self) -> None:
        rule = (
            "/* Multi-line\n"
            "   comment */\n"
            "rule test {\n"
            "    condition:\n"
            "        true\n"
            "}\n"
        )
        ast = CommentAwareParser().parse(rule)
        output = CodeGenerator().generate(ast)
        assert "/* Multi-line" in output
        assert "comment */" in output

    def test_leading_line_comment_preserved(self) -> None:
        rule = (
            "// Line comment\n"
            "rule test {\n"
            "    condition:\n"
            "        true\n"
            "}\n"
        )
        ast = CommentAwareParser().parse(rule)
        output = CodeGenerator().generate(ast)
        assert "// Line comment" in output

    def test_multiple_rules_with_comments(self) -> None:
        rules = (
            "/* First rule */\n"
            "rule first {\n"
            "    condition:\n"
            "        true\n"
            "}\n"
            "\n"
            "/* Second rule */\n"
            "rule second {\n"
            "    condition:\n"
            "        false\n"
            "}\n"
        )
        ast = CommentAwareParser().parse(rules)
        output = CodeGenerator().generate(ast)
        assert "/* First rule */" in output
        assert "/* Second rule */" in output

    def test_import_comment_preserved(self) -> None:
        rule = (
            "/* Module import */\n"
            'import "pe"\n'
            "\n"
            "rule test {\n"
            "    condition:\n"
            "        true\n"
            "}\n"
        )
        ast = CommentAwareParser().parse(rule)
        output = CodeGenerator().generate(ast)
        assert "/* Module import */" in output
        assert 'import "pe"' in output

    def test_no_comments_still_works(self) -> None:
        rule = "rule test {\n    condition:\n        true\n}\n"
        ast = CommentAwareParser().parse(rule)
        output = CodeGenerator().generate(ast)
        assert "rule test" in output
        assert "true" in output
